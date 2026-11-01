#!/usr/bin/env python3
"""Send hand-made packets from a container and report whether anything answered.

Uses a raw (AF_PACKET) socket, which containers can open with Docker's default
capabilities (NET_RAW), so every probe here is available to any container.

    craft udp --dst IP --dport N [options]     UDP datagram
    craft tcp --dst IP --dport N [options]     TCP SYN
    craft flood --count N                      N UDP datagrams from random unused sources
    craft scan --dst IP --count N              N UDP datagrams to distinct ports, fast
    craft icmp-error --dst IP --about IP:PORT --dport N
                                               ICMP port unreachable to IP, quoting a UDP
                                               datagram from IP:N to the --about address
    craft arp [--src IP] [--src-mac MAC]       gratuitous ARP announcing IP at MAC
    craft ipv6 [--src-mac MAC]                 IPv6 UDP datagram to all nodes

Options:
    --src IP          source address (default: the container's own)
    --sport N         source port (default: random)
    --src-mac MAC     source MAC (default: the container's own)
    --to-mac MAC      destination MAC (default: the gateway's for addresses outside the
                      subnet, the address's own otherwise, broadcast for broadcasts)
    --vlan IDS        802.1Q tags, outermost first, e.g. 0 or 0,0 (0x88a8 outer tag)
    --fragment N      split the IP payload into fragments of N bytes (multiple of 8)
    --overlap PORT    send a second first fragment rewriting the destination port
    --wait S          how long to listen for answers (default 4)

Prints `answered <summary>` for each reply from the destination, `rejected` for ICMP
unreachable, `nothing` when nothing came back, and always exits 0.
"""

import argparse
import ipaddress
import random
import sys
import time

from scapy.all import (
    ARP,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    AsyncSniffer,
    Dot1AD,
    Dot1Q,
    Ether,
    Raw,
    conf,
    get_if_addr,
    get_if_hwaddr,
    getmacbyip,
    sendp,
)

IFACE = "eth0"
conf.verb = 0


def network():
    for route in conf.route.routes:
        net, mask, gateway, iface, *_ = route
        if iface == IFACE and gateway == "0.0.0.0" and mask not in (0, 0xFFFFFFFF):
            return ipaddress.ip_network(
                (ipaddress.ip_address(net), bin(mask).count("1")), strict=False
            )
    raise SystemExit("no subnet on eth0")


def gateway():
    for net, mask, gateway, iface, *_ in conf.route.routes:
        if iface == IFACE and net == 0 and mask == 0:
            return gateway
    raise SystemExit("no default route")


def destination_mac(dst, subnet):
    address = ipaddress.ip_address(dst)
    if address == subnet.broadcast_address or str(address) == "255.255.255.255":
        return "ff:ff:ff:ff:ff:ff"
    if address.is_multicast:
        octets = address.packed
        return "01:00:5e:%02x:%02x:%02x" % (octets[1] & 0x7F, octets[2], octets[3])
    mac = getmacbyip(dst if address in subnet else gateway())
    if mac is None:
        raise SystemExit(f"no MAC for {dst}")
    return mac


def frame(args, src, src_mac, to_mac, transport):
    layer2 = Ether(src=src_mac, dst=to_mac)
    tags = [int(tag) for tag in args.vlan.split(",")] if args.vlan else []
    for index, tag in enumerate(tags):
        outer = index == 0 and len(tags) > 1
        layer2 = layer2 / (Dot1AD(vlan=tag) if outer else Dot1Q(vlan=tag))
    packet = IP(src=src, dst=args.dst, id=random.randint(1, 0xFFFF)) / transport
    if not args.fragment:
        return [layer2 / packet]
    # Build the fragments by hand, so they can overlap.
    raw = bytes(IP(bytes(packet))[IP].payload)
    header = IP(bytes(packet))
    frames = []
    size = args.fragment
    for offset in range(0, len(raw), size):
        more = offset + size < len(raw)
        piece = IP(
            src=header.src, dst=header.dst, id=header.id, proto=header.proto,
            flags="MF" if more else 0, frag=offset // 8,
        ) / Raw(raw[offset:offset + size])
        frames.append(layer2.copy() / piece)
    if args.overlap is not None:
        rewritten = bytearray(raw)
        rewritten[2:4] = args.overlap.to_bytes(2, "big")
        piece = IP(
            src=header.src, dst=header.dst, id=header.id, proto=header.proto,
            flags="MF", frag=0,
        ) / Raw(bytes(rewritten[:size]))
        frames.append(layer2.copy() / piece)
    return frames


def send_only(args, subnet, src, src_mac, own_mac):
    """Probes that expect no answer: the test looks for the event they cause."""
    if args.mode == "arp":
        sendp(
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=2, psrc=src, hwsrc=src_mac, pdst=src, hwdst="ff:ff:ff:ff:ff:ff"),
            iface=IFACE,
        )
    elif args.mode == "ipv6":
        sendp(
            Ether(src=src_mac, dst="33:33:00:00:00:01")
            / IPv6(src="fe80::1", dst="ff02::1")
            / UDP(sport=9000, dport=9000),
            iface=IFACE,
        )
    elif args.mode == "icmp-error":
        about, port = args.about.rsplit(":", 1)
        quoted = IP(src=args.dst, dst=about) / UDP(sport=args.dport, dport=int(port))
        sendp(
            Ether(src=src_mac, dst=destination_mac(args.dst, subnet))
            / IP(src=src, dst=args.dst)
            / ICMP(type=3, code=3)
            / bytes(quoted)
            / Raw(b"data of my choice"),
            iface=IFACE,
        )
    else:
        # Raw bytes, to send tens of thousands of datagrams in about a second.
        import socket

        frame = bytearray(
            bytes(
                Ether(src=own_mac, dst=destination_mac(args.dst, subnet))
                / IP(src=src, dst=args.dst)
                / UDP(sport=40000, dport=1, chksum=0)
                / Raw(b"x")
            )
        )
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((IFACE, 0))
        for index in range(args.count):
            frame[34:36] = (40000 + index // 65535).to_bytes(2, "big")
            frame[36:38] = (1 + index % 65535).to_bytes(2, "big")
            sock.send(frame)
    print("sent")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=["udp", "tcp", "flood", "scan", "icmp-error", "arp", "ipv6"]
    )
    parser.add_argument("--sport", type=int)
    parser.add_argument("--about")
    parser.add_argument("--dst")
    parser.add_argument("--dport", type=int)
    parser.add_argument("--src")
    parser.add_argument("--src-mac")
    parser.add_argument("--to-mac")
    parser.add_argument("--vlan")
    parser.add_argument("--fragment", type=int)
    parser.add_argument("--overlap", type=int)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--wait", type=float, default=4)
    args = parser.parse_args()

    subnet = network()
    own_ip = get_if_addr(IFACE)
    own_mac = get_if_hwaddr(IFACE)
    src = args.src or own_ip
    src_mac = args.src_mac or own_mac

    if args.mode in ("scan", "icmp-error", "arp", "ipv6"):
        send_only(args, subnet, src, src_mac, own_mac)
        return 0

    if args.mode == "flood":
        to_mac = destination_mac(args.dst, subnet)
        frames = []
        for _ in range(args.count):
            host = str(subnet.network_address + random.randint(200, subnet.num_addresses - 2))
            frames.append(
                Ether(src=own_mac, dst=to_mac)
                / IP(src=host, dst=args.dst)
                / UDP(sport=random.randint(1024, 65535), dport=args.dport)
                / Raw(b"ping")
            )
        sendp(frames, iface=IFACE)
        print(f"sent {len(frames)}")
        return 0

    to_mac = args.to_mac or destination_mac(args.dst, subnet)
    sport = args.sport or random.randint(20000, 60000)
    if args.mode == "udp":
        transport = UDP(sport=sport, dport=args.dport) / Raw(b"ping")
    else:
        transport = TCP(sport=sport, dport=args.dport, flags="S", seq=random.randint(0, 2**31))

    def answer_arp(packet):
        # Replies to a borrowed address need someone to answer ARP for it.
        if ARP in packet and packet[ARP].op == 1 and packet[ARP].pdst == src and src != own_ip:
            sendp(
                Ether(src=src_mac, dst=packet[ARP].hwsrc)
                / ARP(op=2, psrc=src, hwsrc=src_mac, pdst=packet[ARP].psrc, hwdst=packet[ARP].hwsrc),
                iface=IFACE,
            )

    sniffer = AsyncSniffer(iface=IFACE, prn=answer_arp, store=True, promisc=True)
    sniffer.start()
    time.sleep(0.3)
    sendp(frame(args, src, src_mac, to_mac, transport), iface=IFACE)
    time.sleep(args.wait)
    packets = sniffer.stop() or []

    seen = False
    for packet in packets:
        if IP not in packet or packet[IP].dst != src:
            continue
        if ICMP in packet and packet[ICMP].type == 3:
            print(f"rejected {packet[IP].src} code {packet[ICMP].code}")
            seen = True
        elif args.mode == "udp" and UDP in packet and packet[UDP].dport == sport:
            print(f"answered {packet[IP].src}:{packet[UDP].sport} {bytes(packet[UDP].payload)!r}")
            seen = True
        elif args.mode == "tcp" and TCP in packet and packet[TCP].dport == sport:
            print(f"answered {packet[IP].src}:{packet[TCP].sport} flags {packet[TCP].flags}")
            seen = True
    if not seen:
        print("nothing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
