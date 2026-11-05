---
title: Outbound connections
description: portcullis.egress labels, their destinations and services, the Docker host, published ports and multicast.
sidebar:
  order: 3
---

Each allowed destination outside the container's network is one label:

```text
portcullis.egress.<name>=<destination>,<service>[,<service>...]
```

`<name>` is any string that makes the label key unique, for example `0`, `1` or `stripe`.

```yaml title="docker-compose.yml"
labels:
  - portcullis.egress.stripe=host:api.stripe.com,tcp:443
  - portcullis.egress.ntp=ip:162.159.200.1,udp:123
  - portcullis.egress.internal=ip:10.20.0.0/16,tcp:80,443
  - portcullis.egress.peers=ip:public,tcp:*,udp:1024-65535
  - portcullis.egress.stun=ip:public,udp:3478-3479
```

## Destinations

| Destination | Matches |
| --- | --- |
| `ip:<address>` | one IPv4 address, such as `ip:1.1.1.1` |
| `ip:<cidr>` | a range, such as `ip:10.0.0.0/8` |
| `ip:public` | any public address (see below) |
| `ip:*` | any address, the Docker host's and the LAN's included |
| `host:<name>` | the addresses the name resolves to, such as `host:api.stripe.com`; see [Hostname rules](/policy/hostnames/) |
| `host:<pattern>` | the addresses of names matching a [pattern](/policy/patterns/), such as `host:*.archive.org` |

IPv6 addresses aren't accepted; see [Limitations](/limits/limitations/).

### `ip:public`

Any public address. That leaves out:

- private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`);
- shared address space (`100.64.0.0/10`, CGNAT);
- loopback, and link-local (`169.254.0.0/16`, with cloud metadata services);
- multicast, documentation, benchmarking and reserved ranges;
- the Docker host's own addresses, even public ones, also when the container reaches a published port through them.

It is for a container that may connect anywhere on the internet, but not to the host, the router or the LAN. See [Internet but not the LAN](/examples/internet-not-lan/).

## Services

At least one service follows the destination:

| Service | Allows |
| --- | --- |
| `tcp:443` | TCP to that port |
| `tcp:8000-8100` | TCP to any port of the range, both ends included |
| `tcp:80,443,8000-8100` | several ports and ranges: those after a protocol's first belong to it |
| `tcp:*` | TCP to any port |
| `udp:...`, `sctp:...` | the same for UDP and SCTP |
| `icmp`, `igmp`, `gre`, `esp`, `ah` | that protocol, which has no ports |
| `*` | anything |

`tcp:80,443,udp:53` reads as TCP 80 and 443, and UDP 53. A label without a service is invalid.

Replies, and ICMP errors about a connection, always pass. `icmp` is only needed for ICMP a container sends of its own, such as `ping`.

## The Docker host

The Docker host counts as a destination too. Traffic to any of its addresses (the network's gateway, its other interfaces) follows the egress labels, so a container can't reach services on the host, or other containers' published ports through the host, unless a label allows it:

```yaml
labels:
  - portcullis.egress.host-proxy=ip:172.18.0.1,tcp:3128
```

The gateway's address depends on the network's subnet. Give the network a fixed subnet in Compose to know it in advance:

```yaml title="docker-compose.yml"
networks:
  backend:
    labels:
      - portcullis.enable=true
    ipam:
      config:
        - subnet: 172.18.0.0/24
          gateway: 172.18.0.1
```

## Published ports and DNAT

Rules match the destination a container asked for. Docker reaches a published port through the host with DNAT when its userland proxy is off (`"userland-proxy": false`), and always from other networks, so the packet then goes to the container behind the port. A label naming the host's address and the published port still allows it, and a connection to another container's published port is never mistaken for traffic between containers on the same network.

## What egress labels don't cover

Egress labels don't apply to DNS (port 53) or to containers on the same network, not even `ip:*,*`. DNS is controlled by the [DNS labels](/policy/dns/), and containers on the same network by the [ICC mode](/policy/icc/); both are checked first. So `ip:1.1.1.1,udp:53` in an egress label has no effect: use `portcullis.dns.0=ip:1.1.1.1`.

Egress labels limit the connections a container opens. A container with a published port can exchange data with anyone allowed to connect to it, since replies to incoming connections are always allowed.

## Multicast group membership

When a process in a container joins a multicast group (SSDP for DLNA, mDNS, IPTV), the container's kernel announces it with IGMP membership reports, to `224.0.0.22` or the group's address. The bridge delivers them to the Docker host too, where they are denied and reported unless a label allows them. That tells you which containers join multicast groups.

Denying them breaks nothing unless something on the host acts on them: a multicast relay such as `igmpproxy` or `smcroute` that forwards the LAN's multicast into Docker networks learns from them which groups a container wants. Allow them for such containers:

```yaml
labels:
  - portcullis.egress.igmp=ip:224.0.0.0/4,igmp
```

Multicast sent to other containers on the same network is decided by ICC, see [Multicast between containers](/policy/icc/#multicast).
