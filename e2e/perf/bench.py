#!/usr/bin/env python3
"""Measurements for names-perf.sh, run in a tester container.

    bench.py tls <address> <port> <name> <count>        TLS handshakes, a connection each
    bench.py http <address> <port> <name> <count>       requests on one keep-alive connection
    bench.py quic <address> <port> <name> <count>       QUIC flows: Initial packets, answer
    bench.py bulk <address> <port> <name> <tls|tcp>     download until the server closes
    bench.py idle <address> <port> <name> <count> <seconds>
                                                        keep-alive connections, idle, then
                                                        a request on each

Prints one line: what was measured, and median, 90th and 99th percentile in milliseconds,
or the rate.
"""

import glob
import socket
import ssl
import statistics
import sys
import time


def summary(kind, times):
    times.sort()
    count = len(times)
    print(
        f"{kind}: n={count} median={statistics.median(times):.3f}ms "
        f"p90={times[int(count * 0.9)]:.3f}ms p99={times[int(count * 0.99)]:.3f}ms"
    )


def context():
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    return tls


def request(sock, reader, name):
    sock.sendall(f"GET / HTTP/1.1\r\nHost: {name}\r\n\r\n".encode())
    length = 0
    while (line := reader.readline()) not in (b"\r\n", b""):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":")[1])
    reader.read(length)


def main():
    kind, address, port, name, *rest = sys.argv[1:]
    port = int(port)
    if kind == "tls":
        times = []
        for _ in range(int(rest[0])):
            sock = socket.create_connection((address, port), timeout=5)
            start = time.perf_counter()
            context().wrap_socket(sock, server_hostname=name).close()
            times.append((time.perf_counter() - start) * 1000)
        summary("TLS handshake", times)
    elif kind == "http":
        sock = socket.create_connection((address, port), timeout=5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        reader = sock.makefile("rb")
        times = []
        for _ in range(int(rest[0])):
            start = time.perf_counter()
            request(sock, reader, name)
            times.append((time.perf_counter() - start) * 1000)
        summary("HTTP request on a keep-alive connection", times)
    elif kind == "quic":
        packets = [
            open(path, "rb").read()
            for path in sorted(glob.glob(f"/usr/local/share/quic/{name}-*.bin"))
        ]
        times = []
        for _ in range(int(rest[0])):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.connect((address, port))
            start = time.perf_counter()
            for packet in packets:
                sock.send(packet)
            sock.recv(65536)
            times.append((time.perf_counter() - start) * 1000)
            sock.close()
        summary("QUIC flow, first answer", times)
    elif kind == "bulk":
        sock = socket.create_connection((address, port), timeout=10)
        if rest[0] == "tls":
            sock = context().wrap_socket(sock, server_hostname=name)
        start = time.perf_counter()
        total = 0
        while data := sock.recv(1 << 20):
            total += len(data)
        print(f"bulk {rest[0]}: {total / (1 << 20) / (time.perf_counter() - start):.0f} MiB/s")
    elif kind == "idle":
        count, seconds = int(rest[0]), float(rest[1])
        connections = []
        for _ in range(count):
            sock = socket.create_connection((address, port), timeout=10)
            reader = sock.makefile("rb")
            request(sock, reader, name)
            connections.append((sock, reader))
        time.sleep(seconds)
        failed = 0
        for sock, reader in connections:
            try:
                request(sock, reader, name)
            except OSError:
                failed += 1
        print(f"idle keep-alive connections: {count}, failed after {seconds:.0f}s: {failed}")


main()
