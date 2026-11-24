#!/usr/bin/env python3
"""A client that names the server it wants, for the name checks of host: rules.

    name-probe tls <address> <port> <name or -> [--pieces N] [--partial]
    name-probe http <address> <port> <host> [<host>...] [--pause SECONDS]
    name-probe raw <address> <port> <data>
    name-probe quic <address> <port> <name>

tls: a TLS handshake with that server name (none for -), its ClientHello sent in N TCP
segments; with --partial, only the first half of it, and then waits. Then an HTTP request.
http: one request per host on one connection (keep-alive), each after the answer to the
one before, SECONDS apart.
raw: sends the data, and prints "answered" if anything comes back.
quic: sends the Initial packets of a QUIC client for that name (captured, in
/usr/local/share/quic), and prints the answer.

Prints the body of the server's answer (the address it was sent to), one line per
request, or what went wrong: "reset", "unreachable", "closed" or "timeout".
"""

import errno
import glob
import socket
import ssl
import sys
import time


def connect(address, port):
    sock = socket.create_connection((address, int(port)), timeout=8)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def body(answer):
    return answer.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()


def tls(address, port, name, pieces, partial):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = context.wrap_bio(incoming, outgoing, server_hostname=None if name == "-" else name)
    sock = connect(address, port)
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    if partial:
        hello = hello[: len(hello) // 2]
    size = -(-len(hello) // pieces)
    for start in range(0, len(hello), size):
        sock.sendall(hello[start : start + size])
        time.sleep(0.05)

    def receive():
        data = sock.recv(65536)
        if not data:
            raise EOFError
        incoming.write(data)

    while True:
        try:
            client.do_handshake()
            break
        except ssl.SSLWantReadError:
            pending = outgoing.read()
            if pending:
                sock.sendall(pending)
            receive()
    client.write(f"GET / HTTP/1.1\r\nHost: {name}\r\n\r\n".encode())
    sock.sendall(outgoing.read())
    answer = b""
    while True:
        try:
            data = client.read(65536)
            if not data:
                break
            answer += data
        except ssl.SSLWantReadError:
            try:
                receive()
            except EOFError:
                break
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            break
    return body(answer)


def http(address, port, hosts, pause):
    sock = connect(address, port)
    reader = sock.makefile("rb")
    for index, host in enumerate(hosts):
        if index:
            time.sleep(pause)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        length = 0
        while (line := reader.readline()) not in (b"\r\n", b""):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        if not line:
            raise EOFError
        print(reader.read(length).decode().strip(), flush=True)


def raw(address, port, data):
    sock = connect(address, port)
    sock.sendall(data.encode() + b"\n")
    return "answered" if sock.recv(65536) else "closed"


def quic(address, port, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    sock.connect((address, int(port)))
    for path in sorted(glob.glob(f"/usr/local/share/quic/{name}-*.bin")):
        with open(path, "rb") as packet:
            sock.send(packet.read())
    return sock.recv(65536).decode(errors="replace").strip()


def main():
    kind, address, port, *rest = sys.argv[1:]
    try:
        if kind == "tls":
            name = rest[0]
            pieces = int(rest[rest.index("--pieces") + 1]) if "--pieces" in rest else 1
            print(tls(address, port, name, pieces, "--partial" in rest))
        elif kind == "http":
            pause = 0.0
            if "--pause" in rest:
                pause = float(rest[rest.index("--pause") + 1])
                rest = rest[: rest.index("--pause")]
            http(address, port, rest, pause)
        elif kind == "raw":
            print(raw(address, port, rest[0]))
        else:
            print(quic(address, port, rest[0]))
    except ConnectionResetError:
        print("reset")
    except ConnectionRefusedError:
        print("refused")
    except (EOFError, ssl.SSLEOFError):
        print("closed")
    except TimeoutError:
        print("timeout")
    except OSError as error:
        unreachable = error.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH)
        print("unreachable" if unreachable else f"error: {error}")


if __name__ == "__main__":
    main()
