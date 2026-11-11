#!/usr/bin/env python3
"""Answer every UDP datagram on a port with the container's hostname.

    udp-answer PORT

One process reads and answers each datagram in turn. `socat UDP-RECVFROM:PORT,fork`
hands each datagram to a child process, and now and then leaves one unanswered when
datagrams arrive close together, which made checks that expect an answer fail at random.
"""

import socket
import sys


def main():
    answer = (socket.gethostname() + "\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", int(sys.argv[1])))
    while True:
        _, peer = sock.recvfrom(65535)
        try:
            sock.sendto(answer, peer)
        except OSError:
            # The rules may reject the answer (an ICMP error comes back on the socket).
            pass


if __name__ == "__main__":
    main()
