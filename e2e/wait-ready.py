#!/usr/bin/env python3
"""Stand in for systemd's notification socket (Type=notify).

    wait-ready.py <socket> <timeout>

Binds <socket>, prints "listening", then waits for a READY=1 notification and prints
"ready". Exits 1 if none comes within <timeout> seconds.
"""

import os
import socket
import sys


def main():
    path, timeout = sys.argv[1], float(sys.argv[2])
    if os.path.exists(path):
        os.unlink(path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.bind(path)
        sock.settimeout(timeout)
        print("listening", flush=True)
        try:
            while True:
                message = sock.recv(4096).decode()
                if "READY=1" in message.split("\n"):
                    print("ready", flush=True)
                    return 0
        except socket.timeout:
            return 1
        finally:
            os.unlink(path)


if __name__ == "__main__":
    sys.exit(main())
