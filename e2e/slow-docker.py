#!/usr/bin/env python3
"""A proxy to Docker's API that answers about containers late, as Docker does on a busy host.

    slow-docker.py <listen socket> <docker socket> <arm file> <delay seconds>

Docker answers an inspect of a container only once it has finished starting it, which takes
seconds for a container on many networks on a slow disk; its events come at once. While
<arm file> exists, every container inspect (`GET .../containers/<id>/json`) is passed on
after <delay seconds>; everything else, the event stream included, at once.
"""

import os
import re
import socket
import sys
import threading
import time

INSPECT = re.compile(rb"^GET /[^ ]*containers/(?!json)[^/ ]+/json", re.MULTILINE)


def pump(source: socket.socket, target: socket.socket, arm: str, delay: float) -> None:
    try:
        while data := source.recv(65536):
            if delay and os.path.exists(arm) and INSPECT.search(data):
                time.sleep(delay)
            target.sendall(data)
    except OSError:
        pass
    finally:
        for end in (source, target):
            try:
                end.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(client: socket.socket, docker: str, arm: str, delay: float) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.connect(docker)
    threading.Thread(target=pump, args=(client, upstream, arm, delay), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, client, arm, 0), daemon=True).start()


def main() -> int:
    listen, docker, arm, delay = sys.argv[1:]
    if os.path.exists(listen):
        os.unlink(listen)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(listen)
    server.listen(64)
    while True:
        client, _ = server.accept()
        serve(client, docker, arm, float(delay))


if __name__ == "__main__":
    sys.exit(main())
