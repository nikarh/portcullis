#!/usr/bin/env python3
"""A proxy to Docker's API that answers about containers late, as Docker does on a busy host.

    slow-docker.py <listen socket> <docker socket> <arm file> <delay seconds> [<event delay>]

Docker answers an inspect of a container only once it has finished starting it, which takes
seconds for a container on many networks on a slow disk; its events come at once. While
<arm file> exists, every container inspect (`GET .../containers/<id>/json`) is passed on
after <delay seconds>, and each part of the event stream after <event delay> (0 by default),
as if Portcullis were slow to handle events, like on a busy host; everything else at once.
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


def pump_events(source: socket.socket, target: socket.socket, arm: str, delay: float) -> None:
    try:
        while data := source.recv(65536):
            if delay and os.path.exists(arm):
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


def serve(client: socket.socket, docker: str, arm: str, delay: float, event_delay: float) -> None:
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.connect(docker)
    # The first request tells the event stream from API calls.
    first = client.recv(65536)
    upstream.sendall(first)
    events = re.match(rb"GET /[^ ]*events", first) is not None
    threading.Thread(target=pump, args=(client, upstream, arm, delay), daemon=True).start()
    if events:
        threading.Thread(
            target=pump_events, args=(upstream, client, arm, event_delay), daemon=True
        ).start()
    else:
        threading.Thread(target=pump, args=(upstream, client, arm, 0), daemon=True).start()


def main() -> int:
    listen, docker, arm, delay, *rest = sys.argv[1:]
    event_delay = float(rest[0]) if rest else 0.0
    if os.path.exists(listen):
        os.unlink(listen)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(listen)
    server.listen(64)
    while True:
        client, _ = server.accept()
        threading.Thread(
            target=serve, args=(client, docker, arm, float(delay), event_delay), daemon=True
        ).start()


if __name__ == "__main__":
    sys.exit(main())
