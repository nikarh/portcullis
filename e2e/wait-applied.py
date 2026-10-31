#!/usr/bin/env python3
"""Block until Portcullis reports rules in place for all given addresses.

    wait-applied.py <events socket> <timeout seconds> <address>...

Reads the event stream (the current state arrives right after connecting) until an
"applied" event lists every address. Exits 1 on timeout or when the stream ends.
"""

import json
import socket
import sys


def main() -> int:
    path, timeout, *addresses = sys.argv[1:]
    wanted = set(addresses)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(float(timeout))
        client.connect(path)
        stream = client.makefile("r", encoding="utf-8")
        try:
            for line in stream:
                event = json.loads(line)
                if event.get("event") == "applied" and wanted <= set(event["sources"]):
                    return 0
        except TimeoutError:
            pass
    print(f"no applied event with {sorted(wanted)} within {timeout}s", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
