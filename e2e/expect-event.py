#!/usr/bin/env python3
"""Wait for a Portcullis event matching every filter.

    expect-event.py <events socket> <timeout seconds> [--save FILE] <filter>...

Connects to the event stream, prints "ready" once subscribed (start the traffic that should
produce the event only after that), then reads events until one matches all filters.

Filters: `key=value` (the field's value, `null` for none) or `key~text` (contains). Exits
0 on a match; on timeout prints the events seen and exits 1. With --save, every event read
is appended to FILE.
"""

import json
import socket
import sys


def matches(event, filters):
    for key, operator, expected in filters:
        value = event.get(key)
        text = "null" if value is None else str(value)
        if operator == "=" and text != expected:
            return False
        if operator == "~" and expected not in text:
            return False
    return True


def parse_filter(argument):
    for operator in ("=", "~"):
        if operator in argument:
            key, expected = argument.split(operator, 1)
            return key, operator, expected
    raise SystemExit(f"invalid filter: {argument}")


def main() -> int:
    path, timeout, *rest = sys.argv[1:]
    save = None
    if rest[:1] == ["--save"]:
        save, rest = rest[1], rest[2:]
    filters = [parse_filter(argument) for argument in rest]

    seen = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(float(timeout))
        client.connect(path)
        print("ready", flush=True)
        stream = client.makefile("r", encoding="utf-8")
        try:
            for line in stream:
                if save:
                    with open(save, "a", encoding="utf-8") as output:
                        output.write(line)
                event = json.loads(line)
                if matches(event, filters):
                    print(line.strip(), flush=True)
                    return 0
                if event.get("event") != "applied":
                    seen.append(line.strip())
        except TimeoutError:
            pass
    print(f"no event matching {' '.join(rest)} within {timeout}s; seen:", file=sys.stderr)
    for line in seen[-10:]:
        print(f"  {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
