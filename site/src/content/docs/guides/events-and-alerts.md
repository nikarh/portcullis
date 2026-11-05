---
title: Events and alerts
description: Where Portcullis reports its decisions, how much it writes, and how to get alerted about denials.
sidebar:
  order: 3
---

Portcullis doesn't store anything. It writes events, and hands denials and warnings to a command of your choice. Send them to whatever already collects your logs and alert there, or use the alert hook.

## Where events go

- stdout: one event per line, as text or, with `log-format = "json"`, as JSON. Under systemd this ends up in the journal.
- The events socket: with `events-socket = "/run/portcullis.sock"` (set in the packaged config), the same events as JSON lines on a Unix socket. A client connecting to it first receives the current state, then events as they happen.
- stderr: diagnostic logs, at `log-level`. Not events; meant for people.

The [event reference](/reference/events/) lists every event and field.

### Live view

```bash
sudo portcullis watch
```

`watch` connects to the events socket named in the config (or `--events-socket <path>`) and prints events as text. The socket has mode `0600`, so only root can connect; change it with `chmod` or `chown` after startup if another user needs access. A client that can't keep up is disconnected after 200 milliseconds rather than slowing anything down.

### From the journal

```bash
journalctl -u portcullis -o cat -f                 # follow
journalctl -u portcullis -o cat | grep '"verdict":"denied"'   # with log-format = "json"
```

## How much is written

A flow (container, destination, protocol and port) is reported at most once a minute, however many connections it makes; the kernel filters out repeats before they reach Portcullis. Replies and the rest of a connection are never reported.

What else is reported depends on `log-allowed` and the mode:

| `log-allowed` | Enforced network | Monitor network |
| --- | --- | --- |
| `monitor` (default) | denials | everything: allowed, would-be denied, DNS lookups |
| `always` | everything | everything |
| `never` | denials | would-be denied only |

In enforce mode with the default, only denials are reported, so once the labels are right there is little to nothing. Monitor mode reports every flow and every DNS lookup of the monitored containers; it is meant for rolling out, not to stay on.

Reports can't be flooded away. A flood of new flows can fill the set Portcullis uses to report each flow once a minute; denials are then still reported, up to 10 a second per rule. If the kernel produces log entries faster than Portcullis reads them, an `events_lost` warning says how many were lost.

## Alerts

```toml title="/etc/portcullis/config.toml"
alert-exec = "logger -t portcullis-alert"
alert-interval = 600
```

`alert-exec` runs the command with `sh -c` for every `denied` connection, `apply_failed` and `warning`, with the event as one line of JSON on stdin. Monitor mode (`would_deny`) never raises alerts.

- The same alert (same container, reason, destination and port) is raised at most once per `alert-interval` seconds.
- A container raises at most 10 alerts per `alert-interval`. Its tenth comes with an `alerts_suppressed` warning, itself an alert, and from then until the interval ends its denials are only reported as events. A container probing thousands of destinations would otherwise queue thousands of alerts, and every alert after them, of any container, would arrive hours late.
- At most 256 alerts wait for the command at a time; more are dropped with a log message.
- A command that runs longer than 30 seconds is killed.

Under the systemd unit, the command runs with the same sandbox as Portcullis: it can reach the network, but can't write outside `/var/lib/portcullis` and `/run`. See [The systemd unit](/guides/service/#the-systemd-unit).

### Examples

Post to an [ntfy](https://ntfy.sh) topic, the event as the message:

```toml
alert-exec = "curl -s -d @- https://ntfy.example.com/portcullis"
```

A one-line summary to a Slack incoming webhook, with `jq`:

```toml
alert-exec = """jq -c '{text: "portcullis: \\(.event) \\(.verdict // .kind // "") \\(.container // "") -> \\(.domain // .destination // "") \\(.message // .error // "")"}' | curl -s -H 'Content-Type: application/json' --data @- https://hooks.slack.com/services/XXX/YYY/ZZZ"""
```

To the journal under its own tag, for a log pipeline to pick up:

```toml
alert-exec = "logger -t portcullis-alert"
```

## Shipping events to a log system

With `log-format = "json"`, every line Portcullis writes to stdout is an event object, so a collector reading the journal only has to parse the message as JSON. With [Vector](https://vector.dev), for example:

```toml title="vector.toml"
[sources.portcullis]
type = "journald"
include_units = ["portcullis"]

[transforms.portcullis_events]
type = "remap"
inputs = ["portcullis"]
source = '''
. = parse_json!(.message)
'''
```

Diagnostic logs (stderr) end up in the journal under the same unit; with `log-format = "json"` they are JSON too, but have no `event` field. Filter on it to keep only events.

Alert on `"event":"connection"` with `"verdict":"denied"`, on `"event":"warning"`, and on `"event":"apply_failed"`; those are the events `alert-exec` would run for.
