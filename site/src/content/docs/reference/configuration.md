---
title: Configuration
description: Every setting of the config file and command line, with its default.
sidebar:
  order: 2
---

Portcullis reads its settings from `/etc/portcullis/config.toml`, if it exists. Each option below is a key there, without its `--`:

```toml title="/etc/portcullis/config.toml"
monitor = true
deny-action = "drop"
events-socket = "/run/portcullis.sock"
alert-exec = "logger -t portcullis-alert"
connection-limit = "none"
```

[`dist/config.toml`](https://github.com/nikarh/portcullis/blob/main/dist/config.toml) lists every setting with its default; the packages install it. To change a setting, edit the file and restart Portcullis (`sudo systemctl restart portcullis`). The rules stay in place while it restarts.

- Unknown keys and invalid values are errors, and Portcullis doesn't start with them.
- The same options can be given on the command line, and override the file.
- `--config <path>` reads another file instead, and that one must exist.
- `portcullis watch` and `portcullis cleanup` read the file too, for the events socket and the state directory.

## Policy

| Option | Default | Description |
| --- | --- | --- |
| `--monitor` | off | Monitor mode on every network: report what would be denied, deny nothing. In the file, `monitor = true` or `false`. |
| `--monitor-network <name>` | none | Watch this network in monitor mode without a `portcullis.enable` label; `*` watches every bridge network. Repeat the flag for more networks. In the file, `monitor-networks = ["backend", "frontend"]`. A network's label, if it has one, wins. See [Enforcing a network](/policy/networks/#watching-networks-without-a-label). |
| `--deny-action <reject\|drop>` | `reject` | `reject` answers denied traffic with an ICMP "administratively prohibited" error, so applications fail immediately with "Host is unreachable". `drop` discards it silently, and applications wait for their own timeout. Traffic denied for its source or kind (reasons `source` and `frame`) is always dropped: a rejection would go to an address the sender only claims. |
| `--hostname-hold <duration>` | `3600` | How long an address of a `host:` rule stays allowed after DNS last returned it: seconds, or a number with `s`, `m`, `h` or `d`, from 10s to 7d. Containers can set their own with `portcullis.hostname-hold`. See [Hostname rules](/policy/hostnames/#how-long-an-address-stays-allowed). |
| `--quarantine <isolate\|report\|off>` | `isolate` | What happens to a container that misbehaves, see [Quarantine](/policy/limits/#quarantine). |
| `--quarantine-denials <n>` | `1000` | Denied connections per minute past which a container is quarantined. |
| `--connection-limit <n\|none>` | `16384` | Open connections a container may have at a time, unless its labels say otherwise. At least 1. In the file, a number or `"none"`. See [Connection limits](/policy/limits/#connection-limits). |

## Events and alerts

| Option | Default | Description |
| --- | --- | --- |
| `--log-allowed <always\|monitor\|never>` | `monitor` | Which allowed connections and successful DNS lookups are reported. Denied and would-be-denied ones always are. `monitor` reports them on networks in monitor mode only. |
| `--events-socket <path>` | off | Serve events as JSON lines on a Unix socket, mode `0600`. The packaged config sets `/run/portcullis.sock`. |
| `--alert-exec <command>` | off | Run a command with `sh -c` for every denial and warning, the event as JSON on stdin, see [Alerts](/guides/events-and-alerts/#alerts). |
| `--alert-interval <seconds>` | `600` | Raise the same alert at most once per interval. |
| `--log-format <text\|json>` | `text` | Format of events (stdout) and diagnostic logs (stderr). |
| `--log-level <error\|warn\|info\|debug\|trace>` | `info` | Level of diagnostic logs. `trace` logs every firewall script that gets applied. |

## Docker and the host

| Option | Default | Description |
| --- | --- | --- |
| `--docker-socket <path>` | `/var/run/docker.sock` | Docker API socket. A `unix://` prefix is accepted. |
| `--docker-root <path>` | `/var/lib/docker` | Docker's data directory (`docker info -f '{{.DockerRootDir}}'`), where Portcullis reads the settings of containers that just started, see [Finding new containers](/internals/discovery/). |
| `--state-dir <path>` | `/var/lib/portcullis` | Where the rules are saved, to be put back first thing at the next start, see [Boot order](/guides/service/#boot-order). |
| `--on-exit <keep\|remove>` | `keep` | What happens to the firewall rules when Portcullis stops, see [While Portcullis isn't running](/guides/service/#while-portcullis-isnt-running). |

## Command line only

| Option | Description |
| --- | --- |
| `--config <path>` | Config file to read instead of `/etc/portcullis/config.toml`. It must exist. |
| `-V`, `--version` | Print the version. |
| `-h`, `--help` | Print a summary of the commands and options. |

## A complete file

```toml title="/etc/portcullis/config.toml"
monitor = false
monitor-networks = []
deny-action = "reject"
log-allowed = "monitor"
hostname-hold = "1h"
events-socket = "/run/portcullis.sock"
alert-exec = "logger -t portcullis-alert"
alert-interval = 600
log-format = "json"
log-level = "info"
quarantine = "isolate"
quarantine-denials = 1000
connection-limit = 16384
docker-socket = "/var/run/docker.sock"
docker-root = "/var/lib/docker"
state-dir = "/var/lib/portcullis"
on-exit = "keep"
```
