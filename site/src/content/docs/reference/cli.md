---
title: Command line
description: The portcullis daemon and its watch, audit and cleanup subcommands.
sidebar:
  order: 1
---

```text
portcullis [OPTIONS]                       run the firewall daemon
portcullis watch [--events-socket <path>]  show live events of a running daemon
portcullis audit [--since <time>] [FILE]   summarize what containers tried that their labels don't allow
portcullis cleanup [--state-dir <path>]    remove all firewall rules Portcullis left in place, and the saved ones
portcullis --version
portcullis --help
```

Errors are printed to stderr as `portcullis: <message>`, and the exit code is 1.

## `portcullis`

Runs the daemon in the foreground until it gets SIGINT or SIGTERM. It needs root. Settings come from `/etc/portcullis/config.toml` if it exists, and from options, which override the file; see [Configuration](/reference/configuration/) for every option.

```bash
sudo portcullis --monitor --log-format json
sudo portcullis --config ./test.toml --log-level debug
```

Run it as a service rather than by hand, so that it starts before Docker; see [Running as a service](/guides/service/).

## `portcullis watch`

```bash
sudo portcullis watch
sudo portcullis watch --events-socket /run/portcullis.sock
```

Connects to a running daemon's events socket and prints events as text, live, until interrupted. On connecting it first prints the current state.

The socket is `--events-socket`, else `events-socket` from the config file (`--config` to read another), else `/run/portcullis.sock`. The daemon only serves events there when its `events-socket` setting is on, as in the packaged config. The socket has mode `0600`, so `watch` normally needs root.

Lines that aren't events are printed as they are.

## `portcullis audit`

```bash
journalctl -u portcullis -o cat | portcullis audit
portcullis audit events.jsonl
portcullis audit --since 2026-11-06T10:30 events.jsonl
journalctl -u portcullis -o cat | portcullis audit --since 12h
```

Reads JSON events (`log-format = "json"`) from `FILE`, or from stdin when `FILE` is `-` or missing, and ignores every other line. Prints, per container, the labels that would have allowed its denied and would-be-denied connections, followed by warnings. It doesn't need root or a running daemon.

```text
billing (12 denied or would-be-denied connections)
  portcullis.egress.api-stripe-com=host:api.stripe.com,tcp:443
  portcullis.icc.allow.db=container:db,tcp:5432
    (with portcullis.icc.mode=allow-listed)
```

It joins consecutive ports into ranges, folds three or more hostnames under one domain with the same ports into a [pattern](/policy/patterns/), and ten or more public addresses with the same ports into `ip:public`. Ten or more public addresses left over, each with ports of its own (peers of a peer-to-peer protocol, say), are folded into `ip:public` too, with all their ports. More than ten ports of one protocol become one range, from the lowest to the highest. Each target gets one label: suggestions for the same target are merged, a pattern takes in the names and narrower patterns it covers, and a pattern whose key would be the same as a name's gets `-subdomains` (`portcullis.egress.archive-org-subdomains=host:**.archive.org` next to `portcullis.egress.archive-org=host:archive.org`).

A suggestion to reach the Docker host (a network's gateway, see [The Docker host](/policy/egress/#the-docker-host)) comes with a note: it lets the container reach services on the host. Traffic that Docker's userland proxy (`docker-proxy`) forwards to a container from a published port comes from the gateway, so a container may have learned the address from that, rather than needing it.

Packets of connections the firewall didn't track (`mid_stream`), traffic labels can't allow, and traffic sent with someone else's address are listed apart. `source` denials that weren't crafted (see [Source or frame events](/help/troubleshooting/#source-or-frame-events)) are listed as needing no label.

`--since` leaves out events from before a time: a UTC time as events have it, or the start of one (`2026-11-06`, `2026-11-06T10:30`), or how long ago (`30m`, `12h`, `7d`). Use it to leave out what containers did before they were recreated with the labels they have now. See [Rolling out a policy](/guides/rollout/#3-turn-events-into-labels).

With no denials in the input, it prints `No denied or would-be-denied traffic found.`

## `portcullis cleanup`

```bash
sudo systemctl disable --now portcullis
sudo portcullis cleanup
```

Removes every firewall rule Portcullis owns (its `inet` and `bridge` tables) and what it saved in the state directory (the rules, and who container addresses belonged to), so they don't come back at the next start. Prints `portcullis: firewall rules removed`.

The state directory is `--state-dir`, else `state-dir` from the config file, else `/var/lib/portcullis`. Stop the daemon first: a running daemon puts its rules back at its next update.

## `--version`, `--help`

`-V`, `--version` prints the version, such as `portcullis 0.2.0`, or `portcullis 0.2.0-dev+abc1234` for a build of `main`. `-h`, `--help` prints a summary of the commands and options.
