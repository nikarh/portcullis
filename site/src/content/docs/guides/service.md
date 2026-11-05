---
title: Running as a service
description: Boot ordering, what happens when something fails, upgrades, and stopping and removing Portcullis.
sidebar:
  order: 2
---

The packages install and set up the service for you, see [Installation](/start/installation/). This page explains what the setup guarantees, and what happens to containers when Portcullis isn't running.

## The systemd unit

The unit is [`dist/portcullis.service`](https://github.com/nikarh/portcullis/blob/main/dist/portcullis.service). It:

- runs Portcullis as a `Type=notify` service, ordered `Before=docker.service` and wanted by it, so it starts before Docker at boot and whenever Docker starts;
- restarts it 2 seconds after a failure, as often as it takes (`StartLimitIntervalSec=0`);
- keeps its saved rules in `/var/lib/portcullis` (`StateDirectory=`);
- keeps it from changing the system beyond its state directory and `/run`: `/usr`, `/boot` and `/etc` are read-only to it, and to `alert-exec` commands, and `/home` and `/root` too.

If an alert command needs to write somewhere else, add the path with `ReadWritePaths=` in `systemctl edit portcullis`. Settings belong in `/etc/portcullis/config.toml`, not in the unit; see [Configuration](/reference/configuration/).

The sandboxing limits mistakes more than attackers: Portcullis runs as root and has the Docker socket, which gives root on the host.

## Boot order

Docker starts containers with a restart policy as soon as it starts, and the kernel forgets every firewall rule at a reboot. If those containers started before Portcullis had put rules in place, they would be unrestricted until it did. So Portcullis saves the rules of every update (in `state-dir`), and when it starts, before anything else:

1. It puts the last saved rules back in place.
2. It reports itself ready to systemd, which only then starts Docker.
3. It waits for Docker to answer, however long that takes, then puts the rules for what is running now in place.

Between 1 and 3, containers on enforced networks are held back rather than let through. They come back with new bridge ports, which the restored rules don't know, so their first packets are held until Portcullis has their rules, and then go out, or are denied, as their labels say. Connections are delayed by a moment at boot, not lost. Containers on networks that aren't enforced aren't affected.

If Portcullis can't start at all, containers on enforced networks stay cut off: their packets are held for a Portcullis that isn't there, rather than sent without their rules. `portcullis cleanup` removes the rules and the saved ones, if you need them gone.

### Without systemd

Start Portcullis before Docker the same way; it waits for Docker on its own. Started after Docker, it works too, but containers that Docker started before it are unrestricted until it has caught up.

## When something fails

Portcullis prefers stopping to running with part of its job undone. Whenever it stops, its rules stay in place (unless `on-exit = "remove"` and a clean stop), and systemd starts it again 2 seconds later:

- If Docker stops or restarts, Portcullis keeps the rules in place, waits for Docker to come back, and then reads its state again.
- If Portcullis can't read the firewall's reports or held packets anymore, or anything in it fails unexpectedly (a panic), it logs why and exits with an error.
- If containers send faster than Portcullis can keep up (a flood), the kernel drops what doesn't fit. Reports are lost (an `events_lost` warning says so), and held packets (new containers' first packets, DNS queries and answers) are dropped, so those connections and lookups are retried or fail. Nothing gets through unchecked.
- If a rule update fails (an `apply_failed` event), the previous rules stay in place, and Portcullis tries again after 5 seconds, then less and less often, down to every 5 minutes, until it succeeds.

`systemctl status portcullis` and `journalctl -u portcullis` show what happened. Events go to stdout and diagnostic logs to stderr, so both end up in the journal.

## Upgrading

Install the newer package, or replace the binary and restart the service. The rules stay in place while it restarts:

```bash
sudo install -m 0755 portcullis/portcullis /usr/local/bin/
sudo systemctl restart portcullis
```

On start, Portcullis updates the rules the previous run left in place in one step, instead of creating them again, so established connections aren't interrupted.

## While Portcullis isn't running

By default (`on-exit = "keep"`), the firewall rules stay in place when Portcullis stops, whether it stops cleanly or crashes. A restart or an upgrade doesn't leave containers unrestricted:

- Containers that were running keep their last rules. Changes to labels, networks and hostname addresses aren't picked up until Portcullis runs again.
- Containers that start on an enforced network in the meantime can't send anything: they have no rules yet, so their packets are held for Portcullis and then dropped by the kernel. They get their rules as soon as Portcullis is back.
- DNS answers are let through without inspection, and nothing is reported.
- Containers with [`portcullis.domains`](/policy/domains/) labels can't look anything up: their queries are held for a Portcullis that isn't there.
- On networks in monitor mode, the first packets of new containers are let through.

When Portcullis starts again, it puts its saved rules back, and its first update replaces them in one step.

With `on-exit = "remove"`, Portcullis removes its rules, and the saved ones, when it stops cleanly. Containers are then unrestricted while it isn't running, including at the next boot until it starts. After a crash the rules stay, as with `keep`.

## Removing Portcullis

To remove the rules, for example after deciding not to use Portcullis anymore, stop and disable the service and run `cleanup`:

```bash
sudo systemctl disable --now portcullis
sudo portcullis cleanup
```

`cleanup` removes the saved rules too, so they don't come back at the next start. Uninstalling the package does both for you.
