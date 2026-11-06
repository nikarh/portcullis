---
title: Troubleshooting
description: Symptoms, what causes them, and what to do, starting from the events Portcullis reports.
sidebar:
  order: 1
---

Almost every question starts with the events. Portcullis reports every denial, with the container, the destination and which part of the policy decided.

```bash
sudo portcullis watch                    # live, from the events socket
journalctl -u portcullis -o cat -f       # the same events, from the journal
```

`watch` needs `events-socket` set in the config (the packaged config sets `/run/portcullis.sock`). A client connecting to the socket first receives the current state.

## A container can't connect somewhere

Look for its `connection` events. The `reason` field names the label family that decided:

| `reason` | Decided by | Fix |
|---|---|---|
| `egress` | `portcullis.egress.*` | Add an [egress label](/policy/egress/) for the destination and port. |
| `dns` | `portcullis.dns.*`, or `portcullis.domains.*` when `query` is set | Allow the resolver with a [DNS label](/policy/dns/), or add the name to the [domains list](/policy/domains/). |
| `icc` | `portcullis.icc.*` | Change the [ICC mode](/policy/icc/) or add an `icc.allow` entry. `destination_container` names the target. |
| `limit` | connection limits | Raise `portcullis.limit.*`, see [Quarantine and limits](/policy/limits/). |
| `source`, `frame` | nothing you can allow | The container sent with someone else's address or MAC, or IPv6 or VLAN frames. See [below](#source-or-frame-events). |

An application error tells you how the traffic was denied:

- "Host is unreachable" (`EHOSTUNREACH`) right away: denied with `deny-action = "reject"`, the default.
- A timeout: denied with `deny-action = "drop"`, or the packet never reached Portcullis at all.

If there is no event for it, the traffic isn't being denied by Portcullis. Check that the container is managed: an `applied` event lists the managed container addresses, and a `container` event with `action: managed` reports each one. A container on a network without `portcullis.enable` isn't managed.

Remember that egress labels don't apply to DNS (port 53) or to containers on the same network, not even `ip:*,*`. Those are decided by the DNS labels and the ICC mode.

## DNS lookups fail with SERVFAIL

A container with `portcullis.domains` labels may only look up the names they list. Other lookups fail at once with `SERVFAIL` from Docker's DNS, and are reported as denied `dns` events with the name in `query`. Add the name, or a pattern for it, to a `portcullis.domains.*` label.

Look out for search domains: a lookup of `api` may first be tried as `api.corp.example`. The events show the exact names asked for.

While Portcullis isn't running, every lookup of such a container fails, rather than go unchecked.

## Label changes have no effect

Docker can't change the labels of a container or a network after it was created.

- Container labels: recreate the container (`docker compose up -d` does when the labels in the Compose file changed).
- Network labels: remove and create the network again, which means stopping its containers. To watch an existing network without recreating it, use `monitor-networks` in the config. See [Rolling out on a host with running stacks](/examples/existing-networks/).

An invalid label is reported as an `invalid_label` warning and ignored; the rest of the container's labels still apply. Ignoring a label never opens anything up: an invalid `portcullis.icc.mode` counts as `deny`, invalid `portcullis.dns.*` labels leave the container with no DNS, and an invalid `portcullis.enable` value enforces the network.

## The first connections after a container starts are slow

The first packets of a container that just started are held until Portcullis has its rules, then allowed or denied as its labels say. Portcullis finds the container from the packet's bridge port, usually within milliseconds. Where that doesn't work (rootless Docker, an unusual cgroup layout, or `docker-root` not pointing at Docker's data directory), it waits for Docker to report the container, and if that takes longer than 2 seconds the first packets are denied. TCP and DNS send them again. See [Finding new containers](/internals/discovery/).

If `docker info -f '{{.DockerRootDir}}'` isn't `/var/lib/docker`, set `docker-root` to it.

## A `host:` rule allows nothing

An `applied` event lists, under `unresolved_hosts`, the hostnames of `host:` rules with no known addresses. Their rules allow nothing until a container looks the name up or Portcullis can resolve it itself through the host's resolver; see [From Portcullis's own lookups](/policy/hostnames/#from-portculliss-own-lookups) for how often it tries.

Check that the host can resolve the name (`getent hosts api.example.com`), and that the container's lookups are visible to Portcullis (see [DNS visibility](/policy/dns/#dns-visibility)). Without visibility, a name that resolves to different addresses for the container than for the host (DNS load balancing, CDNs) allows the host's answer only.

## A pattern `host:` rule doesn't work

A pattern such as `host:*.archive.org` can't be looked up. It only allows addresses from DNS answers the container received for names it matches. Portcullis has to see the container's lookups: set `dns` in `/etc/docker/daemon.json`, or `dns:` on the container. A `dns_not_observable` warning at the container's start says it can't.

## Source or frame events

A well-behaved container never sends with an address or MAC that isn't its own, IPv6 or VLAN-tagged frames on a network without IPv6, or ARP with data after it. `source` and `frame` denials mean something in the container crafts its own packets: a compromised process, or a network tool. They get the container quarantined.

Some `source` denials aren't crafted, and don't get the container quarantined. Their `detail` tells them apart:

- `sent before its rules were in place`: the container's own address and MAC, from its own port, judged by rules that didn't know them yet. Containers that start or join a network while Portcullis updates its rules can cause a few.
- `uses its own address on <network>`: a container on several networks sent a packet with its address on one network out of another. Linux picks the interface by route, not by source address: while Docker attaches a container's networks one by one as it starts, a reply to a connection made to one of its addresses can leave through whichever network has the default route at that moment. The packet is dropped; the connection sends it again.
- a detail ending in `before Portcullis knew its port`: a packet of a container that just started was held, and Portcullis didn't learn the container in time (see [Finding new containers](/internals/discovery/)).

An enforced network with IPv6 enabled has all IPv6 denied (and an `ipv6_network` warning). Disable IPv6 on it.

## A container is cut off completely

It was quarantined: look for a `quarantined` warning. Restart or recreate the container through Docker (`docker restart`) to let it back; it starts from a clean state. Being started again by its restart policy after it exited doesn't. Restarting Portcullis also releases every quarantined container.

If the container has a reason to craft packets, opt it out with `portcullis.quarantine=off`. If it was quarantined for too many denials, find out what it was trying to reach first. See [Quarantine and limits](/policy/limits/).

## A container's traffic isn't filtered

A container on an enforced network and on a network that isn't enforced is only restricted for traffic it sends from its enforced-network address. Its traffic through the other network isn't filtered at all. Portcullis reports this as `unenforced_network`.

Other configurations that get around the rules, such as `network_mode: host` or a shared network namespace, are reported too. See [Configuration checks](/policy/checks/).

A brand-new network isn't enforced until Portcullis has seen it created, usually within milliseconds. Containers that start on it in that window can get packets out. Create enforced networks ahead of time.

## Alerts don't arrive

- Monitor mode (`would_deny`) never raises alerts. Only `denied` connections, `apply_failed` and warnings do.
- The same alert (container, reason, destination and port) is raised at most once per `alert-interval`, 600 seconds by default.
- A container raises at most 10 alerts per interval. The tenth comes with an `alerts_suppressed` warning.
- A command running longer than 30 seconds is killed. At most 256 alerts wait for the command; more are dropped with a log message.
- The systemd unit makes `/usr`, `/boot`, `/etc`, `/home` and `/root` read-only to the alert command. Add other paths it writes with `ReadWritePaths=` in `systemctl edit portcullis`.

Test the command by hand with an event on stdin, and check `journalctl -u portcullis` for its errors.

## `apply_failed` events

A rule update failed. The previous rules stay in place, and Portcullis retries after 5 seconds, then less and less often, down to every 5 minutes, until it succeeds. The event's `error` says what the kernel or libnftables refused. Run with `log-level = "trace"` to log every firewall script that gets applied.

## `events_lost` warnings

The kernel produced log entries faster than Portcullis read them, and dropped the rest. Containers sending a flood of new flows cause this. Nothing gets through unchecked; only reports are lost. Look for a container with many denials around the same time.

## Inspecting the rules

Portcullis keeps its rules in two tables of its own:

```bash
sudo nft list table inet portcullis
sudo nft list table bridge portcullis
```

They are generated and replaced in one step on every update; don't edit them. With `log-level = "trace"`, every script Portcullis applies is logged to stderr.

## Conflicts with other software

Portcullis uses NFLOG group 4242, NFQUEUE 4242 to 4245, and packet marks 0x70630001 to 0x70630003. Other software on the host that uses the same numbers breaks it, and the other way round. See [Host resources](/reference/host-resources/).

## Removing everything

Stopping Portcullis keeps its rules in place by default. To remove them for good:

```bash
sudo systemctl disable --now portcullis
sudo portcullis cleanup
```

`cleanup` removes the saved rules too, so they don't come back at the next start. Removing the package runs it for you.
