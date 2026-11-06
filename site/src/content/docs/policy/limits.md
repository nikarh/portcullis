---
title: Quarantine and limits
description: How misbehaving containers are cut off, and the per-container limits on open and new connections.
sidebar:
  order: 9
---

A compromised container can try to flood its network or the host instead of getting past its rules. Portcullis cuts off containers that misbehave, and limits how many connections each container can have.

## Quarantine

A container is quarantined when:

- it sends anything with an address or MAC that isn't its own, or a kind of frame enforced networks don't carry (a `source` or `frame` denial). A well-behaved container never does: it takes a raw socket and intent. IPv6 on a network with IPv6 enabled doesn't count.
- more than `quarantine-denials` (1000 by default) of its connections are denied within a minute: scanning, probing, or flooding destinations it may not reach.

A quarantined container is cut off from its networks: nothing it sends gets anywhere, not even ARP, and the firewall drops it before looking at anything else. It is reported with a `quarantined` warning, which raises an [alert](/guides/events-and-alerts/#alerts).

Restarting the container through Docker (`docker restart`, `docker stop` or `docker kill` and then `docker start`, or recreating it) lets it back, starting from a clean state; if it misbehaves again, it is quarantined again. A container can't let itself back: when it exits on its own and its restart policy (`restart: always`, `unless-stopped`, `on-failure`) starts it again, it stays cut off. So does every quarantined container when Docker restarts. Quarantine is kept in memory, so restarting Portcullis lets quarantined containers back.

| Setting | Effect |
| --- | --- |
| `quarantine = "isolate"` (default) | cut off containers as above |
| `quarantine = "report"` | only report what would be done, with the same warning |
| `quarantine = "off"` | nothing |
| `quarantine-denials = 1000` | denied connections per minute past which a container is quarantined |

A container that has a reason to misbehave, such as a network tool that crafts its own packets, can opt out:

```yaml
labels:
  - portcullis.quarantine=off
```

The label takes `on` (the default) or `off`. Its traffic is still checked and denied as usual; it just isn't cut off for it.

On networks in monitor mode, nothing is cut off.

## Connection limits

Two limits, by bridge port, protect what all containers share:

```text
portcullis.limit.connections=<n>|none     open connections at a time (default: connection-limit, 16384)
portcullis.limit.new-connections=<n>      new connections per second (default: no limit)
```

The kernel tracks every open connection on the host in one table. A container opening connections without end would fill it, and then new connections of every container on the host fail. The open connections limit keeps one container from doing that. Set it for every container with `connection-limit` in the config (a number, or `"none"`), and per container with the label.

The new connections limit is off unless a label sets it, since normal rates vary widely. It suits containers that only make a few connections.

Connections over either limit are denied and reported with reason `limit`.

```yaml title="docker-compose.yml"
services:
  crawler:
    labels:
      - portcullis.egress.web=ip:public,tcp:80,443
      - portcullis.limit.connections=2000
      - portcullis.limit.new-connections=50
  proxy:
    labels:
      - portcullis.limit.connections=none
```

## What they don't cover

Quarantine and limits only cover containers whose bridge port Portcullis knows. They can't stop a container from using up bandwidth or CPU with traffic its rules allow. Give containers CPU limits, and, where bandwidth matters, limit it on the host with `tc`; see [Limits and workarounds](/limits/escape-hatches/#bandwidth-and-cpu).
