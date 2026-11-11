---
title: Architecture
description: The daemon, the two nftables tables, atomic updates, the packet hold for new containers, and DNS inspection.
sidebar:
  order: 1
---

Portcullis is a daemon that runs on the Docker host. It watches the Docker API for containers and networks, turns their labels into firewall rules, and updates the rules whenever something changes.

```text
 Docker API ──events──▶ ┌────────────┐ ──nft script──▶ libnftables ──▶ kernel rules
 Docker's files ──────▶ │ portcullis │ ◀──NFLOG────── decisions to report
 rtnetlink ───────────▶ │   daemon   │ ◀─NFQUEUE───── held packets: new containers, DNS
                        └────────────┘ ──events──▶ stdout, socket, alert command
```

## Rules

The rules are nftables rules, kept in two tables of its own:

- an `inet` table for traffic leaving a container's network or addressed to the Docker host;
- a `bridge` table for everything entering a network's bridge from a container.

A Linux bridge passes traffic between containers directly, without the IP-level hooks Docker's own rules use, so only the bridge table can see it. The bridge table is also where Portcullis checks that each frame really comes from the container it claims to come from. Both work next to Docker's rules whether Docker itself uses iptables or nftables.

Each update changes the rules in one atomic step, so there is never a moment with half-applied rules. Each container has chains of its own, and an update only writes those of containers whose rules changed; a container starting leaves the chains of containers whose rules don't mention it as they are. Packets that pass while the kernel puts new rules in place are never misjudged: an established connection isn't denied, nor reported as sent from an unknown source, and nothing gets past a check meanwhile. Starting Portcullis updates the rules a previous run left in place the same way, instead of creating them again.

Portcullis only removes access. Traffic that a policy allows still goes through Docker's own rules afterwards, so things Docker blocks (internal networks, isolation between networks) stay blocked.

Every update is also saved to the state directory, so the rules can be put back before Docker starts at the next boot. See [Boot order](/guides/service/#boot-order).

## Containers that just started

A container can start sending before Portcullis has seen it start. Its first packets then come from an address the rules don't know yet. Portcullis doesn't deny them: the firewall holds them (NFQUEUE) until the container's rules are in place and then runs them through those rules, so they are allowed or denied as if the rules had been there all along. TCP and UDP are only delayed, not lost.

Portcullis doesn't wait for Docker to report the container. It finds it from the packet's bridge port, through the kernel and the files Docker keeps for each container, usually within milliseconds; see [Finding new containers](/internals/discovery/).

Packets whose source is still unknown after 2 seconds are denied as spoofed: normally they belong to no container. On networks in monitor mode such packets are held the same way, so that they are reported with their container, and let through once the hold expires.

## Reports

The rules log what they allow and deny to an NFLOG group, which Portcullis reads. The kernel filters out repeats before they reach it: a flow is logged at most once a minute. Portcullis adds the container's name, the destination container for traffic between containers, and the domain, and writes the event.

## DNS inspection

Portcullis looks at the DNS answers containers receive. The firewall holds each answer to a managed container until Portcullis has read it, then releases it unchanged. That gives events their domains, and gives [hostname rules](/policy/hostnames/) the exact addresses each container was told. If Portcullis isn't running or falls behind, answers go through uninspected rather than being lost.

Portcullis also looks the hostnames of `host:` rules up itself, through the host's resolver, a few times per hold, and adds what it gets to the rules of every container that uses the name, without a rule update. That keeps an address allowed while DNS still returns it, also for applications that resolved it once and kept it.

For containers with [`portcullis.domains`](/policy/domains/) labels, queries are held too, until Portcullis has checked the names they ask for. Those are denied, not let through, when Portcullis can't check them.

## Failure handling

Portcullis prefers stopping to running with part of its job undone, and its rules stay in place when it stops; systemd starts it again. Rule updates that fail are retried with backoff while the previous rules stay in force. See [When something fails](/guides/service/#when-something-fails).
