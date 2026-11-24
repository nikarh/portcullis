---
title: Architecture
description: The daemon, the two nftables tables, atomic updates, the packet hold for new containers, DNS inspection, and name checks.
sidebar:
  order: 1
---

Portcullis is a daemon that runs on the Docker host. It watches the Docker API for containers and networks, turns their labels into firewall rules, and updates the rules whenever something changes.

```text
 Docker API ──events──▶ ┌────────────┐ ──netlink batch──▶ kernel rules
 Docker's files ──────▶ │ portcullis │ ◀──NFLOG────── decisions to report
 rtnetlink ───────────▶ │   daemon   │ ◀─NFQUEUE───── held packets: new containers, DNS, names
                        └────────────┘ ──events──▶ stdout, socket, alert command
```

## Rules

The rules are nftables rules, kept in two tables of its own:

- an `inet` table for traffic leaving a container's network or addressed to the Docker host;
- a `bridge` table for everything entering a network's bridge from a container.

A Linux bridge passes traffic between containers directly, without the IP-level hooks Docker's own rules use, so only the bridge table can see it. The bridge table is also where Portcullis checks that each frame really comes from the container it claims to come from. Both work next to Docker's rules whether Docker itself uses iptables or nftables.

Each update changes the rules in one atomic step, so there is never a moment with half-applied rules: Portcullis sends it to the kernel as one batch of nftables netlink messages, which the kernel applies all or nothing, as it does a script `nft` runs. The rules are encoded as `nft` encodes them, so `nft list ruleset` shows them as if `nft` had added them. Each container has chains of its own, and an update only writes those of containers whose rules changed, and only adds and deletes the set elements that changed. The base chains every packet passes are only written again when their rules change, when networks come and go. An update costs what changed, not the size of the rules in place. A container starting leaves the chains of containers whose rules don't mention it as they are. Packets that pass while the kernel puts new rules in place are never misjudged: an established connection isn't denied, nor reported as sent from an unknown source, and nothing gets past a check meanwhile. Starting Portcullis updates the rules a previous run left in place the same way, instead of creating them again. A change that leaves every rule as it is, such as Docker's report of a container Portcullis [found before it](/internals/discovery/), costs no update at all.

Portcullis only removes access. Traffic that a policy allows still goes through Docker's own rules afterwards, so things Docker blocks (internal networks, isolation between networks) stay blocked.

Every update is also saved to the state directory, so the rules can be put back before Docker starts at the next boot. See [Boot order](/guides/service/#boot-order).

## Containers that just started

A container can start sending before Portcullis has seen it start. Its first packets then come from an address the rules don't know yet. Portcullis doesn't deny them: the firewall holds them (NFQUEUE) until the container's rules are in place and then runs them through those rules, so they are allowed or denied as if the rules had been there all along. TCP and UDP are only delayed, not lost.

Portcullis doesn't wait for Docker to report the container. It finds it from its bridge port as soon as the port comes up, or from the port a held packet came in on, through the kernel and the files Docker keeps for each container, usually within milliseconds; see [Finding new containers](/internals/discovery/). Its rules are then usually in place before it has sent anything.

Packets whose source is still unknown after 2 seconds are denied as spoofed: normally they belong to no container. On networks in monitor mode such packets are held the same way, so that they are reported with their container, and let through once the hold expires.

## Reports

The rules log what they allow and deny to an NFLOG group, which Portcullis reads. The kernel filters out repeats before they reach it: a flow is logged at most once a minute. Portcullis adds the container's name, the destination container for traffic between containers, and the domain, and writes the event.

## DNS inspection

Portcullis looks at the DNS answers containers receive. The firewall holds each answer to a managed container until Portcullis has read it, then releases it unchanged. That gives events their domains, and gives [hostname rules](/policy/hostnames/) the exact addresses each container was told. If Portcullis isn't running or falls behind, answers go through uninspected rather than being lost.

Portcullis also looks the hostnames of `host:` rules up itself, through the host's resolver, a few times per hold, and adds what it gets to the rules of every container that uses the name, without a rule update.

Addresses from DNS answers and Portcullis's own lookups go into the hostname sets in a netlink batch of their own, without a rule update. Neither these nor rule updates read anything of the kernel's rules first, so large sets in other tables, such as another firewall's block or country lists, cost them nothing. That keeps an address allowed while DNS still returns it, also for applications that resolved it once and kept it.

For containers with [`portcullis.domains`](/policy/domains/) labels, queries are held too, until Portcullis has checked the names they ask for. Those are denied, not let through, when Portcullis can't check them.

## Name checks

A `host:` rule checks the name a connection asks for (see [Names connections ask for](/policy/hostnames/#names-connections-ask-for)). The rules can't read TLS, HTTP or QUIC, so Portcullis does, for the first packets of each such connection only:

1. The rule that allows the connection by address marks it (a bit of the [connection's mark](/reference/host-resources/#connection-marks)) and hands its first packet to Portcullis (NFQUEUE), which notes where the client's data will start.
2. Every later packet of a marked connection, both ways, goes to Portcullis too: the first rule of each base chain of the inet table tests the mark, before established traffic passes. That test is all other traffic pays.
3. TCP: the handshake passes. The client's first data is held until it shows what it is: a ClientHello or HTTP request head, put together in order from however many packets it took, or something else. Then it is let through, or denied: the connection is marked denied, the client gets a TCP reset, and the kernel drops whatever else the connection sends. A connection that names no server, allowed by address, leaves the queue with its first data: Portcullis sends its packet back through the hook with a packet mark, from which the rules clear the connection's mark.
4. TLS: once the server has acknowledged the whole ClientHello, the connection leaves the queue the same way. Until then, data the client sends again in the same place must be what was checked: a client could otherwise send a ClientHello for an allowed name that never reaches the server (one sent to expire on the way, or with a bad checksum), and then another in its place. That is a few more packets per connection, all of the handshake's first round trip.
5. Plain HTTP: every request names a server, so the connection stays marked, and its client's packets with data keep going to Portcullis, which follows the requests by their bodies' lengths. Replies, and the client's packets without data, pass in the kernel. Portcullis keeps what it knows of the connection for as long as connection tracking keeps the connection: a connection that hasn't sent anything for a minute is looked up in connection tracking, and forgotten once connection tracking has forgotten it.
6. QUIC: the client's first Initial packets are decrypted, with keys anyone can derive from the connection ID the client chose (as Wireshark and Suricata do), and held until their CRYPTO frames hold the whole ClientHello, which can span several packets. Then the flow leaves the queue.

Whether a name's addresses include the destination, Portcullis asks the kernel's hostname sets, the same sets the rules match.

On networks in monitor mode, packets go to another queue, which lets them through when Portcullis isn't reading it; Portcullis reads copies and holds nothing. The queue of enforced networks drops what Portcullis doesn't read: while it isn't running, new connections through `host:` rules don't get past their handshake.

What it costs, measured in the end-to-end test VM (`e2e/names-perf.sh`), against an `ip:` rule to the same server: a TLS handshake took 0.05 to 0.1 ms longer (median about 1.7 ms) and about 0.12 ms of Portcullis's CPU time; a request on a plain HTTP keep-alive connection 0.01 ms longer and 7 µs of CPU; a new QUIC flow 0.04 to 0.3 ms longer and about 0.1 ms of CPU. The throughput of established connections, at about 1 GiB/s of TCP, didn't change measurably, with or without the test of the mark. A thousand idle keep-alive connections, looked up every 5 seconds, took 2 to 3 ms of CPU per second.

## Failure handling

Portcullis prefers stopping to running with part of its job undone, and its rules stay in place when it stops; systemd starts it again. Rule updates that fail are retried with backoff while the previous rules stay in force. See [When something fails](/guides/service/#when-something-fails).
