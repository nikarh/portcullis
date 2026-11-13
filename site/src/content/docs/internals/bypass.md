---
title: Containers trying to get around the rules
description: What a compromised container with a raw socket can try, and how Portcullis keeps it within its labels.
sidebar:
  order: 3
---

Portcullis assumes a container may be compromised and actively try to get past its rules. With Docker's default capabilities, a container can send any frame it likes through a raw socket (`NET_RAW`). Portcullis makes sure that doesn't get it anywhere its labels don't allow, and reports every attempt.

## Identity

- Every frame entering an enforced bridge has to come from a managed container's own port on the bridge (the host side of its network interface), with that container's MAC and, for IPv4 and ARP, its address. Borrowing another container's address, MAC or both doesn't borrow its rules or its connections.
- A container can't take over another container's MAC in the bridge's forwarding table, or claim another container's address, or the gateway's, in its neighbours' ARP caches.
- ARP has to be a plain request or reply for Ethernet and IPv4: 28 bytes, or 46 with zero padding. ARP reaches other containers whatever their ICC rules, so data after it, or ARP of another shape, is denied as a frame enforced networks don't carry.
- Portcullis finds each container's port by asking the kernel about the container's network namespace; it never runs anything inside the container.
- Routed traffic is only checked against a container's egress rules when it comes in from a managed network's bridge. Packets with a container's address from anywhere else aren't the container's: they aren't reported as its, and don't count towards its [quarantine](/policy/limits/#quarantine).
- A container with no port on the bridge, such as one that is stopping (Docker removes its interface before it reports it gone), can't send anything there, so nothing sent with its address or MAC passes as its.
- When Docker gives a removed container's address to a new container, Portcullis deletes the old container's tracked connections first, so the new container can't keep using them. That holds when Portcullis finds the new container before Docker reports the old one gone, and when the address changed hands while Portcullis wasn't running: it keeps who each address belongs to in `state-dir`. The connections the new container makes in the meantime are its own, under its own rules, and stay when Docker reports the old one gone; only while both containers still run, and it isn't known whose rules apply, are they deleted again then.

## Connections

- Established connections only pass once their source checks out.
- ICMP errors about a connection are only accepted from one of its two ends, so they can't be used to send data to wherever another container has a connection.
- Fragmented packets are put back together before the rules look at them, so fragments can't hide or rewrite ports.

## Frames and addresses

- Enforced bridges only carry IPv4 and ARP. IPv6, VLAN-tagged frames (the receiving container's kernel could unwrap them past the rules) and anything else are denied. So are frames to the link-local group addresses used by STP and LLDP, which the bridge hands to the host past its usual checks.
- Traffic between two containers has to be addressed to their shared network. A frame to another container's MAC addressed to that container's address on another network is denied, even with ICC allowed. Broadcast and multicast count as traffic to other containers.
- Traffic to the Docker host follows the egress labels, and rules see the destination the container asked for, before Docker's DNAT of published ports. That includes the host's copy of broadcast to the network's subnet: the ICC rules decide whether other containers get it, the egress rules whether the host does.
- Traffic denied for using someone else's address or MAC is dropped, not rejected, whatever `deny-action` says: a rejection would only go back to the sender, addressed to someone else.

## Timing

- Packets from a port Portcullis doesn't know yet (a container that just started) are held for at most 2 seconds and then denied. Flooding that queue makes the kernel drop them; it never lets them through. On networks in monitor mode the same queue lets them through instead.
- Rule updates never misjudge packets that pass while the kernel puts them in place. The `updates` end-to-end scenario floods traffic between containers and out while rules are updated dozens of times.

## DNS

- Addresses a container learns from DNS answers only count for its own `host:` rules, so a container that may ask a resolver of its choice can't widen anyone else's. What it learns is bounded too: at most 4096 addresses per hostname at a time.
- Lookups themselves can carry data out; see [How DNS gets abused](/policy/domains/#how-dns-gets-abused) and the `portcullis.domains` labels that close it.

## Reports

Reports can't be flooded away. A flood of new flows can fill the set Portcullis uses to report each flow once a minute; denials are then still reported, up to 10 a second per rule. A container's alerts are limited as described under [Alerts](/guides/events-and-alerts/#alerts).

A well-behaved container never causes `source` or `frame` events: it sends with its own address and MAC, and Docker doesn't set it up to send IPv6 or VLAN frames on a network without IPv6. Such events are a strong sign that a container is compromised, or at least running tools that craft their own packets. They name the container behind the port the frame came from, whatever address or MAC it used, raise alerts, and get the container [quarantined](/policy/limits/#quarantine). A few `source` events don't get it quarantined, because a container sends such packets without crafting them: its own traffic judged before its rules were in place, and its address on another of its networks (see [Quarantine](/policy/limits/#quarantine)).

## Tests

These are covered by the `bypass` end-to-end scenario, which sends hand-made frames from a container with scapy: borrowed addresses and MACs, VLAN tags, overlapping fragments, ARP claims, ARP carrying data, broadcast to the host, IPv6, link-local group addresses, spoofed traffic into another container's connection, and floods of reports and alerts. See [Development](/project/development/#end-to-end-tests).

What a firewall can't prevent is listed under [Limitations](/limits/limitations/).
