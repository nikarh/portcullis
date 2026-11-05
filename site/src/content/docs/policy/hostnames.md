---
title: Hostname rules
description: "How host: rules turn names into addresses, how long addresses stay allowed, and what that allows besides the name."
sidebar:
  order: 5
---

An IP firewall can't match hostnames, so a `host:` rule allows the addresses the hostname resolves to. Portcullis learns them in two ways.

## From the container's DNS answers

Portcullis inspects DNS answers to managed containers. The firewall holds each answer until Portcullis has added its addresses to the matching `host:` rules of the container that received it (a CNAME the name resolved through also counts), then releases it unchanged. The container can connect to exactly the addresses it was told, including ones that change with every lookup (CDNs, DNS load balancing).

- Queries still go to the resolver the container uses. Portcullis never answers or changes them.
- An answer only counts for the container that received it. A container that may ask a resolver of its choice can't make another container's `host:` rules allow whatever that resolver claims.
- At most 4096 addresses per hostname are kept at a time.
- If Portcullis isn't running or falls behind, answers go through uninspected rather than being lost, so DNS keeps working. Addresses in them are then missing from `host:` rules until a later lookup.
- DNS answers over TCP that span more than one packet aren't inspected; they still reach the container.

This needs Docker to forward the container's lookups from its own address; see [DNS visibility](/policy/dns/#dns-visibility).

## From Portcullis's own lookups

When a hostname has no known addresses, Portcullis resolves it itself through the host's resolver. That covers containers that resolved it before Portcullis started, and containers whose lookups it can't see. It retries every 30 seconds while the name doesn't resolve.

Until a name has addresses, its rules allow nothing; everything else is applied as usual. The [`applied` event](/reference/events/#applied) lists such names as `unresolved_hosts`.

## How long an address stays allowed

An address stays allowed for its DNS TTL, but at least `hostname-hold` seconds (an hour by default) after it was last seen, because applications often keep using an address longer than its TTL. Change it in the config:

```toml title="/etc/portcullis/config.toml"
hostname-hold = 3600
```

## Patterns

A [pattern](/policy/patterns/) such as `host:*.archive.org` can't be looked up, so it only allows addresses from DNS answers to the container for names it matches. Portcullis has to see the container's lookups. Of an answer, only the addresses of the name asked for, and of the CNAMEs it resolved through, count.

## What a hostname rule allows

A hostname rule allows the hostname's addresses, not the hostname. Any other service on the same addresses is reachable too, which is common with CDNs and shared hosting: `host:api.example.com` behind a large CDN allows every other site that CDN serves from the same addresses. Portcullis doesn't look at TLS SNI or HTTP Host headers.

When that matters, send the container's traffic through a proxy that filters by name; see [Filtering by hostname with a proxy](/examples/egress-proxy/).

A resolver the container may use and someone else controls can answer any name with any address, and the container's `host:` rule then allows that address. Allow only resolvers you trust; see [How DNS gets abused](/policy/domains/#how-dns-gets-abused).
