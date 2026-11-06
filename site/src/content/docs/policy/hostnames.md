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

Portcullis also resolves every hostname of a `host:` rule itself, through the host's resolver: when a rule first needs it, then again four times per [hold](#how-long-an-address-stays-allowed) (every 15 minutes with the default hold of an hour). What a lookup returns is allowed for every container with a rule for the name, right away.

That covers what the container's own answers can't:

- Applications that resolve a name once and keep the address, such as nginx with a hostname in `proxy_pass`, or a connection pool. Without lookups of its own, Portcullis would stop allowing the address an hour after the container's lookup, while the application still uses it.
- Containers whose lookups Portcullis can't see, such as those using DNS over HTTPS or TLS.
- Containers that looked the name up before Portcullis started.

When the resolver doesn't answer, Portcullis tries again every 30 seconds. When it answers that the name doesn't exist, Portcullis asks again at the usual pace: the name may only exist for the resolver the container uses. Until a name has addresses, its rules allow nothing; everything else is applied as usual. The [`applied` event](/reference/events/#applied) lists such names as `unresolved_hosts`, and a new `applied` event follows as soon as one resolves.

Lookups go through the host's resolver (`/etc/resolv.conf`, `/etc/hosts`), not the container's. The host's resolver can give other addresses for the same name than the container's does, for names that resolve differently by location or network. The container's own answers still count for it.

## How long an address stays allowed

An address stays allowed for the hold, an hour by default, after anything last said it belongs to the name: a DNS answer to the container, or one of Portcullis's lookups. An answer with a longer TTL allows it for that TTL, up to 7 days.

- While DNS keeps returning an address, it stays allowed, however long the container keeps it without looking it up.
- An address DNS no longer returns stays allowed for the rest of its hold, then is removed. The hold isn't cut short when the name moves: many names return a different subset of a pool at every lookup, so an address missing from one answer may well still be in use, and still the name's.
- When the host's resolver doesn't answer, addresses get one more hold: containers that don't need DNS right then keep working through an outage of up to an hour. When it answers that the name doesn't exist, they run out as usual.
- Connections that are open keep working when their address runs out. Only new connections need it allowed.
- Addresses outlast a restart of Portcullis: the first rule update keeps what the rules left in place have, each for the time it had left. After a reboot, rules put back from the saved copy start without them, as those may be days old.

So a shorter hold removes addresses DNS no longer returns sooner, and a longer one keeps addresses an application holds on to working longer, even when DNS has moved on. Set the hold for every container in the config:

```toml title="/etc/portcullis/config.toml"
hostname-hold = "1h"
```

and for one container with a label:

```yaml
labels:
  - portcullis.egress.api=host:api.example.com,tcp:443
  - portcullis.hostname-hold=10m
```

A hold is seconds (`3600`), or a number with `s`, `m`, `h` or `d` (`90s`, `30m`, `2h`, `1d`), from 10 seconds to 7 days. A container's hold applies to all its `host:` rules, and only to them. An invalid label is reported, and the container gets the hold of the config.

A longer hold is for applications that keep using an address DNS stopped returning, typically one of a pool: an application that resolves once at startup and keeps the address for days needs a hold of days, or an `ip:` rule. Prefer making the application look names up again (nginx: a `resolver` directive and a variable in `proxy_pass`).

## Patterns

A [pattern](/policy/patterns/) such as `host:*.example.org` can't be looked up, so it only allows addresses from DNS answers to the container for names it matches. Portcullis has to see the container's lookups. Of an answer, only the addresses of the name asked for, and of the CNAMEs it resolved through, count.

## What a hostname rule allows

A hostname rule allows the hostname's addresses, not the hostname. Any other service on the same addresses is reachable too, which is common with CDNs and shared hosting: `host:api.example.com` behind a large CDN allows every other site that CDN serves from the same addresses. Portcullis doesn't look at TLS SNI or HTTP Host headers.

When that matters, send the container's traffic through a proxy that filters by name; see [Filtering by hostname with a proxy](/examples/egress-proxy/).

## Which DNS answers count

Portcullis believes a DNS answer that comes from a resolver the container may use and goes to that container. It doesn't check that the container asked the question: the name and addresses are read from the answer, and answers aren't matched to queries. So every resolver the container's [resolver labels](/policy/dns/#resolver-labels) allow is trusted to say where its hostnames are. One that someone else controls can make the container's rule for `api.stripe.com` allow any address, by answering that name with it, whether or not the container asked (see [How DNS gets abused](/policy/domains/#how-dns-gets-abused)). Other containers' rules aren't affected, and [domain labels](/policy/domains/) don't help: the names of `host:` rules are always allowed.

Tools that allow egress by name settle this in one of three ways:

| Approach | Example | What a resolver can still do |
| --- | --- | --- |
| Learn from answers of trusted servers | Calico's domain-based policy learns addresses from DNS responses of the servers listed in `dnsTrustedServers` (the cluster DNS by default). | A trusted server can answer any name with any address. |
| Forward the lookups itself | Cilium's `toFQDNs` rules send a pod's lookups through Cilium's DNS proxy, which learns addresses only from answers to the queries it forwarded for that pod. | Names the pod didn't ask for can't get in, but the upstream resolver is still trusted for the names it was asked. |
| Resolve and connect itself | Istio's sidecar picks the destination of HTTP and TLS traffic by Host header or SNI, and for a `ServiceEntry` with `resolution: DNS` connects to the address Envoy resolved, whatever the application was told. | Nothing, as long as the sidecar's own resolver is right. It needs a proxy in the path of every connection, and plain TCP has no name to go by. |

Portcullis takes the first approach, with the resolvers the container may use as the trusted servers. To keep that list to servers you trust, leave the container on `docker` (the default) with DNS servers you run or choose, and avoid `portcullis.dns.*=*` and `ip:` resolvers you don't control on containers with `host:` rules. For the third approach, put a filtering proxy in front of the container: see [Filtering by hostname with a proxy](/examples/egress-proxy/).
