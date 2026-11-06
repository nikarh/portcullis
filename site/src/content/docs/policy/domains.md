---
title: Limiting lookups
description: How DNS is used to get data out of a container that may connect nowhere, and portcullis.domains labels that close it.
sidebar:
  order: 8
---

## How DNS gets abused

A container may only connect where its labels allow, yet looking up a name works everywhere: the resolver it may use asks whoever is in charge of that name, on its behalf. That makes DNS a way out for a compromised container, even with no egress labels at all:

- Sending data out. Someone registers `evil.example` and runs its DNS server. The container looks up `c2VjcmV0cw.0.evil.example`, `cGFzc3dvcmQ.1.evil.example` and so on: each name carries a few dozen bytes of whatever it wants to leak, encoded. The resolver dutifully asks the server of `evil.example`, which writes the names down. Nothing ever connects to `evil.example`, so no egress rule is involved.
- Receiving commands. The answers come back: a `TXT` record holds text of the server's choosing, an `A` record four bytes. Tools such as `iodine` and `dnscat2` build a two-way tunnel, and with it a shell, out of nothing but lookups.
- Tunnelling through port 53. With `portcullis.dns.x=*`, the container doesn't even need DNS: any server on the internet listening on port 53 is reachable, whatever is sent to it.
- Steering `host:` rules. A resolver the container may use and someone else controls can answer `api.stripe.com` with any address, and the container's `host:` rule for `api.stripe.com` then allows that address. The container doesn't even have to ask for `api.stripe.com`: Portcullis reads the name from the answer and doesn't match answers to queries, so an answer about it to any lookup the container made of that resolver will do.

Every packet of this follows the network policy: the container only talks to a resolver it may use, on port 53. That's why only the names can tell it apart.

Without `portcullis.domains` labels, a compromised container can use DNS like this, to anyone it wants, through any resolver it may use. That is the default, as it is without Portcullis.

## Domain labels

A container with `portcullis.domains` labels may only look up the names they list:

```text
portcullis.domains.<name>=<domain>[,<domain>...]
```

A domain is a name (`api.stripe.com`) or a [pattern](/policy/patterns/): `*.stripe.com` allows `api.stripe.com`, `**.stripe.com` also `a.b.stripe.com`, and neither allows `stripe.com`. Names and patterns of the container's `host:` rules are always allowed too, so they don't have to be listed twice.

```yaml title="docker-compose.yml"
labels:
  - portcullis.egress.stripe=host:api.stripe.com,tcp:443
  - portcullis.domains.github=**.github.com,github.com
```

Here the container may look up `api.stripe.com` (from its `host:` rule), `github.com` and any name under it, and nothing else. It may connect only to `api.stripe.com`; the GitHub names resolve, but connections to them are denied unless an egress label allows them.

Lookups of any other name fail at once (Docker's DNS answers `SERVFAIL`), and are reported as denied `dns` events naming the query. So is anything sent to port 53 that isn't a DNS query.

Any `portcullis.domains` label turns the limit on, even an invalid one: a typo allows fewer names, never all of them.

## How it works

The firewall holds each DNS query of such a container until Portcullis has read the names it asks for. An allowed query continues to the resolver unchanged, and the resolver rules still apply to it; Portcullis never answers or changes queries. This closes all of [How DNS gets abused](#how-dns-gets-abused) for names outside the list, since a server for those names never hears from the container.

## Costs and requirements

- Every lookup of the container waits for a round trip through Portcullis, a small delay next to the lookup itself. Containers without the labels aren't affected at all.
- While Portcullis isn't running, the container's lookups fail, rather than go unchecked.
- The list has to be complete. Applications look up more names than one might think: other services they call, CDNs behind them (`*.cloudfront.net`), telemetry, update checks, and the host's search domains (a lookup of `api` may first be tried as `api.corp.example`). Run with the labels on a network in monitor mode first: queries outside the list are reported as `would_deny`, and nothing fails.
- It only sees lookups that leave the container's network: Docker's DNS has to forward them from the container's address (see [DNS visibility](/policy/dns/#dns-visibility)). Without a `dns` setting daemon-wide or on the container, Docker 29 resolves outside names from the host, where no limit applies.
- It can't help with names you allow. A compromised container can still send data through lookups of names whose servers are controlled by someone else, such as a domain anyone can create records under. List exact names rather than wide patterns where you can.
- A DNS message over TCP split across segments can't be read, and is denied.
- Container and service names are answered by Docker's DNS inside the container, so they always resolve and don't need listing.
