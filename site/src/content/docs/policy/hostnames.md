---
title: Hostname rules
description: "How host: rules turn names into addresses, how long addresses stay allowed, and how the names connections ask for are checked."
sidebar:
  order: 5
---

A `host:` rule allows connections to the addresses its hostname resolves to. A connection that names the server it wants (TLS, HTTP, QUIC) must also name the rule's hostname; see [Names connections ask for](#names-connections-ask-for). Portcullis learns the addresses in two ways.

## From the container's DNS answers

Portcullis inspects DNS answers to managed containers. The firewall holds each answer until Portcullis has added its addresses to the matching `host:` rules of the container that received it (a CNAME the name resolved through also counts), then releases it unchanged. The container can connect to exactly the addresses it was told, including ones that change with every lookup (CDNs, DNS load balancing).

- Queries still go to the resolver the container uses. Portcullis never answers or changes them.
- An answer only counts for the container that received it. A container that may ask a resolver of its choice can't make another container's `host:` rules allow whatever that resolver claims.
- At most 4096 addresses per hostname are kept at a time.
- If Portcullis isn't running or falls behind, answers go through uninspected rather than being lost, so DNS keeps working. Addresses in them are then missing from `host:` rules until a later lookup.
- DNS answers over TCP that span more than one packet aren't inspected; they still reach the container.

This needs Docker to forward the container's lookups from its own address; see [DNS visibility](/policy/dns/#dns-visibility).

## From Portcullis's own lookups

Portcullis also resolves every hostname of a `host:` rule itself, through the host's resolver: right after the rule update that first needs it, then again four times per [hold](#how-long-an-address-stays-allowed) (every 15 minutes with the default hold of an hour). What a lookup returns is allowed for every container with a rule for the name, right away.

A rule update never waits for a lookup, which can take seconds: a container that starts with a rule for a name no other rule has gets its rules at once, and the name's addresses a moment later, usually within milliseconds: first lookups are made each on their own, and don't wait for lookups of other names, such as names whose resolver doesn't answer. Until then, the rule allows what DNS answers to the container say. A container whose lookups Portcullis sees has its answer held until the addresses in it are allowed, so it doesn't notice. What lookups returned outlasts the rules that needed it for as long as it stays allowed, so a container recreated with the same rules gets it at once.

That covers what the container's own answers can't:

- Applications that resolve a name once and keep the address, such as nginx with a hostname in `proxy_pass`, or a connection pool. Without lookups of its own, Portcullis would stop allowing the address an hour after the container's lookup, while the application still uses it.
- Containers whose lookups Portcullis can't see, such as those using DNS over HTTPS or TLS.
- Containers that looked the name up before Portcullis started.

When the resolver doesn't answer, Portcullis tries again every 30 seconds. When it answers that the name doesn't exist, Portcullis asks again at the usual pace: the name may only exist for the resolver the container uses. Until a name has addresses, its rules allow nothing; everything else is applied as usual. The [`applied` event](/reference/events/#applied) lists such names as `unresolved_hosts` once a lookup of them failed, and a new `applied` event follows as soon as one resolves.

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

## Names connections ask for

Many sites share an address: a CDN, shared hosting, or a reverse proxy serves them all from the same addresses and tells them apart by the name the client asks for. Allowing the addresses of `api.example.com` alone would allow every other site there. So Portcullis reads the name a connection through a `host:` rule asks for, and allows it only when the name is one of the container's `host:` names for that port, and that name's addresses include the destination. Other names on the same address are denied, with the name they asked for on the [event](/reference/events/#connection) (`name`).

```yaml
labels:
  - portcullis.egress.stripe=host:api.stripe.com,tcp:443
```

With that label, a connection to an address of `api.stripe.com` that asks for `api.stripe.com` is allowed. One to the same address that asks for any other site behind the same CDN is denied.

What is checked by name, and what by address:

| The client sends | Checked |
| --- | --- |
| A TLS ClientHello with a server name (SNI), on any port; after a Postgres request for TLS too | By name: the server name |
| An HTTP/1 request | By name: the `Host` of every request on the connection, the first and those that follow on a keep-alive connection; the URI too, for a request with a full URI |
| An HTTP `Upgrade` (WebSocket) or `CONNECT` request | By name, that request: after it, the connection is a tunnel that names nothing more |
| QUIC (HTTP/3): Initial packets with a ClientHello | By name: the server name, read from the first Initial packets of the flow, however many the ClientHello spans |
| TLS without a server name (a client connecting to an address, not a name) | By address |
| Anything else: SSH, SMTP, plain Postgres, a server that speaks first, HTTP/2 without TLS, UDP other than QUIC | By address |
| ICMP and other protocols without ports | By address |

By address means as any `ip:` rule: allowed when the destination is one of the name's addresses. That leaves protocols that name nothing working, and keeps the check from guessing at them.

Some things are denied because what they name can't be told:

- A ClientHello, request head or QUIC ClientHello that doesn't arrive whole within 3 seconds, or is over 64 KiB (16 KiB for a request head). Its first bytes could be the start of a name for another site.
- TLS and HTTP that servers could read differently: two server names, a repeated TLS extension, more than one `Host`, a body with both `Content-Length` and `Transfer-Encoding`, folded header lines, lines that end with a bare line feed. The [Limitations](/limits/limitations/#names) list the rest.
- A ClientHello with Encrypted Client Hello (ECH): the name it shows is the provider's (such as `cloudflare-ech.com`), not the site's, and is checked like any other. Browsers use ECH for sites that publish it in DNS; most other clients don't.

### Strict name checks

Connections that don't name a server are allowed by address, which also allows every service on those addresses that is reached that way: SSH to a shared address, or TLS without a server name to a CDN's default site. Where that matters, check names strictly: only TLS and QUIC with a matching server name, and HTTP with a matching `Host`, get through; everything else to the rule's addresses is denied.

For one rule, add `strict` after its services:

```yaml
labels:
  - portcullis.egress.stripe=host:api.stripe.com,tcp:443,strict
```

For every `host:` rule of a container, with a label:

```yaml
labels:
  - portcullis.name-checks=strict
```

For every container, in the config (`--name-checks`):

```toml title="/etc/portcullis/config.toml"
name-checks = "strict"
```

A rule's `strict` wins over the others, and a container's label over the config; `portcullis.name-checks=lenient` turns it off for a container. An invalid label value counts as `strict`. The default is `lenient`.

### How it works

Portcullis gets the first packets of each such connection. The TCP handshake goes through, and the client's first bytes are held until the ClientHello or request head is whole (it often takes more than one packet), then let through or denied. A denied TCP connection gets a reset. Once a TLS server has the whole ClientHello, the rest of the connection passes in the kernel like any other; so does a connection allowed by address, after its first data, and a QUIC flow, after its ClientHello. A plain HTTP connection names a server in every request, so the packets its client sends with data keep going through Portcullis for as long as connection tracking keeps the connection, however long it idles between requests. See [Name checks](/internals/how-it-works/#name-checks).

### In monitor mode

On networks in monitor mode, nothing is held or denied: Portcullis reads copies of the packets and reports connections it would deny as `would_deny`, with the name. [`portcullis audit`](/reference/cli/) lists them.

### What the check doesn't see

The name is checked where the client sends it in the clear. What follows is up to the client and the server:

- Inside TLS, an HTTP request can ask for another site on the same server than its server name said ("domain fronting"). Most large CDNs refuse that now; some servers don't. Seeing it takes decrypting the traffic.
- HTTP/2 clients reuse a connection for other sites whose names the server's certificate covers ("connection coalescing"), without a new ClientHello.
- A QUIC flow's later packets aren't read: a client could start a second QUIC connection on the same UDP flow, with another name.
- A site that is allowed can still be used for anything it offers, such as an account of someone else's on the same service.

For control over those, put a filtering proxy in front of the container; see [Filtering by hostname with a proxy](/examples/egress-proxy/).

### Compared with other tools

- Cilium's `toFQDNs` rules allow the addresses DNS answers gave, as `host:` rules do, without looking at what connections ask for: every site on those addresses is allowed. Checking names takes its L7 policies on top, `serverNames` for TLS and HTTP rules, which send the traffic through an Envoy proxy and only apply where a rule asks for them. A rule with `serverNames` denies TLS without a server name.
- Istio's sidecar routes HTTP and TLS by `Host` and server name to the services it knows of, and treats other TCP as opaque, by address and port.
- Portcullis checks the names of TLS, HTTP and QUIC on every `host:` rule, in the kernel's path with a queue for the first packets rather than a proxy, and allows what names nothing by address unless names are checked strictly.

## Which DNS answers count

Portcullis believes a DNS answer that comes from a resolver the container may use and goes to that container. It doesn't check that the container asked the question: the name and addresses are read from the answer, and answers aren't matched to queries. So every resolver the container's [resolver labels](/policy/dns/#resolver-labels) allow is trusted to say where its hostnames are. One that someone else controls can make the container's rule for `api.stripe.com` allow any address, by answering that name with it, whether or not the container asked (see [How DNS gets abused](/policy/domains/#how-dns-gets-abused)). Other containers' rules aren't affected, and [domain labels](/policy/domains/) don't help: the names of `host:` rules are always allowed.

Tools that allow egress by name settle this in one of three ways:

| Approach | Example | What a resolver can still do |
| --- | --- | --- |
| Learn from answers of trusted servers | Calico's domain-based policy learns addresses from DNS responses of the servers listed in `dnsTrustedServers` (the cluster DNS by default). | A trusted server can answer any name with any address. |
| Forward the lookups itself | Cilium's `toFQDNs` rules send a pod's lookups through Cilium's DNS proxy, which learns addresses only from answers to the queries it forwarded for that pod. | Names the pod didn't ask for can't get in, but the upstream resolver is still trusted for the names it was asked. |
| Resolve and connect itself | Istio's sidecar picks the destination of HTTP and TLS traffic by Host header or SNI, and for a `ServiceEntry` with `resolution: DNS` connects to the address Envoy resolved, whatever the application was told. | Nothing, as long as the sidecar's own resolver is right. It needs a proxy in the path of every connection, and plain TCP has no name to go by. |

Portcullis takes the first approach, with the resolvers the container may use as the trusted servers. To keep that list to servers you trust, leave the container on `docker` (the default) with DNS servers you run or choose, and avoid `portcullis.dns.*=*` and `ip:` resolvers you don't control on containers with `host:` rules. For the third approach, put a filtering proxy in front of the container: see [Filtering by hostname with a proxy](/examples/egress-proxy/).
