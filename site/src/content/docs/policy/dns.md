---
title: DNS
description: How containers resolve names through Docker, portcullis.dns labels for resolvers, common setups, and what DNS rules can and can't control.
sidebar:
  order: 7
---

## How containers resolve names

Containers normally resolve names through Docker's DNS server (`127.0.0.11`). It runs inside the container's network namespace, answers container and service names itself, and forwards everything else:

1. If the container has its own DNS servers (`docker run --dns`, Compose `dns:`), Docker forwards to them from the container's address. These queries go through the container's policy.
2. Otherwise, if `dns` is set in Docker's `/etc/docker/daemon.json`, Docker forwards to those servers, also from the container's address.
3. Otherwise Docker forwards to the host's DNS servers from the host itself (Docker 29; older versions forwarded from the container's address). Portcullis can't see these queries, so such a container can always resolve outside names through Docker's DNS.

Docker's DNS server itself is never filtered: it runs inside the container.

## Resolver labels

Besides that, any DNS query a container sends itself (port 53, UDP and TCP) is denied unless its destination is allowed with:

```text
portcullis.dns.<name>=<target>
```

| Target | Allows DNS to |
| --- | --- |
| `docker` | the servers Docker's DNS forwards to for this container: its own DNS servers if it has any, otherwise the daemon-wide ones, otherwise the host's. The default when no `portcullis.dns.*` label is set. |
| `host` | the host's DNS servers |
| `ip:<address>` | that resolver, for example `ip:1.1.1.1` |
| `*` | any resolver |
| `none` | nothing |

Setting any `portcullis.dns.*` label replaces the default, so list `docker` too if you still want it. Invalid `portcullis.dns.*` labels leave the container with no DNS, rather than the default.

The host's DNS servers are the `nameserver` entries of the host's `/etc/resolv.conf`, or of `/run/systemd/resolve/resolv.conf` when the former only points at systemd-resolved's local stub. Loopback addresses are left out. They are read again on every rule update.

DNS rules are checked before egress rules, so an egress label like `ip:1.1.1.1,udp:53` has no effect; use `portcullis.dns.x=ip:1.1.1.1` instead. DNS rules cover DNS leaving the container's network; a resolver running in a container on the same network is reached under the [ICC rules](/policy/icc/).

## Common setups

| Goal | Container DNS servers | Labels |
| --- | --- | --- |
| Resolve through the host's DNS only | not set | none needed (add `portcullis.dns.0=host` to also allow direct queries to the host's servers) |
| Only `1.1.1.1` | `dns: [1.1.1.1]` | `portcullis.dns.0=ip:1.1.1.1` |
| The host's DNS and `1.1.1.1` | not set | `portcullis.dns.0=host`, `portcullis.dns.1=ip:1.1.1.1` |
| Any resolver | any | `portcullis.dns.0=*` |
| Container names only, no outside names | `dns:` set to any address | `portcullis.dns.0=none` |

A container running its own resolver against a public DNS server:

```yaml
labels:
  - portcullis.dns.0=docker
  - portcullis.dns.1=ip:9.9.9.9
```

More in [Own resolver](/examples/own-resolver/).

## DNS visibility

Portcullis can only see a container's lookups when Docker forwards them from the container's address, which means when the container has its own DNS servers or `dns` is set daemon-wide. Seeing them gives events their domains and lets [hostname rules](/policy/hostnames/) follow exactly what the container was told. The simplest setup is once per host, using the resolver from the host's `resolv.conf` or any other:

```json title="/etc/docker/daemon.json"
{ "dns": ["192.168.1.1"] }
```

Then restart Docker. For containers without it, Portcullis reports a `dns_not_observable` warning when they start. Acknowledge it with `portcullis.ack=dns-not-observable` on a container where that's intended.

## What can and can't be controlled

DNS labels control:

- which resolvers a container may query directly: the host's, specific addresses, any, or none;
- which resolvers Docker's DNS may forward to, for a container with its own DNS servers (`dns:`).

On their own, they can't control:

- Which names are looked up. Rules allow or deny resolvers by address, not by name: a container that may use a resolver can resolve any name through it. [Limiting the names a container can look up](/policy/domains/) closes this, and the next two items.
- What a container sends to port 53. The DNS labels allow traffic to that port, whether or not it is DNS. With `portcullis.dns.x=*`, a container can reach port 53 of any address on the internet, which works as a tunnel to anywhere.
- What a resolver answers. A container that may use a resolver someone else controls (or `*`) can be told any address for any name, and its `host:` rules then allow that address. Only other containers' rules are safe from it.
- Lookups Docker's DNS forwards from the host, for a container with neither its own DNS servers nor daemon-wide ones (Docker 29). No container policy applies there, so such a container can always resolve outside names. To restrict name resolution, set `dns` daemon-wide or on the container, and allow only those servers.
- Names of other containers and services. Docker's DNS answers them inside the container, so they always resolve.
- DNS over TLS or HTTPS. That's ordinary traffic on ports 853 and 443, controlled by egress labels, not DNS labels.
