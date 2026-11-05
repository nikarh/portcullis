---
title: Pinned resolvers and containers without outside names
description: Common DNS setups with portcullis.dns labels, a shared resolver container with its own policy, and a container that resolves container names only.
sidebar:
  label: Resolvers
  order: 8
---

By default a container may send DNS only to the servers Docker's DNS forwards to for it. The `portcullis.dns.*` labels replace that default. These are the common setups; the labels are described in [DNS](/policy/dns/).

| Goal | Container DNS servers | Labels |
|---|---|---|
| Resolve through the host's DNS only | not set | none needed (add `portcullis.dns.0=host` to also allow direct queries to the host's servers) |
| Only `1.1.1.1` | `dns: [1.1.1.1]` | `portcullis.dns.0=ip:1.1.1.1` |
| The host's DNS and `1.1.1.1` | not set | `portcullis.dns.0=host`, `portcullis.dns.1=ip:1.1.1.1` |
| Any resolver | any | `portcullis.dns.0=*` |
| Container names only, no outside names | `dns:` set to any address | `portcullis.dns.0=none` |

An egress label like `ip:1.1.1.1,udp:53` has no effect: DNS rules are checked first.

## A container with its own resolver

A container that runs a local resolver (a caching `unbound`, or an application with a built-in resolver) and queries a public server directly:

```yaml title="docker-compose.yml"
services:
  crawler:
    image: ghcr.io/acme/crawler:latest
    networks: [backend]
    labels:
      - portcullis.dns.0=docker
      - portcullis.dns.1=ip:9.9.9.9
      - portcullis.egress.web=ip:public,tcp:80,443

networks:
  backend:
    labels:
      - portcullis.enable=true
```

`docker` keeps the default (Docker's DNS can still forward for it), and `ip:9.9.9.9` adds Quad9 for direct queries. Setting any `portcullis.dns.*` label replaces the default, which is why `docker` is listed.

## A shared resolver with a policy

To decide centrally which names containers may resolve, run one resolver container that applies a policy (an allow-list, or a response policy zone), and make it the only resolver everyone may use:

```yaml title="docker-compose.yml"
services:
  resolver:
    image: ghcr.io/acme/unbound-allowlist:latest
    networks:
      backend:
        ipv4_address: 172.31.0.53
    labels:
      - portcullis.icc.mode=deny
      - portcullis.dns.0=ip:9.9.9.9

  app:
    image: ghcr.io/acme/app:latest
    dns: [172.31.0.53]
    networks: [backend]
    labels:
      - portcullis.dns.0=none
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.resolver=container:resolver,udp:53,tcp:53

networks:
  backend:
    labels:
      - portcullis.enable=true
    ipam:
      config:
        - subnet: 172.31.0.0/24
```

`app` has its own DNS server, so Docker's DNS forwards its outside lookups from its address to `172.31.0.53`. The resolver is on the same network, so that is traffic between containers: the ICC rules decide it, not the DNS labels, which only cover DNS leaving the network. `container:resolver,udp:53,tcp:53` allows it. `portcullis.dns.0=none` denies DNS to any resolver outside the network. Container names still resolve through Docker's DNS.

The resolver may only query Quad9 upstream, and opens no connections to other containers. It still answers queries, since replies are always allowed.

For per-container name lists without running a resolver, use [`portcullis.domains`](/policy/domains/) instead.

## Container names only

A worker that only talks to other containers and never needs an outside name:

```yaml title="docker-compose.yml"
services:
  worker:
    image: ghcr.io/acme/worker:latest
    dns: [192.0.2.1]
    networks: [backend]
    labels:
      - portcullis.dns.0=none
```

Docker's DNS answers container and service names itself, inside the container, so they always resolve. Outside names are forwarded to the container's DNS server from its address, and `none` denies that. The address in `dns:` doesn't matter; it only makes Docker forward from the container rather than from the host.

Without a `dns:` setting on the container or daemon-wide, Docker 29 resolves outside names from the host, where no label applies. That's why the table above has `dns:` set for this case.
