---
title: Introduction
description: What Portcullis does, the problem it solves, and the model behind its policies.
sidebar:
  order: 1
---

Portcullis limits what Docker containers can connect to, using labels on your networks and containers. It is a daemon that runs on the Docker host, turns those labels into nftables rules, and keeps the rules up to date as containers come and go.

## Why

By default a container can open connections to any address on the internet and to every other container on its network. That is convenient until one of them is compromised or misbehaves, and then nothing stops it from talking to whatever it wants. Docker has no built-in way to say "this service may only reach `api.stripe.com` on port 443 and the database on 5432".

Portcullis adds that. You mark a network as enforced, every container on it loses outbound access by default, and each container gets back the destinations its labels list. The policy lives next to the service definition in your Compose file, so it is reviewed and versioned with everything else:

```yaml title="docker-compose.yml"
services:
  billing:
    image: ghcr.io/acme/billing:latest
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443

networks:
  backend:
    labels:
      - portcullis.enable=true
```

Before enforcing anything, Portcullis can run in monitor mode and report every connection a policy would deny, so the labels can be written from what the services actually do.

## The model

- Nothing changes until a network has the `portcullis.enable` label. Containers on other networks are left alone.
- On an enforced network, a container without labels can talk to the other containers on the network and resolve names through Docker's DNS, and nothing else.
- Each label opens something up: a destination outside (`portcullis.egress.*`), a resolver (`portcullis.dns.*`), or narrows down which containers it may reach (`portcullis.icc.*`). See the [label overview](/policy/overview/).
- Portcullis only removes access. Traffic a policy allows still goes through Docker's own rules afterwards, so things Docker blocks (internal networks, isolation between networks) stay blocked.
- Rules decide new connections. Replies, and the rest of an allowed connection, always pass.
- Every decision can be reported as an [event](/reference/events/), with the container, the destination and, where Portcullis can tell, the domain.

Portcullis assumes a container may be compromised and actively try to get past its rules: a container can't borrow another's address or MAC, smuggle traffic in IPv6 or VLAN frames, or widen another container's hostname rules. See [Containers trying to get around the rules](/internals/bypass/).

## What it isn't

- It isn't an inbound firewall. Labels limit the connections a container opens; who may connect to a container's published ports is up to Docker and your host firewall.
- It doesn't look inside traffic. A `host:` rule allows the addresses a name resolves to, not the name; there is no TLS SNI or URL filtering. [Limits and workarounds](/limits/escape-hatches/) shows how to add that with a proxy.
- It doesn't do IPv6, and only works on bridge networks. See [Limitations](/limits/limitations/).

## Where to go next

- [Quick start](/start/quick-start/): install it, watch a network in monitor mode, write labels from what you see, and enforce them.
- [Installation](/start/installation/): packages, repositories, signatures, and building from source.
- [Policy labels](/policy/overview/): every label, what it takes, and how labels combine.
- [How it works](/internals/how-it-works/): the nftables tables, the packet hold, and DNS inspection.
