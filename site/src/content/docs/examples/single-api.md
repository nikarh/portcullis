---
title: A service that calls one API
description: Limit a service to one external HTTPS API, and optionally to the names it may look up.
sidebar:
  label: One external API
  order: 1
---

A billing service talks to Stripe and to nothing else. It needs no other container on its network, no other address on the internet, and no services on the Docker host.

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

## What each label does

`portcullis.enable=true` on the network enforces it. Every container on `backend` loses outbound access, whether it has labels or not. A container without labels can still reach other containers on the network and resolve names through Docker's DNS.

`portcullis.egress.stripe=host:api.stripe.com,tcp:443` allows TCP 443 to the addresses `api.stripe.com` resolves to. `stripe` only makes the label key unique. Portcullis learns the addresses from the DNS answers the container receives, and resolves the name itself when it has none yet. See [Hostname rules](/policy/hostnames/).

Traffic to other containers on `backend` is still allowed, since the default ICC mode is `allow`. Add `portcullis.icc.mode=deny` if the service never opens connections to its neighbours.

## Limiting the names it can look up

The egress label limits where the container connects, not what it resolves. A compromised container can still send data out through DNS lookups of names its resolver forwards to someone else's server (see [How DNS gets abused](/policy/domains/#how-dns-gets-abused)). To close that, list the names it may look up:

```yaml title="docker-compose.yml"
services:
  billing:
    image: ghcr.io/acme/billing:latest
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443
      - portcullis.icc.mode=deny
      # Names of host: rules are always allowed; list anything else it resolves.
      - portcullis.domains.telemetry=telemetry.acme.io
```

Lookups of any other name fail at once with `SERVFAIL`, and are reported as denied `dns` events with the query. Run it on a network with `portcullis.enable=monitor` first: names outside the list are then reported as `would_deny` and nothing fails. Applications often look up more names than expected.

## Make the lookups visible

Portcullis only sees a container's lookups when Docker forwards them from the container's address. Without a `dns` setting, Docker 29 resolves outside names from the host, where neither `host:` rules can follow the answers nor `portcullis.domains` labels apply. Set it once per host in `/etc/docker/daemon.json` and restart Docker:

```json title="/etc/docker/daemon.json"
{ "dns": ["192.168.1.1"] }
```

Containers without it get a `dns_not_observable` warning when they start. See [DNS visibility](/policy/dns/#dns-visibility).

## What this doesn't cover

- A `host:` rule allows the hostname's addresses. Any other service on the same addresses is reachable too, which is common behind CDNs. For hostname-precise filtering, see [Egress through a filtering proxy](/examples/egress-proxy/).
- Inbound connections. Replies to connections made to the container are always allowed; egress labels only limit what it opens.
