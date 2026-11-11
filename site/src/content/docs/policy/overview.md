---
title: Overview
description: Every Portcullis label on one page, how a packet is decided, and how invalid labels are handled.
sidebar:
  order: 1
---

A policy is a set of Docker labels. Networks get one label that turns Portcullis on; containers get labels that open things up. All labels start with `portcullis.`.

## All labels

| Label | On | Value | Default |
| --- | --- | --- | --- |
| [`portcullis.enable`](/policy/networks/) | network | `true`, `monitor`, `false` | not enforced |
| [`portcullis.egress.<name>`](/policy/egress/) | container | `<destination>,<service>[,<service>...]` | nothing allowed |
| [`portcullis.icc.mode`](/policy/icc/) | container | `allow`, `deny`, `allow-listed` | `allow` |
| [`portcullis.icc.allow.<name>`](/policy/icc/#allow-listed) | container | `container:<target>,<service>...` or `multicast:<group>,<service>...` | none |
| [`portcullis.dns.<name>`](/policy/dns/) | container | `docker`, `host`, `ip:<address>`, `*`, `none` | `docker` |
| [`portcullis.domains.<name>`](/policy/domains/) | container | `<domain>[,<domain>...]` | any name |
| [`portcullis.limit.connections`](/policy/limits/#connection-limits) | container | `<n>` or `none` | `connection-limit` setting (16384) |
| [`portcullis.limit.new-connections`](/policy/limits/#connection-limits) | container | `<n>` per second | no limit |
| [`portcullis.quarantine`](/policy/limits/#quarantine) | container | `on`, `off` | `on` |
| [`portcullis.hostname-hold`](/policy/hostnames/#how-long-an-address-stays-allowed) | container | a duration: `600`, `30m`, `2h`, `1d` | `hostname-hold` setting (1h) |
| [`portcullis.ack`](/policy/checks/#acknowledging-a-warning) | container, network | warning names, comma separated | none |
| [`portcullis.policy-file`](/policy/files/) | container | the name of a file with more of these labels | none |

`<name>` in a label key is any string that makes the key unique, such as `0`, `1` or `stripe`. It has no meaning beyond that, and shows up in nothing but the label itself.

Services, used by egress and ICC labels:

| Service | Allows |
| --- | --- |
| `tcp:443` | TCP to that port |
| `tcp:8000-8100` | TCP to any port of the range, both ends included |
| `tcp:80,443,8000-8100` | several ports and ranges: those after a protocol's first belong to it |
| `tcp:*` | TCP to any port |
| `udp:...`, `sctp:...` | the same for UDP and SCTP |
| `icmp`, `igmp`, `gre`, `esp`, `ah` | that protocol, which has no ports |
| `*` | anything |

## How a packet is decided

For a container on an enforced network, Portcullis decides the first packet of every connection it opens, in this order:

1. Quarantine. A [quarantined](/policy/limits/#quarantine) container sends nothing; its frames are dropped before anything else is looked at.
2. Source. The frame has to come from a managed container's own port on the bridge, with that container's MAC and IPv4 address. Anything else is denied (reason `source`), and so are IPv6, VLAN-tagged and other frames enforced networks don't carry (reason `frame`). See [Containers trying to get around the rules](/internals/bypass/).
3. Limits. A container over its [connection limits](/policy/limits/#connection-limits) is denied (reason `limit`).
4. DNS. Traffic to port 53 leaving the network is decided by the [DNS labels](/policy/dns/) alone (reason `dns`). For containers with [`portcullis.domains`](/policy/domains/) labels, the query's names are checked too.
5. Containers on the same network. Decided by the [ICC mode](/policy/icc/) alone (reason `icc`).
6. Everything else, the Docker host included. Decided by the [egress labels](/policy/egress/) (reason `egress`).

The first rule that applies decides. An egress label never allows DNS or traffic to containers on the same network, not even `ip:*,*`.

What a policy allows still goes through Docker's own rules afterwards. Replies, and the rest of an allowed connection, always pass.

## Where labels go

Container labels are set in Compose under the service, or with `docker run --label`:

```yaml title="docker-compose.yml"
services:
  api:
    image: ghcr.io/acme/api:latest
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432
```

The map form works too:

```yaml
    labels:
      portcullis.egress.stripe: host:api.stripe.com,tcp:443
```

:::note
Docker sets labels when it creates a container or network, and they can't be changed afterwards. A changed policy takes recreating the container (`docker compose up -d` does when labels change), and a changed `portcullis.enable` takes recreating the network.
:::

Labels that shouldn't be visible in Docker's metadata, such as the address of a VPN endpoint, can be kept in a [policy file](/policy/files/) on the Docker host instead.

A container's policy applies to every enforced network it is on. A container on no enforced network isn't restricted, whatever its labels say; Portcullis warns about that with [`unused_labels`](/policy/checks/).

## Invalid labels

Invalid labels are reported with an `invalid_label` warning and ignored; the container's other labels still apply. Ignoring a label never opens anything up:

- an invalid `portcullis.icc.mode` counts as `deny`;
- invalid `portcullis.dns.*` labels leave the container with no DNS, instead of the default;
- an invalid `portcullis.domains.*` label still limits the container's lookups, to the names of its valid ones;
- an invalid `portcullis.enable` value on a network enforces it;
- a [policy file](/policy/files/#when-the-file-cant-be-used) that can't be used denies the container everything.

Label keys Portcullis doesn't know are ignored without a warning, so check the spelling of keys: `portcullis.egres.0` does nothing.
