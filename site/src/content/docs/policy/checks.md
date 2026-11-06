---
title: Configuration checks
description: Container and network configurations that get around the rules, the warnings Portcullis raises for them, and portcullis.ack.
sidebar:
  order: 10
---

Some configurations get a container around its rules without sending a single packet Portcullis could deny. Portcullis looks for them when it starts and whenever a container starts, and reports each as a `warning` event, which raises an [alert](/guides/events-and-alerts/#alerts).

| Warning | When | Why it matters |
| --- | --- | --- |
| `unenforced_network` | A container on an enforced network is also on a network that isn't enforced. | Its traffic through the other network isn't filtered at all. |
| `unused_labels` | A container has `portcullis.*` labels but isn't on an enforced network, for example with `network_mode: host`. | The labels look like a policy, but nothing applies them. |
| `shared_network` | A container uses another container's network (`network_mode: "service:x"` or `container:x`) and either container is restricted. | It shares the other container's addresses and rules; its own labels have no effect. |
| `docker_socket` | A restricted container has the Docker socket mounted. | It can start containers outside the rules, or change its own. |
| `privileged` | A restricted container is privileged. | It can change its network interfaces and get around the rules. |
| `net_admin` | A restricted container has `NET_ADMIN`. | It can change its own interfaces and routes. Portcullis still denies what doesn't match its address and MAC, but this is rarely needed. |
| `ipv6_network` | An enforced network has IPv6 enabled. | Portcullis denies all IPv6 on it, so its containers can't use IPv6. |
| `dns_not_observable` | Portcullis can't see a container's DNS lookups. | Events have no domains, and `host:` patterns and `portcullis.domains` can't work. See [DNS visibility](/policy/dns/#dns-visibility). |

## Acknowledging a warning

When a configuration is intended, acknowledge it with a label, and its warning is no longer reported. Several names are separated by commas:

```yaml title="docker-compose.yml"
services:
  traefik:
    labels:
      - portcullis.ack=docker-socket,dns-not-observable
```

| Name | On |
| --- | --- |
| `unenforced-network` | container |
| `unused-labels` | container |
| `shared-network` | container |
| `docker-socket` | container |
| `privileged` | container |
| `net-admin` | container |
| `dns-not-observable` | container |
| `ipv6-network` | network |

An unknown name is reported as an invalid label. `portcullis.ack` doesn't count as a policy label, so a container that only has `portcullis.ack` doesn't get an `unused_labels` warning.

:::caution
Acknowledging a warning silences it; it doesn't make the configuration safe. A container with the Docker socket can still start a container outside every rule.
:::

## Other warnings

Not every warning is a configuration check. These are reported as `warning` events too, and can't be acknowledged:

| Warning | Meaning |
| --- | --- |
| `invalid_label` | A container label is invalid and was ignored; see [Invalid labels](/policy/overview/#invalid-labels). |
| `invalid_network` | A network can't be enforced, for example because it has no usable IPv4 subnet, or its `portcullis.enable` value is invalid. |
| `events_lost` | The kernel produced log entries faster than Portcullis read them. |
| `alerts_suppressed` | A container raised so many alerts that further ones are held back until the interval ends. |
| `quarantined` | A container misbehaved and was cut off, or would have been with `quarantine = "report"`. |
