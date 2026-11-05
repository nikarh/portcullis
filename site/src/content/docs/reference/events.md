---
title: Events
description: The JSON schema of every event Portcullis writes, with examples and the text format.
sidebar:
  order: 3
---

Portcullis writes one event per line to stdout, as text or, with `log-format = "json"`, as JSON. The events socket serves the same events, always as JSON. Where events go and how much is written is in [Events and alerts](/guides/events-and-alerts/).

Every JSON event has two common fields, followed by those of its kind:

| Field | Type | Meaning |
| --- | --- | --- |
| `time` | string | RFC 3339 UTC timestamp with milliseconds, such as `2026-11-02T10:15:30.120Z` |
| `event` | string | `connection`, `dns`, `container`, `warning`, `applied` or `apply_failed` |

Fields that don't apply are `null`, except `mid_stream`, which is left out unless it is `true`. Consumers should ignore fields they don't know: new ones may be added.

## `connection`

A decision about a packet: <span class="v-allowed">allowed</span>, <span class="v-denied">denied</span>, or <span class="v-would">would_deny</span> in monitor mode.

```json
{"time":"2026-11-02T10:15:30.120Z","event":"connection","verdict":"denied","reason":"egress",
 "container":"billing","network":"backend","protocol":"tcp",
 "source":"172.18.0.2","source_port":40312,"destination":"104.18.3.4","destination_port":443,
 "destination_container":null,"domain":"api.stripe.com","domain_source":"dns",
 "query":null,"detail":null}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `verdict` | string | `allowed`, `denied`, or `would_deny` in monitor mode |
| `reason` | string | Which part of the policy decided, see below |
| `container` | string or null | The container that sent it. For `source` and `frame`, the container behind the bridge port the frame came in on, whatever address or MAC it used. |
| `network` | string or null | The network it was sent on |
| `protocol` | string | `tcp`, `udp`, `sctp`, `icmp`, `igmp`, `gre`, `esp`, `ah`, or the number of another IP protocol; for `source` and `frame`, also `arp`, `ipv6` or `ether type 0x....` |
| `source`, `destination` | string or null | The addresses the packet claims. For egress, the destination the container asked for, before Docker's DNAT of published ports. Both are `null` for frames without IP addresses. |
| `source_port`, `destination_port` | number or null | Ports, for protocols that have them |
| `destination_container` | string or null | For `icc`, the container at the destination |
| `domain` | string or null | The destination's name, if known |
| `domain_source` | string or null | `dns` when the container looked the name up and Portcullis saw the answer, `rule` when the address belongs to one of the container's `host:` rules |
| `query` | string or null | For denied DNS queries, the name asked for |
| `detail` | string or null | For `source`, what's wrong, such as which container's address was used |
| `mid_stream` | `true`, or absent | A TCP packet that doesn't start a connection: a reply, or the rest of a connection the firewall doesn't track, because it lost track of it or the packet doesn't fit the connection. Rules decide new connections; what they say about such a packet doesn't mean a label is missing. |

Reasons:

| Reason | Decided by |
| --- | --- |
| `egress` | [Egress labels](/policy/egress/): traffic leaving the network or to the Docker host |
| `dns` | [DNS labels](/policy/dns/) and [domain labels](/policy/domains/): traffic to port 53 |
| `icc` | The [ICC mode](/policy/icc/): traffic to a container on the same network |
| `source` | [Source checks](/internals/bypass/): a container sending with an address or MAC that isn't its own, ARP included |
| `frame` | Source checks: a kind of frame enforced networks don't carry, such as IPv6 or VLAN-tagged frames |
| `limit` | [Connection limits](/policy/limits/#connection-limits) |

A flow (container, destination, protocol and port) is reported at most once a minute. Replies and the rest of a connection are never reported.

## `dns`

A container received a DNS answer. Reported where allowed connections are (`log-allowed`).

```json
{"time":"2026-11-02T10:15:30.101Z","event":"dns","container":"billing","network":"backend",
 "resolver":"192.168.1.1","name":"api.stripe.com","record_type":"A","response_code":"No Error",
 "aliases":[],"answers":["104.18.3.4","104.18.2.4"]}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `container`, `network` | string or null | The container that received the answer, and its network |
| `resolver` | string | The resolver that answered |
| `name` | string | The name asked for |
| `record_type` | string | `A`, `AAAA`, `CNAME`, `TXT` and so on |
| `response_code` | string | `No Error`, `Non-Existent Domain`, `Server Failure` and so on |
| `aliases` | array of strings | CNAME targets the name resolved through |
| `answers` | array of strings | The addresses in the answer |

Denied lookups aren't `dns` events: they are `connection` events with reason `dns`, and `query` names what was asked.

## `container`

A container address became managed or stopped being managed.

```json
{"time":"2026-11-02T10:15:29.870Z","event":"container","action":"managed","container":"billing",
 "network":"backend","address":"172.18.0.2","mode":"enforce"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `action` | string | `managed`: rules now apply to this address. `released`: they no longer do. |
| `container`, `network`, `address` | string | The container, the network and its address there |
| `mode` | string | `enforce` or `monitor` |

## `warning`

Something that needs attention. Every warning raises an alert.

```json
{"time":"2026-11-02T10:15:29.902Z","event":"warning","kind":"docker_socket","container":"traefik",
 "message":"..."}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `kind` | string | The warning, see below |
| `container` | string or null | The container it is about, if any |
| `message` | string | A description for people; its wording may change between versions |

| Kind | Meaning |
| --- | --- |
| `invalid_label` | A container label is invalid and was ignored |
| `invalid_network` | A network's configuration prevents enforcing it |
| `dns_not_observable` | Portcullis can't see this container's DNS lookups |
| `events_lost` | The kernel dropped log entries because they weren't read fast enough |
| `alerts_suppressed` | A container raised so many alerts that further ones are held back for a while |
| `unenforced_network`, `unused_labels`, `shared_network`, `docker_socket`, `privileged`, `net_admin`, `ipv6_network` | [Configuration checks](/policy/checks/) |
| `quarantined` | A container misbehaved and was cut off from its networks, or would have been |

## `applied`

Rules were updated. It comes after everything else the update caused.

```json
{"time":"2026-11-02T10:15:29.912Z","event":"applied","generation":42,
 "sources":["172.18.0.2","172.18.0.3"],"unresolved_hosts":["api.example.com"]}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `generation` | number | Increases by one with every successful update |
| `sources` | array of strings | The managed container addresses |
| `unresolved_hosts` | array of strings | Hostnames of `host:` rules with no known addresses; their rules allow nothing yet |

## `apply_failed`

Updating the rules failed; the previous rules stay in place, and Portcullis tries again. Raises an alert.

```json
{"time":"2026-11-02T10:15:29.912Z","event":"apply_failed","error":"..."}
```

## Text format

With `log-format = "text"` (the default), and in `portcullis watch`, each event is one line, for people:

```text
2026-11-02T10:15:29.870Z managing billing 172.18.0.2 on backend (enforce)
2026-11-02T10:15:29.912Z applied rules (generation 42, 2 container addresses), unresolved: api.example.com
2026-11-02T10:15:30.101Z dns billing A api.stripe.com via 192.168.1.1: No Error 104.18.3.4 104.18.2.4
2026-11-02T10:15:30.120Z DENIED egress billing 172.18.0.2 -> api.stripe.com (104.18.3.4) tcp/443
2026-11-02T10:15:31.004Z would deny icc worker 172.18.0.4 -> db (172.18.0.5) tcp/5432
2026-11-02T10:15:32.450Z warning traefik: ...
2026-11-02T10:15:33.000Z releasing billing 172.18.0.2 on backend (enforce)
```

The text format isn't meant for machines and may change. Use JSON for anything that parses events.
