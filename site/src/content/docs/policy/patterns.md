---
title: Names and patterns
description: "The wildcard syntax shared by host:, container: and portcullis.domains labels."
sidebar:
  order: 4
---

Every label that names something takes the same patterns: hostnames (`host:`), containers (`container:`) and the names a container may look up (`portcullis.domains`). A name is a list of labels separated by dots, and:

- `*` within a label stands for any characters of that one label, none included.
- `**` as the first label stands for one or more labels.

| Pattern | Matches | Doesn't match |
| --- | --- | --- |
| `*.example.com` | `a.example.com` | `a.b.example.com`, `example.com` |
| `cdn-*.example.com` | `cdn-1.example.com`, `cdn-.example.com` | `cdn.example.com` |
| `**.example.com` | `a.example.com`, `a.b.example.com` | `example.com`, `badexample.com` |
| `example.com` | `example.com`, `EXAMPLE.com.` | `www.example.com` |

For a domain and everything below it, list both: `example.com` and `**.example.com`.

Rules for hostnames:

- Case and a trailing dot don't matter.
- A hostname pattern has to name a domain: a pattern of wildcards only (`*`, `**`, `*.*`) is invalid. Use `ip:*` or `ip:public` instead.
- `**` is only allowed as a whole label, and only the first one.
- Labels take letters, digits, `-`, `_` and `*`, up to 63 characters each.

Wildcards never match across a dot, or an empty label. Container names aren't normalized: they are matched as Docker's DNS knows them.

For containers, `container:*` matches every container on a shared network, and `container:worker-*` every container or alias starting with `worker-`; see [Traffic between containers](/policy/icc/).

## What a pattern costs

A pattern in a `host:` rule can't be looked up, so it only allows addresses from DNS answers the container received for names it matches. Portcullis has to [see the container's lookups](/policy/dns/#dns-visibility) for it to allow anything. See [Hostname rules](/policy/hostnames/#patterns).

A pattern allows the addresses of every name it matches. Under a domain where anyone can create names (`*.cloudfront.net`, `*.github.io`, `*.s3.amazonaws.com`), that is anyone's server. Prefer exact names where you can.
