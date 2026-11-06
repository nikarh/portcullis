---
title: Traffic between containers
description: The ICC mode, allow-listing containers by name or pattern, and multicast between containers.
sidebar:
  order: 6
---

ICC (inter-container communication) covers traffic from a container to other containers on the same enforced network. Set the mode with:

```text
portcullis.icc.mode=allow|deny|allow-listed
```

| Mode | The container may open connections to |
| --- | --- |
| `allow` (default) | every container on its networks |
| `deny` | no container |
| `allow-listed` | only the containers and multicast groups its `portcullis.icc.allow.*` labels list |

The mode only controls connections the container starts. Whether others can reach it is decided by their own labels, and replies always pass: a database with `deny` still answers the connections its clients open.

An invalid mode counts as `deny`.

## Allow-listed

```text
portcullis.icc.allow.<name>=container:<target>,<service>[,<service>...]
```

Services are those of [egress labels](/policy/egress/#services). The target is a container name, or a [pattern](/policy/patterns/) of one, matched the way Docker's DNS resolves names from the source container:

- It matches a container name or a network alias. Compose gives every container its service name as an alias, so `container:db` works for a service called `db`, even though the container itself is named something like `myproject-db-1`.
- `container:worker-*` matches every service whose name starts with `worker-`, and `container:*` every container on a shared network.
- Only containers on a network the source container is also on can match, and only their addresses on that shared network are allowed.
- If several containers match (a service scaled to more than one replica), all of them are allowed. Containers that start later and match are added as they start.

Container IDs are not accepted, since they change every time a container is recreated.

```yaml title="docker-compose.yml"
services:
  api:
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432
      - portcullis.icc.allow.cache=container:redis,tcp:6379
  db:
    labels:
      - portcullis.icc.mode=deny
  redis:
    labels:
      - portcullis.icc.mode=deny
```

`icc.allow` labels on a container whose mode isn't `allow-listed` have no effect.

## Broadcast and multicast

With `deny` and `allow-listed`, broadcast (`255.255.255.255`) and multicast (`224.0.0.0/4`) traffic is blocked too, since the bridge delivers it to every container on the network. Broadcast can't be allowed.

The Docker host gets broadcast and multicast of the network as well. Its copy follows the container's [egress labels](/policy/egress/), as all traffic to the host does, whatever the ICC mode: with `allow`, broadcast to the subnet reaches the other containers, but not services on the host unless an egress label allows the host.

### Multicast

An `allow-listed` container can be let send to multicast groups:

```text
portcullis.icc.allow.<name>=multicast:<group>,<service>[,<service>...]
```

The group is an address (`224.0.0.251`), a range (`239.0.0.0/8`), or `*` for any.

Members of a cluster that find each other by multicast need it, such as Hazelcast (`224.2.2.3`, UDP 54327) or JGroups' UDP stack (Infinispan, Keycloak); so do services that announce themselves over mDNS (`224.0.0.251`, UDP 5353) to others on the network.

- Every container on the network receives what is sent to a group it joined, whatever its own labels: they only decide what a container sends.
- Answers to multicast are usually sent to the sender's own address, which takes a `container:` rule.

See [Multicast cluster](/examples/multicast-cluster/) for a full example.

## What ICC can't do

- Traffic to a container on another network goes through the Docker host, so egress labels decide it, and Docker's isolation between networks applies after that.
- Traffic between two containers has to be addressed to their shared network. A frame to another container's MAC addressed to that container's address on another network is denied, even with ICC allowed.
- DNS: Docker's DNS server answers container names inside the container, so they always resolve, whatever the ICC mode.
