---
title: A cluster that discovers its members by multicast
description: Let replicas of a service find each other through one multicast group and port, and talk to each other, while others reach them on one port only.
sidebar:
  label: Multicast cluster
  order: 3
---

Hazelcast members find each other by multicast (group `224.2.2.3`, UDP 54327) and then talk over TCP 5701. The API may only reach the cluster on 5701.

```yaml title="docker-compose.yml"
services:
  cache:
    image: hazelcast/hazelcast:5.5
    deploy:
      replicas: 3
    networks: [backend]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.discovery=multicast:224.2.2.3,udp:54327
      - portcullis.icc.allow.members=container:cache,tcp:5701

  api:
    image: ghcr.io/acme/api:latest
    networks: [backend]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.cache=container:cache,tcp:5701

networks:
  backend:
    labels:
      - portcullis.enable=true
```

## What each label does

With `allow-listed` (and `deny`), broadcast and multicast are blocked, since the bridge delivers them to every container on the network.

`portcullis.icc.allow.discovery=multicast:224.2.2.3,udp:54327` lets each member send UDP 54327 to that group, and nothing else multicast. The group can also be a range (`239.0.0.0/8`) or `*`.

`portcullis.icc.allow.members=container:cache,tcp:5701` lets members connect to each other. `cache` is the Compose service name, which is an alias of all three replicas, so every replica matches.

The API's `container:cache,tcp:5701` lets it connect to the members, and not send to their multicast group.

## Replies to multicast

Members usually answer a multicast announcement with a unicast packet to the sender's own address, not to the group. That is a connection to another container, so it takes a `container:` rule. Without `members`, discovery packets go out but the answers are denied as `icc`.

## Receiving is not controlled

Every container on the network receives what is sent to a group it joined, whatever its own labels. Labels only decide what a container sends. Containers that must not see the cluster's traffic belong on another network.

Broadcast (`255.255.255.255`) can't be allowed. A clustering setup that relies on broadcast needs another discovery method, such as a fixed member list using `container:` names.

## Other uses

The same entry fits services that announce themselves over mDNS to others on the network (`multicast:224.0.0.251,udp:5353`), and JGroups' UDP stack (Infinispan, Keycloak) with its configured group and port.
