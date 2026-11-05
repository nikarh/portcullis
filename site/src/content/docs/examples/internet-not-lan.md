---
title: The internet, but not the LAN
description: Let a container connect anywhere on the internet while keeping it away from the Docker host, the router and the local network.
sidebar:
  label: Internet, not the LAN
  order: 5
---

A BitTorrent client, a crawler or a game server connects to addresses nobody can list in advance. It still has no business on the LAN, the router's admin page, the cloud metadata service or other services on the Docker host.

```yaml title="docker-compose.yml"
services:
  torrent:
    image: ghcr.io/acme/torrent:latest
    ports: ["51413:51413/tcp", "51413:51413/udp"]
    networks: [isolated]
    cap_drop: [NET_RAW]
    labels:
      - portcullis.icc.mode=deny
      - portcullis.egress.peers=ip:public,tcp:*,udp:*

networks:
  isolated:
    labels:
      - portcullis.enable=true
```

## What each label does

`portcullis.egress.peers=ip:public,tcp:*,udp:*` allows TCP and UDP to any port of any public address. `ip:public` leaves out:

- private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and shared address space (`100.64.0.0/10`, CGNAT);
- loopback, link-local (`169.254.0.0/16`, which has cloud metadata services), multicast, documentation, benchmarking and reserved ranges;
- the Docker host's own addresses, even public ones, also when the container reaches a published port through them.

So the container can reach peers on the internet, and not the router, the NAS, other hosts on the LAN, or services and published ports on the Docker host.

`portcullis.icc.mode=deny` keeps it from opening connections to other containers on the network.

`cap_drop: [NET_RAW]` isn't a Portcullis setting. It takes away raw sockets, which a torrent client doesn't need, and with them the ability to craft frames. See [Hardening containers](/guides/hardening/).

## Narrower variants

Limit the ports where you can. A crawler only needs `ip:public,tcp:80,443`. A WebRTC service might need `ip:public,udp:3478-3479` for STUN and `udp:1024-65535` for media.

`ip:*` instead of `ip:public` allows every address, the host's and the LAN's included. That is rarely what you want.

## DNS and incoming connections

DNS isn't covered by egress labels, not even `ip:*,*`. The container resolves names through Docker's DNS as any container does; with the default `portcullis.dns` target `docker`, direct queries may only go to the servers Docker forwards to. See [DNS](/policy/dns/).

The published port is reachable from outside, and replies to those connections are always allowed, whatever the labels say. Portcullis doesn't decide who may connect in.

## What this doesn't cover

- Bandwidth. A container with `ip:public,*` can use all of the uplink. Limit it on the host with `tc`, see [Escape hatches](/limits/escape-hatches/#bandwidth-and-cpu).
- Abuse of the internet itself. If the container is compromised, it can attack anyone on the internet its rules allow, which with `ip:public` is everyone.
