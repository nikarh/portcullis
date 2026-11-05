---
title: Escape hatches
description: Things Portcullis can't do, and what to use instead.
sidebar:
  label: Workarounds
  order: 2
---

Portcullis filters what containers on bridge networks send, by IPv4 address, protocol and port, from labels. Some needs fall outside that. This page lists them with what to do instead. The underlying limits are listed in [Limitations](/limits/limitations/).

## Filtering by hostname, SNI or URL

A `host:` rule allows the addresses a name resolves to. Behind a CDN or shared hosting, those addresses serve other sites too, and a pattern under a domain where anyone can create names (`*.cloudfront.net`, `*.github.io`) allows anyone's server. Portcullis doesn't look at TLS SNI or HTTP.

Use a filtering proxy (Squid, Envoy, smokescreen) that decides by `CONNECT` target, SNI or URL, and let Portcullis make it the only way out: the application may only reach the proxy, the proxy may reach `ip:public` on 80 and 443.

```yaml
labels:
  - portcullis.icc.mode=allow-listed
  - portcullis.icc.allow.proxy=container:proxy,tcp:3128
```

Full setup: [Egress through a filtering proxy](/examples/egress-proxy/).

## Data leaks through lookups of allowed names

`portcullis.domains` stops lookups of names outside its list, which closes DNS tunnels through domains someone else controls. It can't help with names you allow whose servers someone else controls, such as a domain anyone can create records under.

- List exact names rather than wide patterns.
- To apply a policy centrally, run a resolver container with an allow-list or response policy zone, and make it the only resolver other containers may use. See [A shared resolver with a policy](/examples/own-resolver/#a-shared-resolver-with-a-policy).

## Bandwidth and CPU

Quarantine and connection limits protect the connection tracking table and cut off containers that misbehave. They can't stop a container from using bandwidth or CPU with traffic its rules allow.

- CPU and memory: Compose `cpus:` and `mem_limit:` (or `deploy.resources.limits`).
- Bandwidth: shape traffic on the host with `tc`, on the container's veth or the bridge.

## IPv6

Portcullis doesn't manage IPv6, and denies all of it on enforced networks. If containers need IPv6, Portcullis can't filter it. On an enforced network, leave IPv6 disabled (Docker's default for user networks). An `ipv6_network` warning reports enforced networks that have it; acknowledge it with `portcullis.ack=ipv6-network` on the network if IPv6 being unusable there is intended.

## Host networking and other network drivers

Containers with `network_mode: host`, and containers on overlay, macvlan or ipvlan networks, aren't filtered. Portcullis reports `unused_labels` for host-networked containers that have Portcullis labels.

Filter those with your own nftables rules on the host: for host networking, rules on the `output` hook matched by the process's cgroup (`socket cgroupv2`), or better, move the container to a bridge network.

## Filtering incoming connections

Labels only limit connections a container opens. Replies to incoming connections are always allowed, and anyone who can reach a published port can exchange data with the container.

To limit who connects in, use the host firewall: Docker's `DOCKER-USER` iptables chain, or your own nftables rules ahead of Docker's. Bind published ports to one address (`127.0.0.1:8080:8080`) where only local access is needed.

## Raw sockets and NET_ADMIN

Portcullis keeps containers with `NET_RAW` from getting past their rules, but they can still flood their network until quarantined, and see broadcast and multicast of their network. With `NET_ADMIN` a container can change its interfaces and routes, and disturb its own traffic.

```yaml
services:
  app:
    cap_drop: [NET_RAW]
```

`ping` is about the only common tool that needs `NET_RAW`. Don't give `NET_ADMIN` to containers you don't trust. See [Hardening a host](/guides/hardening/).

## The window when a network is created

A network is enforced once Portcullis has seen it created. `docker compose up` creates the network and starts containers right away, which leaves them a window of milliseconds. Create enforced networks ahead of time and use them as `external: true` in Compose:

```bash
docker network create --label portcullis.enable=true backend
```

See [Rolling out on a host with running stacks](/examples/existing-networks/#why-external-networks).

## Lookups Docker resolves from the host

Without its own DNS servers and without a daemon-wide `dns` setting, Docker 29 resolves a container's outside names from the host. No container policy applies to those lookups, `portcullis.domains` included, and `host:` patterns can't learn addresses from them. Set `dns` in `/etc/docker/daemon.json`:

```json
{ "dns": ["192.168.1.1"] }
```

## Debugging a policy without denying anything

- One network: create it with `portcullis.enable=monitor`. Docker only sets labels at creation, so this means recreating the network.
- An existing network without recreating it: `monitor-networks = ["backend"]` in the config, then restart Portcullis. A network's own label wins.
- Everything: `monitor = true` in the config, then restart Portcullis.

Monitor mode reports `would_deny` for what would be denied, and every allowed flow and lookup by default. It never raises alerts.

## Opting a container out

- Quarantine: `portcullis.quarantine=off` on a container that has a reason to craft packets, such as a network tool. `--quarantine report` or `off` changes it host-wide.
- Configuration checks: `portcullis.ack=<name>[,<name>...]` silences a warning you've reviewed. It changes nothing else. See [Configuration checks](/policy/checks/).
- Connection limit: `portcullis.limit.connections=none`.

There is no label that exempts a container on an enforced network from its rules. Move it to a network that isn't enforced, and accept the `unenforced_network` warning if it's on both.

## Turning it off in an emergency

Stopping Portcullis doesn't open anything: with the default `on-exit = "keep"` its rules stay, containers keep their last rules, and new containers on enforced networks can't send at all.

To stop denying while still seeing what would be denied, set `monitor = true` in the config and restart Portcullis. To remove all restrictions:

```bash
sudo systemctl stop portcullis
sudo portcullis cleanup
```

`cleanup` also removes the saved rules, so they don't come back at the next start. Disable the service too if it shouldn't come back at boot.

With `on-exit = "remove"`, a clean stop removes the rules, and containers are unrestricted whenever Portcullis isn't running, including at boot until it starts. After a crash the rules stay either way.

## While Portcullis is down

With `on-exit = "keep"`:

- Running containers keep their last rules. Changes to labels, networks and hostname addresses aren't picked up.
- Containers that start on an enforced network can't send anything until Portcullis is back.
- DNS answers go through uninspected, so `host:` rules don't learn new addresses. Lookups of containers with `portcullis.domains` labels fail.
- Nothing is reported, and no alerts are raised.
