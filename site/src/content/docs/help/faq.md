---
title: FAQ
description: Short answers to the questions that come up first.
sidebar:
  order: 2
---

## Does it replace Docker's firewall rules?

No. Portcullis only removes access. Traffic that a policy allows still goes through Docker's own rules afterwards, so what Docker blocks (internal networks, isolation between networks) stays blocked. Portcullis keeps its rules in tables of its own, next to Docker's.

## Does it work with Docker using iptables, or nftables?

Both. Portcullis's rules work next to Docker's either way.

## Does it support IPv6?

No, by design. Portcullis uses a network's IPv4 subnet and matches containers by their IPv4 address. IPv6 entering an enforced network's bridge is denied, so containers on an enforced network with IPv6 enabled can't use IPv6 at all.

## Which network drivers work?

Bridge networks only. Overlay (Swarm), macvlan, ipvlan and host networking aren't supported. A container with `network_mode: host` and `portcullis.*` labels gets an `unused_labels` warning: its labels look like a policy, but nothing applies them. The default `bridge` network can't be enforced, because it can't be given labels, but `monitor-networks` can watch it.

## Rootless Docker, Podman, Kubernetes?

Portcullis talks to the Docker API and reads the files Docker keeps for each container. With rootless Docker, finding new containers without waiting for Docker doesn't work (see [Finding new containers](/internals/discovery/)). Podman and Kubernetes aren't supported or tested.

## What happens when Portcullis crashes or stops?

By default its rules stay in place. Running containers keep their last rules; containers that start meanwhile on an enforced network can't send anything until Portcullis is back. DNS answers go through uninspected, and nothing is reported. systemd starts it again after 2 seconds. See [Running as a service](/guides/service/).

## What happens at boot?

Portcullis puts the last saved rules back before Docker starts, then waits for Docker. Containers that Docker starts on enforced networks are held until their rules are in place. Nothing runs unrestricted in between.

## What does it cost?

Rules are evaluated in the kernel. Containers with `portcullis.domains` labels wait for a round trip through Portcullis on every lookup, a small delay next to the lookup itself; containers without them aren't affected. There are no published benchmarks.

## Can it filter by URL, or by TLS SNI?

No. Rules match addresses and ports. A `host:` rule allows the addresses a name resolves to, which may serve other sites too. For hostname- or URL-precise filtering, send traffic through a filtering proxy and let Portcullis make the proxy the only way out: see [Egress through a filtering proxy](/examples/egress-proxy/).

## Does it control incoming connections?

No. Labels limit the connections a container opens. Replies to incoming connections are always allowed, so published ports keep working. Use the host firewall to limit who may connect in.

## Does it store logs?

No. It writes events to stdout (and optionally a Unix socket). Send them to whatever collects your logs. See [Events and alerts](/guides/events-and-alerts/).

## Does it change anything inside containers?

No. It never runs anything inside a container. It reads container interfaces through the kernel and Docker's files, and filters on the host.

## Do I have to restart containers to apply a policy?

To change a container's labels, yes: Docker can't change labels of an existing container. Portcullis picks up the new container immediately. Changing Portcullis's own config takes a restart of Portcullis, during which the rules stay in place.
