---
title: Finding new containers
description: How Portcullis identifies a container from its bridge port within milliseconds, without waiting for Docker.
sidebar:
  order: 2
---

Docker reports a container that started through its events and API, which can take a second, or much longer when the host is busy. Meanwhile, the container's packets are held (see [Containers that just started](/internals/how-it-works/#containers-that-just-started)). Portcullis doesn't wait for Docker: for the bridge port a held packet came in on, it finds the container behind it, and applies its rules right away.

1. The kernel tells which bridge the port is on, and which network namespace the other end of the veth pair is in (rtnetlink).
2. The container's interface in that namespace has its MAC and address, as Docker set them up before the container's process ran. Nothing is run inside the container.
3. The container whose processes are in that namespace is found by its cgroup (`docker-<id>.scope`). A container that uses another one's network (`network_mode: container:...`) isn't the namespace's owner and is skipped.
4. Its name and labels come from the files Docker keeps for it, `config.v2.json` and `hostconfig.json` under `docker-root`.

This takes a few milliseconds. Until the container's process exists (its interface comes up a moment before), the packets stay held, and Portcullis looks again every 100 milliseconds. Docker's own report of the container, when it comes, replaces what was found.

A restarted container gets new MACs. When the MAC found on one network isn't the one Portcullis knew there, the container's other networks are taken as of its previous run, and forgotten until they are found from their own ports, or Docker reports them. A container that is stopping (its network namespace is gone) keeps its addresses only as long as no other container has them: Docker may already have given them to the container recreated in its place, and report the old one gone only later.

Portcullis asks Docker about containers from the thread that reads Docker's events, never while it looks for containers: Docker answers about a container only once it has finished starting it. For a container on many networks on a busy host that takes seconds, and Docker reports each network the container joins before that.

The address and MAC are those of the container's own interface. A container with `NET_ADMIN` can change them, as it can do much else; see [Limitations](/limits/limitations/).

## Where it doesn't work

Portcullis then waits for Docker's report as before, and a container that Docker takes longer than 2 seconds to report loses its first packets on enforced networks (TCP and DNS send them again). That is the case:

- when the container's cgroup isn't `system.slice/docker-<id>.scope` (systemd cgroup driver) or `docker/<id>` (cgroupfs);
- with rootless Docker;
- when `docker-root` isn't Docker's data directory. With `userns-remap` it is a directory below the usual one; `docker info -f '{{.DockerRootDir}}'` shows it.

## Monitor mode

On networks in monitor mode the hold never denies anything: a packet whose source stays unknown is reported and let through, and the queue lets packets through while Portcullis isn't running, and when it is full.

Only while Portcullis runs but can't read the queue at all (stopped with `SIGSTOP`, or the whole process stuck) do the first packets of new containers on those networks wait, until the kernel's queue is full (1024 packets) and lets the rest through.
