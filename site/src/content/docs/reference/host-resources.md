---
title: Files and kernel resources
description: The files, nftables tables, netfilter numbers and kernel modules Portcullis uses on the host.
sidebar:
  order: 4
---

## Files

| Path | What |
| --- | --- |
| `/usr/bin/portcullis` | The binary, from the packages (`/usr/local/bin/portcullis` when installed by hand) |
| `/etc/portcullis/config.toml` | The config file, see [Configuration](/reference/configuration/) |
| `portcullis.service` | The systemd unit, see [The systemd unit](/guides/service/#the-systemd-unit) |
| `/var/lib/portcullis/rules.nft` | The rules of the last update, put back at the next start (`state-dir`) |
| `/var/lib/portcullis/owners` | Which container each container address belonged to at the last update, to tell at the next start which addresses changed hands meanwhile (`state-dir`) |
| `/run/portcullis.sock` | The events socket, when `events-socket` is set (it is in the packaged config) |
| `/var/run/docker.sock` | Docker's API, read (`docker-socket`) |
| `/var/lib/docker/containers/<id>/config.v2.json`, `hostconfig.json` | Read for containers that just started (`docker-root`), see [Finding new containers](/internals/discovery/) |
| `/etc/resolv.conf`, `/run/systemd/resolve/resolv.conf` | Read on every rule update, for the host's DNS servers |
| `/etc/docker/daemon.json` | Read on every rule update, for Docker's daemon-wide `dns` servers |

## nftables

Portcullis keeps its rules in two tables of its own:

| Table | For |
| --- | --- |
| `inet portcullis` | traffic leaving a container's network, or addressed to the Docker host |
| `bridge portcullis` | everything entering an enforced network's bridge from a container: traffic between containers, and the source checks |

Look at them with:

```bash
sudo nft list table inet portcullis
sudo nft list table bridge portcullis
```

Don't edit them: every update rewrites what changed, and an edit in a chain it leaves alone may stay. `--log-level trace` logs every script Portcullis applies.

Portcullis doesn't touch Docker's rules or anyone else's, and works next to Docker using iptables or nftables.

## Netfilter numbers

| Resource | Number | Used for |
| --- | --- | --- |
| NFLOG group | 4242 | decisions the rules report |
| NFQUEUE | 4242 | DNS answers held for inspection |
| NFQUEUE | 4243 | packets of containers not known yet, on enforced networks |
| NFQUEUE | 4244 | DNS queries of containers with `portcullis.domains` labels |
| NFQUEUE | 4245 | packets of containers not known yet, on networks in monitor mode |
| Packet marks | `0x70630001` to `0x70630003` | internal bookkeeping |

Other software on the host must not use the same numbers. They can't be changed.

## Kernel

- Filtering traffic between containers needs connection tracking for bridged traffic. The kernel loads the `nf_conntrack_bridge` module for this the first time Portcullis installs its rules.
- Portcullis uses rtnetlink to find each container's bridge port and network namespace, and conntrack to delete the tracked connections of a removed container's address before Docker gives it to a new one.
