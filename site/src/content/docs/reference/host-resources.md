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
| `/var/lib/portcullis/rules.batch` | The rules of the last update, as the netlink batch that puts them in place, put back at the next start (`state-dir`). Earlier versions saved them as `rules.nft`, an nft script, which Portcullis removes when it starts |
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

Don't edit them: every update rewrites what changed, and an edit in a chain it leaves alone may stay. A change of containers that leaves the rules as they are writes nothing at all, so an edit stays until the rules change. `--log-level trace` logs every update, as the nft script that does the same.

Portcullis doesn't touch Docker's rules or anyone else's, and works next to Docker using iptables or nftables. Large sets in other tables, such as another firewall's block lists, don't slow it down: it sends its changes to the kernel without reading anything of the rules first (see [DNS inspection](/internals/how-it-works/#dns-inspection)).

## Netfilter numbers

| Resource | Number | Used for |
| --- | --- | --- |
| NFLOG group | 4242 | decisions the rules report |
| NFQUEUE | 4242 | DNS answers held for inspection |
| NFQUEUE | 4243 | packets of containers not known yet, on enforced networks |
| NFQUEUE | 4244 | DNS queries of containers with `portcullis.domains` labels |
| NFQUEUE | 4245 | packets of containers not known yet, on networks in monitor mode |
| NFQUEUE | 4246 | connections through `host:` rules whose names are checked, on enforced networks |
| NFQUEUE | 4247 | the same, on networks in monitor mode |
| Packet marks | `0x70630001` to `0x70630006` | internal bookkeeping |
| Connection marks | bits `0x00f00000` (`ct-mark-mask`) | the state of name checks; other bits are left alone |

Other software on the host must not use the same numbers. Only the connection mark bits can be changed.

## Connection marks

Connection tracking keeps a 32-bit mark for each connection, which rules can read and set (`ct mark`). Portcullis keeps the state of each [name check](/internals/how-it-works/#name-checks) in four bits of it, by default `0x00f00000`:

| Bit (default) | Set while |
| --- | --- |
| `0x00100000` | the connection is a monitored container's: its packets go to the queue that lets them through when Portcullis isn't reading it |
| `0x00200000` | the connection's name is being checked: all its packets, both ways, go to Portcullis |
| `0x00400000` | the connection is plain HTTP: the packets its client sends with data go to Portcullis |
| `0x00800000` | the connection was denied: its packets are dropped |

It needs the connection's mark because the check spans several packets: the kernel has to know, for every packet of the connection, whether to hand it to Portcullis, let it through, or drop it, and the connection mark is what connection tracking keeps per connection. Most connections never have any of these bits set: those that don't go through a `host:` rule, and those whose check is over. Every packet costs one test of the mark.

Portcullis only changes these four bits, and leaves the rest of the mark as it is. Other software that sets the same bits breaks name checks; software that sets the whole mark (`ct mark set 1337`, rather than a masked change) clears them, and a connection being checked then passes unchecked; one whose bits Portcullis set may be dropped or held by the other software's rules. Software known to use connection marks:

- Istio's sidecar uses the mark `1337`: packet marks, and connection marks in its TPROXY mode.
- Cilium reserves bits of packet marks for its own datapath.
- kube-proxy and some Kubernetes network plugins, WireGuard and other VPN setups (`wg-quick` with policy routing), and firewalld zones and some routers' QoS rules use marks too, mostly packet marks, which connection tracking can copy into connection marks (`connmark`).

To check, list the rules of every table and look for marks:

```bash
sudo nft list ruleset | grep -i mark
sudo iptables-save | grep -i mark
```

and look at the marks connections have, which shows bits someone set:

```bash
sudo conntrack -L -o extended | grep -o 'mark=[0-9]*' | sort | uniq -c
```

(`conntrack` prints marks in decimal; `printf '%#010x\n' 1337` shows one in hex.) If anything uses bits of `0x00f00000`, give Portcullis other ones, at least four that are contiguous and free (the lowest four of the mask are used), in the config:

```toml title="/etc/portcullis/config.toml"
ct-mark-mask = "0x0000f000"
```

and restart Portcullis. Connections whose names were being checked during the restart are denied.

## Kernel

- Filtering traffic between containers needs connection tracking for bridged traffic. The kernel loads the `nf_conntrack_bridge` module for this the first time Portcullis installs its rules.
- Portcullis uses rtnetlink to find each container's bridge port and network namespace, and conntrack to delete the tracked connections of a removed container's address before Docker gives it to a new one.
