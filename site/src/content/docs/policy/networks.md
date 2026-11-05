---
title: Enforcing a network
description: The portcullis.enable network label, monitor mode, watching existing networks, and which networks can be enforced.
sidebar:
  order: 2
---

Nothing is restricted until you enable Portcullis on a network with a network label:

```text
portcullis.enable=true      # enforce
portcullis.enable=monitor   # report what would be denied, deny nothing
portcullis.enable=false     # leave alone, also when monitor-networks = ["*"]
```

Docker only lets you set labels when a network is created. With Compose:

```yaml title="docker-compose.yml"
networks:
  backend:
    labels:
      - portcullis.enable=true
```

Or by hand:

```bash
docker network create --label portcullis.enable=true backend
```

Every container attached to an enforced network is then restricted (or, in monitor mode, watched), whether or not it has Portcullis labels of its own. A container without labels can talk to other containers on the same network and resolve names through Docker's DNS, and nothing else. Labels on the container open up more.

`portcullis.enable` only has an effect on networks; on a container it is ignored. An invalid value enforces the network.

## Watching networks without a label

To watch networks that already exist without recreating them, and so without restarting their containers, name them in the config instead:

```toml title="/etc/portcullis/config.toml"
monitor-networks = ["backend", "frontend"]
# or every bridge network:
monitor-networks = ["*"]
```

On the command line, repeat `--monitor-network <name>`. This only puts networks in monitor mode; enforcing a network takes its label. A network's own label, if it has one, wins, so `portcullis.enable=false` keeps a network out of `"*"`.

`monitor = true` in the config puts every network Portcullis watches in monitor mode, the enforced ones included. It is a switch for the whole host, for rolling out or for an emergency.

## Which networks can be enforced

- Only bridge networks. Overlay, macvlan, ipvlan and host networking are ignored.
- The default `bridge` network can't be enforced, because it can't be given labels, but `monitor-networks` can watch it.
- The network needs an IPv4 subnet. An enforced network without a usable subnet is reported with an `invalid_network` warning and not enforced.
- On a network with IPv6 enabled, Portcullis denies all IPv6, so its containers can't use it. An `ipv6_network` warning says so; acknowledge it with `portcullis.ack=ipv6-network` on the network if that's intended.

## When enforcement starts

A network is enforced once Portcullis has seen it created, which usually takes milliseconds. Until then, its traffic isn't filtered at all. Containers that start on a brand-new network can get packets out in that window, for example when `docker compose up` creates the network and starts its containers right away.

To close the window, create enforced networks ahead of time and start containers on them afterwards. In Compose, declare such a network `external`:

```bash
docker network create --label portcullis.enable=true backend
```

```yaml title="docker-compose.yml"
networks:
  backend:
    external: true
```

Packets of containers that start on an already enforced network are held until their rules are in place, so nothing gets through there. See [Existing networks](/examples/existing-networks/) for a full setup.

## Containers on several networks

A container's labels apply on every enforced network it is on. A container attached to both an enforced and a non-enforced network is only restricted for traffic it sends from its enforced-network address; traffic leaving through the other network is not filtered. Portcullis reports this with an `unenforced_network` warning. See [Configuration checks](/policy/checks/).
