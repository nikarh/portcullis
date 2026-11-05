---
title: Rolling out on a host with running stacks
description: Watch networks that already exist without recreating them, write labels from what was seen, then enforce on networks created ahead of time.
sidebar:
  label: Existing networks
  order: 7
---

A host already runs a dozen Compose projects. Docker only sets network labels when a network is created, and recreating a network means restarting its containers. This rollout watches everything first, without touching any project, and only recreates networks once their labels are written.

## 1. Watch every network

In `/etc/portcullis/config.toml`:

```toml title="/etc/portcullis/config.toml"
monitor-networks = ["*"]
events-socket = "/run/portcullis.sock"
```

```bash
sudo systemctl restart portcullis
```

`*` puts every bridge network in monitor mode, the default `bridge` network included. Nothing is denied. Every connection the containers' labels (none, so far) wouldn't allow is reported as `would_deny`, and every DNS lookup is reported, since `--log-allowed monitor` reports allowed traffic on networks in monitor mode.

A network's own `portcullis.enable` label wins over `monitor-networks`. To leave a network out of `*`, it needs `portcullis.enable=false`, which again means creating it with that label.

Watch the events live while you work:

```bash
sudo portcullis watch
```

## 2. Turn the events into labels

Let the services run through their usual work: a day, a week, whatever covers backups, renewals and other periodic jobs. Then:

```bash
journalctl -u portcullis -o cat | portcullis audit
```

`audit` reads JSON events, so the daemon has to run with `log-format = "json"` for this to find anything in the journal. It prints, per container, the labels that would have allowed what it saw. Review them: they describe what happened, not what should happen. A container that phoned somewhere unexpected shows up here first.

See [Rolling out a policy](/guides/rollout/) for what `audit` joins and how it reports packets that need no label.

## 3. Create the enforced networks ahead of time

For each project, create its network once, with the label, outside Compose:

```bash
docker network create --label portcullis.enable=true shop-backend
```

and refer to it as external:

```yaml title="docker-compose.yml"
services:
  api:
    image: ghcr.io/acme/api:latest
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443

networks:
  backend:
    name: shop-backend
    external: true
```

```bash
docker compose up -d --force-recreate
```

To check the labels on a network that still reports, create it with `portcullis.enable=monitor` first, and switch to `true` (recreating the network) once its events are quiet.

### Why external networks

A network is enforced once Portcullis has seen it created, which usually takes milliseconds. When `docker compose up` creates a network and starts containers on it right away, those containers can get packets out in that window. A network created ahead of time is enforced before any container starts on it, and packets of containers that start on an enforced network are held until their rules are in place. Nothing gets through.

External networks also survive `docker compose down`, so the project's containers never start on a network Portcullis hasn't seen yet.

## 4. Stop watching the rest

Once every project's network is enforced, remove `monitor-networks` (or list only what you still want to watch), and restart Portcullis. Monitor mode reports every flow and lookup; it's meant for rolling out, not to stay on.
