---
title: Quick start
description: Install Portcullis, watch a network in monitor mode, turn what you see into labels, and enforce them.
sidebar:
  order: 2
---

This walks through the whole cycle on one Debian or Ubuntu host: install, observe, write labels, enforce. It takes about ten minutes. On other systems, install as described in [Installation](/start/installation/) and continue from step 2.

## 1. Install

Add the apt repository and install the package:

```bash
sudo install -d /etc/apt/keyrings
curl -fL https://raw.githubusercontent.com/nikarh/portcullis/main/docs/signing-key.asc \
  | sudo tee /etc/apt/keyrings/portcullis.asc >/dev/null
sudo tee /etc/apt/sources.list.d/portcullis.sources >/dev/null <<'SRC'
Types: deb
URIs: https://github.com/nikarh/portcullis/releases/download/apt/
Suites: ./
Signed-By: /etc/apt/keyrings/portcullis.asc
SRC
sudo apt update
sudo apt install portcullis
```

The service is enabled and running right away. The Debian package's config starts in monitor mode (`monitor = true` in `/etc/portcullis/config.toml`), so it reports what it would deny and denies nothing. Check that it runs:

```bash
systemctl status portcullis
```

## 2. Let Docker's DNS lookups be seen

Portcullis names destinations in its reports by watching the DNS answers containers receive. It can only see them when Docker forwards lookups from the container's address, which takes a `dns` setting in `/etc/docker/daemon.json`. Use the resolver from the host's `resolv.conf`, or any other:

```json title="/etc/docker/daemon.json"
{ "dns": ["192.168.1.1"] }
```

```bash
sudo systemctl restart docker
```

This is optional, but without it reports show bare addresses, and patterns in `host:` rules can't work. See [DNS visibility](/policy/dns/#dns-visibility).

## 3. Watch a network

`portcullis audit`, used below, reads events as JSON. Switch the event format in the config and restart:

```toml title="/etc/portcullis/config.toml"
log-format = "json"
```

```bash
sudo systemctl restart portcullis
```

Start a small project on a network in monitor mode. The container fetches a page every 30 seconds:

```yaml title="docker-compose.yml"
services:
  app:
    image: alpine:3
    command: sh -c 'while true; do wget -qO /dev/null https://example.com; sleep 30; done'
    networks: [demo]

networks:
  demo:
    labels:
      - portcullis.enable=monitor
```

```bash
docker compose up -d
sudo portcullis watch
```

`portcullis watch` prints events live from the daemon's events socket. Each connection the policy would deny shows up once a minute per destination, along with the DNS answer it came from:

```text
2026-11-06T10:15:30.120Z dns demo-app-1 A example.com via 192.168.1.1: No Error 93.184.215.14
2026-11-06T10:15:30.124Z would deny egress demo-app-1 172.20.0.2 -> example.com (93.184.215.14) tcp/443
```

The addresses here are examples; yours will differ.

## 4. Turn the reports into labels

After the services have run for a while, summarize everything that would have been denied:

```bash
journalctl -u portcullis -o cat | portcullis audit
```

```text
demo-app-1 (3 denied or would-be-denied connections)
  portcullis.egress.example-com=host:example.com,tcp:443
```

The suggestions describe what happened, not what should happen: review them before you use them. See [Rolling out a policy](/guides/rollout/) for what `audit` folds together and what it leaves out.

## 5. Enforce

Add the label to the service, and switch the network to `portcullis.enable=true`:

```yaml title="docker-compose.yml" ins={5-6} ins="portcullis.enable=true"
services:
  app:
    image: alpine:3
    command: sh -c 'while true; do wget -qO /dev/null https://example.com; sleep 30; done'
    labels:
      - portcullis.egress.example-com=host:example.com,tcp:443
    networks: [demo]

networks:
  demo:
    labels:
      - portcullis.enable=true
```

Docker only sets a network's labels when it creates it, so recreate the project:

```bash
docker compose down
docker compose up -d
```

Then turn off global monitor mode, which overrides every network's label, and restart:

```toml title="/etc/portcullis/config.toml"
monitor = false
```

```bash
sudo systemctl restart portcullis
```

## 6. Check it

The allowed destination works, anything else fails at once:

```bash
docker compose exec app wget -qO /dev/null https://example.com && echo allowed
docker compose exec app wget -qO /dev/null https://example.org
```

The second command fails with "Host is unreachable": denied traffic is answered with an ICMP error unless `deny-action = "drop"`. The denial shows up in `portcullis watch` as `DENIED egress ...`, and, if you configure one, runs the [alert command](/guides/events-and-alerts/#alerts).

## Next

- Roll out on hosts that already run services without recreating their networks: [Rolling out a policy](/guides/rollout/).
- Write the rest of the policy: [ICC](/policy/icc/) for traffic between containers, [DNS](/policy/dns/) for resolvers, [domains](/policy/domains/) for the names a container may look up.
- Make sure the rules are in place at boot, before Docker starts any container: [Running as a service](/guides/service/).
