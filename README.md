# Portcullis

[![CI](https://github.com/nikarh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/portcullis/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portcullis.svg)](https://crates.io/crates/portcullis)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Portcullis limits what Docker containers can connect to, using labels on your networks and containers.

## Why

By default a container can open connections to any address on the internet and to every other container on its network. That is convenient until one of them is compromised or misbehaves, and then nothing stops it from talking to whatever it wants. Docker has no built-in way to say "this service may only reach `api.stripe.com` on port 443 and the database on 5432". Portcullis adds that: you mark a network as enforced, every container on it loses outbound access by default, and each container gets back the destinations its labels list. The policy lives next to the service definition in your Compose file, so it is reviewed and versioned with everything else.

## How it works

Portcullis is a daemon that runs on the Docker host. It watches the Docker API for containers and networks, turns their labels into firewall rules, and rebuilds the rules whenever something changes. Each rebuild replaces the whole ruleset in one atomic step, so there is never a moment with half-applied rules.

It has two firewall backends: nftables, and iptables (with ipset when it is installed). By default it uses the same one Docker uses. The two backends enforce the same policy, and the labels don't depend on which one runs.

Portcullis only removes access. Traffic that a policy allows still goes through Docker's own rules afterwards, so things Docker blocks (internal networks, isolation between networks) stay blocked.

## Usage

### Requirements

- Linux, with Portcullis running as root (it needs to manage the firewall and read the Docker socket).
- Docker with bridge networks.
- `libnftables`, for both building and running.
- For the iptables backend: `iptables-restore` and `iptables-save`. `ipset` is optional and makes hostname rules cheaper.

### Building

Building needs Rust, the libnftables development headers and clang (used to generate the libnftables bindings).

```bash
cargo build --release
```

The binary is `target/release/portcullis`.

### Running

```bash
sudo ./target/release/portcullis
```

Portcullis runs in the foreground until it gets SIGINT or SIGTERM. On startup and on shutdown it removes all firewall rules it owns.

| Option | Default | Description |
|---|---|---|
| `--docker-socket <path>` | `/var/run/docker.sock` | Docker API socket. A `unix://` prefix is accepted. |
| `--firewall-backend <auto\|nftables\|iptables>` | `auto` | `auto` picks the backend Docker itself uses. |
| `--dns-mode <lazy\|proxy>` | `lazy` | How hostname rules get their addresses, see [Hostname rules](#hostname-rules). |
| `--dns-proxy-bind <ip:port>` | `127.0.0.1:1053` | Where the DNS proxy listens in `proxy` mode. |
| `--log-level <error\|warn\|info\|debug\|trace>` | `info` | `trace` logs every firewall script that gets applied. |

### Enforcing a network

Nothing is restricted until you label a network:

```text
portcullis.network.enforce=true
```

Docker only lets you set labels when a network is created. With Compose:

```yaml
networks:
  backend:
    labels:
      - portcullis.network.enforce=true
```

Or by hand:

```bash
docker network create --label portcullis.network.enforce=true backend
```

Every container attached to an enforced network is then restricted, whether or not it has Portcullis labels of its own. A container without labels can talk to other containers on the same network and send DNS queries to the network's gateway, and nothing else. Labels on the container open up more.

Only bridge networks can be enforced. The default `bridge` network can't be, because it can't be given labels.

### Allowing outbound connections

Each allowed destination is one label:

```text
portcullis.egress.<name>=<target>,<protocol>:<port>[,<protocol>:<port>...]
```

`<name>` is any string that makes the label key unique, for example `0`, `1` or `stripe`. The target is one of:

- `ip:<address>` or `ip:<cidr>`, for example `ip:1.1.1.1` or `ip:10.0.0.0/8`.
- `host:<hostname>`, for example `host:api.stripe.com`. See [Hostname rules](#hostname-rules) for how the name is resolved.

Ports are `tcp:<port>` or `udp:<port>`, at least one per label. There are no port ranges and no "any port" option.

```yaml
labels:
  - portcullis.egress.stripe=host:api.stripe.com,tcp:443
  - portcullis.egress.ntp=ip:162.159.200.1,udp:123
  - portcullis.egress.internal=ip:10.20.0.0/16,tcp:80,tcp:443
```

Egress labels don't apply to DNS (port 53) or to containers on the same network. DNS is controlled by the [DNS labels](#dns), and containers on the same network by the [ICC mode](#traffic-between-containers). Both are checked first.

### Traffic between containers

ICC (inter-container communication) covers traffic from a container to other containers on the same enforced network. Set the mode with:

```text
portcullis.icc.mode=allow|deny|allow-listed
```

- `allow` (the default) lets the container reach every container on its networks.
- `deny` blocks all of it.
- `allow-listed` blocks all of it except the entries you list:

```text
portcullis.icc.allow.<name>=container:<target>,<protocol>:<port>[,<protocol>:<port>...]
```

The target is matched the way Docker's DNS resolves names from the source container:

- It matches a container name or a network alias. Compose gives every container its service name as an alias, so `container:db` works for a service called `db`, even though the container itself is named something like `myproject-db-1`.
- Only containers on a network the source container is also on can match, and only their addresses on that shared network are allowed.
- If several containers match (a service scaled to more than one replica), all of them are allowed.

Container IDs are not accepted, since they change every time a container is recreated.

The mode only controls connections the container starts. Whether others can reach it is decided by their own labels.

### DNS

DNS queries (port 53, UDP and TCP) from a container are dropped unless their destination is allowed with:

```text
portcullis.dns.<name>=<target>
```

| Target | Allows DNS to |
|---|---|
| `docker` | the gateway address of the container's network. This is the default when no `portcullis.dns.*` label is set. |
| `runtime` | the servers set with `docker run --dns` or Compose `dns:`. |
| `ip:<address>` | that resolver, for example `ip:1.1.1.1`. |
| `*` | any resolver. |

Setting any `portcullis.dns.*` label replaces the default, so add `docker` explicitly if you still want it. Since DNS rules are checked before egress rules, an egress label like `ip:1.1.1.1,udp:53` has no effect; use `portcullis.dns.x=ip:1.1.1.1` instead.

Docker's own DNS server (`127.0.0.11`) runs inside the container. Names it can't answer itself it forwards to the upstream servers from the host's `resolv.conf`, or to the ones set with `--dns`, and those forwarded queries can leave from the container's address. They are then subject to these rules. If name resolution stops working on an enforced network, allow the upstream servers with `ip:` or `runtime`.

### Hostname rules

An IP firewall can't match hostnames, so a `host:` rule is turned into the addresses the hostname resolves to. `--dns-mode` decides where those addresses come from.

`lazy` (the default) needs no setup. Portcullis resolves each hostname itself, using the host's resolver, when it builds the rules, and re-resolves all of them every 30 seconds. Results are cached for 5 minutes. Portcullis and the container may not get the same answer, though. Services behind CDNs or DNS load balancing often return different addresses on each lookup, and then the container ends up connecting to an address the firewall doesn't allow.

`proxy` fixes that by making Portcullis the container's DNS server. When a container looks up a hostname used in a policy, Portcullis resolves it, adds the addresses to the firewall, and only then sends the answer back. The container can only connect to addresses it got from that lookup, and those are always allowed. To use it:

1. Bind the proxy to an address containers can reach, such as the gateway of an enforced network. The default `127.0.0.1:1053` is not reachable from containers.
2. Point the containers' DNS at it.

```bash
portcullis --dns-mode proxy --dns-proxy-bind 172.30.0.1:53
```

```yaml
services:
  app:
    dns: [172.30.0.1]
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443

networks:
  backend:
    ipam:
      config:
        - subnet: 172.30.0.0/24
    labels:
      - portcullis.network.enforce=true
```

The network has to exist before Portcullis starts, otherwise there is no gateway address to bind to.

In proxy mode a hostname rule allows nothing until a container has looked the name up through the proxy. The proxy answers only A and AAAA queries; other record types get an empty answer.

### Examples

A service that may only call one external API:

```yaml
services:
  billing:
    image: ghcr.io/acme/billing:latest
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443

networks:
  backend:
    labels:
      - portcullis.network.enforce=true
```

An API that may reach its database and cache but nothing else on the network, and a database with no outbound access at all:

```yaml
services:
  api:
    image: ghcr.io/acme/api:latest
    networks: [backend]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432
      - portcullis.icc.allow.cache=container:redis,tcp:6379
      - portcullis.egress.telemetry=host:telemetry.acme.io,tcp:443

  db:
    image: postgres:16
    networks: [backend]
    labels:
      - portcullis.icc.mode=deny

  redis:
    image: redis:7
    networks: [backend]
    labels:
      - portcullis.icc.mode=deny

networks:
  backend:
    labels:
      - portcullis.network.enforce=true
```

`db` and `redis` can still answer the API's connections; the `deny` mode only stops them from opening their own.

A container that runs its own resolver against a public DNS server:

```yaml
labels:
  - portcullis.dns.0=docker
  - portcullis.dns.1=ip:9.9.9.9
```

## Limitations and details

- IPv6 is not supported, by design. Containers are matched by their IPv4 address only, so on a network with IPv6 enabled their IPv6 traffic is not restricted. Don't enable IPv6 on enforced networks.
- Only the first subnet configured on a network is used.
- A container attached to both an enforced and a non-enforced network is only restricted for traffic it sends from its enforced-network address. Traffic leaving through the other network is not filtered.
- Rules apply to new connections. Connections that were already open when a policy changed keep working until they close. Replies to incoming connections are always allowed, so published ports keep working.
- A hostname rule allows the hostname's addresses, not the hostname. Any other service on the same addresses (common with CDNs and shared hosting) is reachable too.
- If a hostname can't be resolved, Portcullis logs an error and its rules allow nothing until it resolves again. Everything else is applied as usual. Failed lookups are retried every 30 seconds.
- Invalid labels are logged and ignored, and the rest of the container's labels still apply. Ignoring a label never opens anything up: an invalid `portcullis.icc.mode` counts as `deny`, invalid `portcullis.dns.*` labels leave the container with no DNS instead of the default, and an invalid `portcullis.network.enforce` value enforces the network. An enforced network without a usable subnet is logged and not enforced.
- Portcullis removes its rules when it starts and when it stops. Containers are unrestricted while it is not running, and if it crashes, the last rules stay in place until it is started again.
- With the iptables backend and no `ipset`, every hostname rule becomes one firewall rule per resolved address.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
