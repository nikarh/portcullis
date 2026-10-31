# Portcullis

[![CI](https://github.com/nikarh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/portcullis/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portcullis.svg)](https://crates.io/crates/portcullis)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Portcullis limits what Docker containers can connect to, using labels on your networks and containers.

## Why

By default a container can open connections to any address on the internet and to every other container on its network. That is convenient until one of them is compromised or misbehaves, and then nothing stops it from talking to whatever it wants. Docker has no built-in way to say "this service may only reach `api.stripe.com` on port 443 and the database on 5432". Portcullis adds that: you mark a network as enforced, every container on it loses outbound access by default, and each container gets back the destinations its labels list. The policy lives next to the service definition in your Compose file, so it is reviewed and versioned with everything else. Before enforcing anything, Portcullis can run in monitor mode and report every connection a policy would deny, so the labels can be written from what the services actually do.

## How it works

Portcullis is a daemon that runs on the Docker host. It watches the Docker API for containers and networks, turns their labels into firewall rules, and rebuilds the rules whenever something changes. Each rebuild replaces the whole ruleset in one atomic step, so there is never a moment with half-applied rules.

The rules are nftables rules, kept in two tables of its own: an `inet` table for traffic leaving a container's network, and a `bridge` table for traffic between containers on the same network. A Linux bridge passes that traffic directly between containers, without the IP-level hooks Docker's own rules use, so only the bridge table can see it. Both work next to Docker's rules whether Docker itself uses iptables or nftables.

Portcullis only removes access. Traffic that a policy allows still goes through Docker's own rules afterwards, so things Docker blocks (internal networks, isolation between networks) stay blocked.

Every decision can be reported. The rules log what they allow and deny to Portcullis, and Portcullis looks at the DNS answers containers receive, so its events name the container, the destination and, where it can tell, the domain.

## Usage

### Requirements

- Linux, with Portcullis running as root (it needs to manage the firewall and read the Docker socket).
- Docker with bridge networks.
- `libnftables`, for both building and running.
- Recommended: a `dns` setting in `/etc/docker/daemon.json` (see [DNS visibility](#dns-visibility)), so Portcullis can see containers' DNS lookups.

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
| `--monitor` | off | Monitor mode on every network: report what would be denied, deny nothing. |
| `--deny-action <reject\|drop>` | `reject` | `reject` answers denied traffic with an ICMP "administratively prohibited" error, so applications fail immediately with "Host is unreachable". `drop` discards it silently, and applications wait for their own timeout. |
| `--log-allowed <always\|monitor\|never>` | `monitor` | Which allowed connections are reported. Denied ones always are. `monitor` reports them on networks in monitor mode only. |
| `--hostname-hold <seconds>` | `3600` | How long an address of a `host:` rule stays allowed after it was last seen, see [Hostname rules](#hostname-rules). |
| `--events-socket <path>` | off | Serve events as JSON lines on a Unix socket. |
| `--alert-exec <command>` | off | Run a command for every denial and warning, see [Alerts](#alerts). |
| `--alert-interval <seconds>` | `600` | Raise the same alert at most once per interval. |
| `--log-format <text\|json>` | `text` | Format of events (stdout) and diagnostic logs (stderr). |
| `--log-level <error\|warn\|info\|debug\|trace>` | `info` | Level of diagnostic logs. `trace` logs every firewall script that gets applied. |

### Rolling out a policy

1. Enable Portcullis on a network in monitor mode with `portcullis.enable=monitor` (see [Enforcing a network](#enforcing-a-network)). Nothing is blocked; every connection that the labels wouldn't allow is reported as `would_deny`.
2. Let the services run for a while, then turn the events into labels:

   ```bash
   journalctl -u portcullis -o cat | portcullis audit
   ```

   ```text
   billing (12 denied or would-be-denied connections)
     portcullis.egress.api-stripe-com=host:api.stripe.com,tcp:443
     portcullis.icc.allow.db=container:db,tcp:5432
       (with portcullis.icc.mode=allow-listed)
   ```

   `audit` reads JSON events (`--log-format json`) from a file or stdin and ignores other lines. Review the suggestions before using them: they describe what happened, not what should happen.
3. Add the labels and switch the network to `portcullis.enable=true`. From then on every denial is reported as `denied` and raises an [alert](#alerts).

### Events

Portcullis writes one event per line to stdout, as text or, with `--log-format json`, as JSON. Diagnostic logs go to stderr. With `--events-socket <path>`, the same JSON events are also served on a Unix socket, for tools such as `portcullis watch --events-socket <path>`, which prints them live as text. The socket is created with mode `0600`, so only its owner (normally root) can connect; change it with `chmod`/`chown` after startup if another user needs access. A client connecting to it first receives the current state.

A connection event:

```json
{"time":"2026-11-02T10:15:30.120Z","event":"connection","verdict":"denied","reason":"egress",
 "container":"billing","network":"backend","protocol":"tcp",
 "source":"172.18.0.2","source_port":40312,"destination":"104.18.3.4","destination_port":443,
 "destination_container":null,"domain":"api.stripe.com","domain_source":"dns",
 "query":null,"detail":null}
```

| Field | Meaning |
|---|---|
| `verdict` | `allowed`, `denied`, or `would_deny` in monitor mode. |
| `reason` | Which part of the policy decided: `egress`, `dns`, `icc` (traffic to a container on the same network), or `source` (a container sending from an address that isn't its own). |
| `destination_container` | For `icc`, the container at the destination. |
| `domain`, `domain_source` | The destination's name, if known: `dns` when the container looked it up and Portcullis saw the answer, `rule` when the address belongs to one of the container's `host:` rules. |
| `query` | For denied DNS queries, the name asked for. |
| `detail` | For `source`, what's wrong, such as which container's address was used. |

Each new connection produces one event; replies and the rest of a connection don't. Other events:

| Event | When |
|---|---|
| `dns` | A container received a DNS answer: the name, its CNAME aliases, the answer addresses and the resolver. |
| `container` | A container address became managed (`action: managed`, with its `mode`) or stopped being managed (`released`). |
| `warning` | `invalid_label`, `invalid_network`, `dns_not_observable` (see [DNS visibility](#dns-visibility)), or `events_lost` (the kernel produced log entries faster than Portcullis read them). |
| `applied` | Rules were updated: the managed container addresses, and hostnames of `host:` rules with no known addresses. It comes after everything else the update caused. |
| `apply_failed` | Updating the rules failed; the previous rules stay in place. |

Portcullis doesn't store events. Send them to whatever already collects your logs (journald, Loki, Elasticsearch, Vector) and search and alert there, or use the alert hook.

### Alerts

`--alert-exec <command>` runs `<command>` with `sh -c` for every `denied` connection, `apply_failed` and `warning`, with the event as one line of JSON on stdin. Monitor mode (`would_deny`) never raises alerts. The same alert (same container, reason, destination and port) is raised at most once per `--alert-interval`. A command that runs longer than 30 seconds is killed.

```bash
portcullis --alert-exec 'curl -s -d @- https://ntfy.example.com/portcullis'
```

### Enforcing a network

Nothing is restricted until you enable Portcullis on a network with a network label:

```text
portcullis.enable=true      # enforce
portcullis.enable=monitor   # report what would be denied, deny nothing
```

Docker only lets you set labels when a network is created. With Compose:

```yaml
networks:
  backend:
    labels:
      - portcullis.enable=true
```

Or by hand:

```bash
docker network create --label portcullis.enable=true backend
```

Every container attached to an enforced network is then restricted (or, in monitor mode, watched), whether or not it has Portcullis labels of its own. `portcullis.enable` only has an effect on networks; on a container it is ignored. A container without labels can talk to other containers on the same network and resolve names through Docker's DNS, and nothing else. Labels on the container open up more.

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

Containers normally resolve names through Docker's DNS server (`127.0.0.11`). It runs inside the container, answers container and service names itself, and forwards everything else:

- If the container has its own DNS servers (`docker run --dns`, Compose `dns:`), Docker forwards to them from the container's address. These queries go through the container's policy.
- Otherwise, if `dns` is set in Docker's `/etc/docker/daemon.json`, Docker forwards to those servers, also from the container's address.
- Otherwise Docker forwards to the host's DNS servers from the host itself (Docker 29; older versions forwarded from the container's address). Portcullis can't see these queries, so such a container can always resolve outside names through Docker's DNS.

Besides that, any DNS query a container sends itself (port 53, UDP and TCP) is denied unless its destination is allowed with:

```text
portcullis.dns.<name>=<target>
```

| Target | Allows DNS to |
|---|---|
| `docker` | the servers Docker's DNS forwards to for this container: its own DNS servers if it has any, otherwise the daemon-wide ones, otherwise the host's. This is the default when no `portcullis.dns.*` label is set. |
| `host` | the host's DNS servers. |
| `ip:<address>` | that resolver, for example `ip:1.1.1.1`. |
| `*` | any resolver. |
| `none` | nothing. |

Setting any `portcullis.dns.*` label replaces the default. The host's DNS servers are the `nameserver` entries of the host's `/etc/resolv.conf`, or of `/run/systemd/resolve/resolv.conf` when the former only points at systemd-resolved's local stub; loopback addresses are left out. They are read again on every rule update.

Some common setups:

| Goal | Container DNS servers | Labels |
|---|---|---|
| Resolve through the host's DNS only | not set | none needed (add `portcullis.dns.0=host` to also allow direct queries to the host's servers) |
| Only `1.1.1.1` | `dns: [1.1.1.1]` | `portcullis.dns.0=ip:1.1.1.1` |
| The host's DNS and `1.1.1.1` | not set | `portcullis.dns.0=host`, `portcullis.dns.1=ip:1.1.1.1` |
| Any resolver | any | `portcullis.dns.0=*` |
| Container names only, no outside names | `dns:` set to any address | `portcullis.dns.0=none` |

Since DNS rules are checked before egress rules, an egress label like `ip:1.1.1.1,udp:53` has no effect; use `portcullis.dns.x=ip:1.1.1.1` instead.

#### What can and can't be controlled

DNS labels control:

- which resolvers a container may query directly: the host's, specific addresses, any, or none;
- which resolvers Docker's DNS may forward to, for a container with its own DNS servers (`dns:`).

They can't control:

- lookups Docker's DNS forwards from the host, for a container with neither its own DNS servers nor daemon-wide ones (Docker 29). No container policy applies there, so such a container can always resolve outside names. To restrict name resolution, set `dns` daemon-wide or on the container, and allow only those servers.
- names of other containers and services. Docker's DNS answers them inside the container, so they always resolve.
- which names are looked up. Rules allow or deny resolvers by address, not by domain: a container that may use a resolver can resolve any name through it.
- DNS over TLS or HTTPS. That's ordinary traffic on ports 853 and 443, controlled by egress labels, not DNS labels.

#### DNS visibility

Portcullis can only see a container's lookups when Docker forwards them from the container's address, which means when the container has its own DNS servers or `dns` is set daemon-wide. Seeing them gives events their domains and lets [hostname rules](#hostname-rules) follow exactly what the container was told. The simplest setup is once per host, using the resolver from the host's `resolv.conf` or any other:

```json
{ "dns": ["192.168.1.1"] }
```

in `/etc/docker/daemon.json`, then restart Docker. For containers without it, Portcullis reports a `dns_not_observable` warning when they start.

### Hostname rules

An IP firewall can't match hostnames, so a `host:` rule allows the addresses the hostname resolves to. Portcullis learns them in two ways:

- It inspects DNS answers to managed containers. The firewall holds each answer until Portcullis has added its addresses to the matching `host:` rules (a CNAME the name resolved through also counts), then releases it unchanged. The container can connect to exactly the addresses it was told, including ones that change with every lookup (CDNs, DNS load balancing). Queries still go to the resolver the container uses; Portcullis never answers or changes them.
- When a hostname has no known addresses, Portcullis resolves it itself through the host's resolver. That covers containers that resolved it before Portcullis started, and containers whose lookups it can't see.

An address stays allowed for its DNS TTL, but at least `--hostname-hold` (an hour by default) after it was last seen, because applications often keep using an address longer than its TTL.

If Portcullis stops reading them (after a crash, for example; a clean shutdown removes all rules), held answers are released anyway, so DNS keeps working.

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
      - portcullis.enable=true
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
      - portcullis.enable=true
```

`db` and `redis` can still answer the API's connections; the `deny` mode only stops them from opening their own.

A container that runs its own resolver against a public DNS server:

```yaml
labels:
  - portcullis.dns.0=docker
  - portcullis.dns.1=ip:9.9.9.9
```

## Limitations and details

- IPv6 is not supported, by design. Portcullis uses a network's IPv4 subnet and matches containers by their IPv4 address only, so on a network with IPv6 enabled their IPv6 traffic is not restricted. Don't enable IPv6 on enforced networks.
- Containers can't use addresses that aren't theirs: traffic entering an enforced network's bridge is only accepted from a known container address together with that container's MAC address, and is denied otherwise. A container with the `NET_ADMIN` capability that copies both the address and the MAC of another container on the same network can still pass as it, although both containers then fight over the MAC and their traffic breaks. Closing this would mean tying each address to the container's own port on the bridge, but Docker's API doesn't say which host-side interface belongs to which container, and finding out would mean looking inside every container's network namespace. Don't give `NET_ADMIN` to containers you don't trust on networks with containers whose policy they could borrow.
- A container attached to both an enforced and a non-enforced network is only restricted for traffic it sends from its enforced-network address. Traffic leaving through the other network is not filtered.
- DNS policies can't restrict everything a container resolves; see [What can and can't be controlled](#what-can-and-cant-be-controlled).
- Filtering traffic between containers needs connection tracking for bridged traffic. The kernel loads the `nf_conntrack_bridge` module for this the first time Portcullis installs its rules.
- Rules apply to new connections. Connections that were already open when a policy changed keep working until they close. Replies to incoming connections are always allowed, so published ports keep working.
- A hostname rule allows the hostname's addresses, not the hostname. Any other service on the same addresses (common with CDNs and shared hosting) is reachable too.
- If a hostname has no known addresses, its rules allow nothing until a container looks it up or Portcullis can resolve it. Everything else is applied as usual. Portcullis retries its own lookup every 30 seconds.
- Domains on events are best effort. They are missing for containers whose DNS lookups Portcullis can't see, for connections to addresses obtained some other way, and for HTTPS hostnames (TLS SNI), which Portcullis doesn't look at.
- DNS answers over TCP that span more than one packet aren't inspected; they still reach the container.
- Portcullis uses NFLOG group 4242 and NFQUEUE 4242. Other software on the host must not use the same numbers.
- Invalid labels are logged and ignored, and the rest of the container's labels still apply. Ignoring a label never opens anything up: an invalid `portcullis.icc.mode` counts as `deny`, invalid `portcullis.dns.*` labels leave the container with no DNS instead of the default, and an invalid `portcullis.enable` value on a network enforces it. An enforced network without a usable subnet is logged and not enforced.
- Portcullis removes its rules when it starts and when it stops. Containers are unrestricted while it is not running, and if it crashes, the last rules stay in place until it is started again.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
