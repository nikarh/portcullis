# Portcullis

[![CI](https://github.com/nikarh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/portcullis/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portcullis.svg)](https://crates.io/crates/portcullis)
[![Docs.rs](https://docs.rs/portcullis/badge.svg)](https://docs.rs/portcullis)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Host-level egress policy controller for Docker containers.

Portcullis reads container labels, compiles egress allowlists, resolves hostname targets with a bounded TTL cache, and applies firewall policy using `nftables` or `iptables`.

## Why
Container workloads usually have broad outbound access by default. Portcullis enforces least-privilege egress so containers can only reach explicitly allowed destinations.

## Current Status
Prototype implementation in Rust.

Implemented:
- Docker container/network discovery from labels and runtime metadata.
- Docker network support is currently limited to `bridge` driver networks.
- Label-based egress policy parsing (`ip/cidr + ports`, `host + ports`).
- ICC allowlist parsing (`container|name|alias + ports`) in `allow-listed` mode.
- DNS resolution cache with TTL + max size + eviction.
- Firewall backends:
- `nftables` via `libnftables`
- `nftables` via CLI runner
- `iptables` adapter (uses `iptables` + `ipset`)
- Runtime backend auto-selection from Docker info:
- Docker reports `nftables` => use nftables (lib backend)
- Docker reports `iptables` => use iptables backend
- Long-running daemon mode:
- Startup cleanup to recover from unclean previous exits.
- Continuous Docker container+network event subscription over Docker Unix socket with incremental runtime-state updates for relevant events.
- Graceful cleanup on shutdown (SIGINT/SIGTERM via signal handler).
- Structured logging with `info` / `debug` / `trace` levels.

## Architecture

### High-level flow
```mermaid
flowchart LR
  A[Docker Runtime] --> B[Monitor]
  B --> C[Policy Compiler]
  C --> D[DNS Resolver + TTL Cache]
  D --> E[Firewall Planner]
  E --> F[nftables or iptables Adapter]
  F --> G[Host Network Rules]
```

### Runtime components
- `monitor`: Docker discovery via Docker Engine HTTP API over Unix socket (`/containers/json?all=1`, `/containers/{id}/json`, `/networks`, `/networks/{id}`, `/info`).
- `labels`: policy parsing from `portcullis.*` labels.
- `dns`: bounded hostname->IP cache (TTL + max-size eviction).
- `firewall`: backend adapters for nftables and iptables.
- iptables hook point: `DOCKER-USER` chain (Docker-compatible user policy chain).
- nftables hook point: dedicated base chain on `forward` hook with priority `-1` (before Docker's default forward filter priority).

## How It Works
1. On startup, detect firewall backend and run cleanup of managed rules/chains/tables.
2. Collect container metadata and labels from Docker.
3. Parse labels into normalized egress rules.
4. Resolve hostname targets and cache resulting IPs.
5. Generate backend-specific firewall operations.
6. Apply default-deny egress plus explicit allow rules.
7. Enter event loop, update only affected container/network runtime objects, then refresh policy.
8. On shutdown, attempt cleanup of managed rules/chains/tables.

## Quick Start

### Build
```bash
cargo build --release
```

### Run
```bash
./target/release/portcullis \
  --docker-socket /var/run/docker.sock \
  --firewall-backend auto \
  --log-level info
```

## CLI
```text
portcullis [--docker-socket <path>] [--firewall-backend <auto|nftables|iptables>] [--log-level <error|warn|info|debug|trace>] [--fail-closed]
```

Options:
- `--docker-socket`: Docker Unix socket path. Default: `/var/run/docker.sock`
- `--firewall-backend`: `auto`, `nftables`, or `iptables`. Default: `auto`
- `--log-level`: `error|warn|info|debug|trace`. Default: `info`
- `--fail-closed`: force default-deny for all discovered containers, even without labels.

## Labels

Prefix: `portcullis.*`

- Enable policy:
```text
portcullis.enable=true
```

- Static target:
```text
portcullis.egress.0=ip:1.1.1.1/32,tcp:443
```

- Hostname target:
```text
portcullis.egress.1=host:api.example.com,tcp:443
```

- ICC mode:
```text
portcullis.icc.mode=allow|deny|allow-listed
```

- ICC allowlist entry (used when `icc.mode=allow-listed`):
```text
portcullis.icc.allow.0=container:db,tcp:5432
```

- DNS policy entries (per container):
```text
portcullis.dns.0=docker
portcullis.dns.1=host
portcullis.dns.2=runtime
portcullis.dns.3=ip:1.1.1.1
portcullis.dns.4=*
portcullis.dns.host.0=192.168.1.1
portcullis.dns.host.1=8.8.8.8
```

DNS entry meanings:
- `docker`: allow Docker internal resolver endpoint for that attachment (gateway-derived).
- `host`: allow only IPs explicitly defined via `portcullis.dns.host.<n>=<ip>`.
- `runtime`: allow DNS configured via container runtime (`docker run --dns` / Compose `dns`).
- `ip:<addr>`: allow a specific resolver IP.
- `*`: allow DNS to any destination (`udp/53` and `tcp/53`).

Default when no `portcullis.dns.*` labels are set:
- `docker` only, plus explicit drop of any other DNS destination.

- Network-level default deny (set on Docker network):
```text
portcullis.network.enforce=true
```

When enabled on a Docker network, Portcullis adds a baseline deny for that network subnet.
Only `bridge` driver networks are currently supported for network-level enforcement.
Labeled container allow rules are still added and evaluated first.

Implicit behavior:
- When policy is enabled for a container, Portcullis automatically allows DNS to that container's Docker network gateway on `udp/53` and `tcp/53`.

ICC target lookup notes:
- `container:<value>` is resolved from Docker runtime metadata, not DNS.
- `<value>` can be container ID, container name, or network alias.

## Docker Compose Examples

### HTTPS-only egress
```yaml
services:
  app:
    image: ghcr.io/acme/app:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=ip:1.1.1.1/32,tcp:443"
```

### Hostname allowlist + DNS
```yaml
services:
  api-client:
    image: ghcr.io/acme/client:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=host:api.stripe.com,tcp:443"
      - "portcullis.egress.1=ip:10.96.0.10/32,udp:53"
```

### ICC deny mode
```yaml
services:
  internal-service:
    image: ghcr.io/acme/internal:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.icc.mode=deny"
      - "portcullis.egress.0=host:telemetry.acme.io,tcp:443"
```

### ICC allowlist by alias
```yaml
services:
  api:
    image: ghcr.io/acme/api:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.icc.mode=allow-listed"
      - "portcullis.icc.allow.0=container:db,tcp:5432"
      - "portcullis.icc.allow.1=container:redis,tcp:6379"

  db:
    image: postgres:16
    networks:
      default:
        aliases: [db]

  redis:
    image: redis:7
    networks:
      default:
        aliases: [redis]
```

## Logging
- `info`: operational lifecycle activity (startup cleanup, snapshot/apply, backend selection, event-triggered refresh)
- `debug`: runtime change details
- `trace`: exact firewall command arrays executed and full event/snapshot payloads

## DNS Cache Notes
- Cache stores hostname -> `Arc<[IpAddr]>`.
- TTL expiration and max-size eviction prevent unbounded growth.
- Cache hits return cached addresses without re-resolving.

## Limitations
- Prototype quality, not fully production hardened.
- Docker network handling currently supports only `bridge` driver networks; other drivers are ignored.
- DNS path currently resolver-driven (not a full packet-level DNS proxy listener yet).
- Backend behavior differences can exist between `nftables` and `iptables` edge cases.

## License
Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Documentation
Detailed technical docs are in:
- `docs/PORTCULLIS.md`
