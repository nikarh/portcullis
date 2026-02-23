# Portcullis: Technical Documentation

## 1. What Portcullis Is
Portcullis is a host-side Rust daemon that enforces **container egress allowlists** using Linux firewall primitives.

It is designed for Docker workloads where applications should not have unrestricted outbound network access.

At a high level, Portcullis does this:
1. Reads container metadata and labels from Docker.
2. Compiles those labels into egress policy.
3. Resolves hostname-based rules into IP addresses (with bounded TTL cache).
4. Applies low-level firewall rules so only allowed destinations/ports are reachable.

---

## 2. Why It Was Written
Most container stacks default to broad egress access. This creates risk:
- accidental data exfiltration,
- unexpected third-party dependencies,
- malware command-and-control reachability,
- poor auditability of outbound traffic.

Portcullis exists to provide:
- **default-deny egress** for managed containers,
- explicit allowlists close to the workload definition,
- deterministic, automatable host firewall enforcement.

---

## 3. Primary Goals
1. **Least privilege networking**
- Containers should only talk to explicitly allowed targets.

2. **Policy close to workloads**
- Policy is attached to containers via labels (Traefik-like style).

3. **Backend separation**
- Runtime discovery, DNS resolution, and firewall application are separate concerns.

4. **Operational transparency**
- High-volume trace logs for deep debugging.
- Info-level logs for operational activity.

5. **Bounded DNS memory usage**
- Hostname resolution cache has TTL and max size.

---

## 4. Current Shortcomings and Tradeoffs
1. **Prototype maturity**
- This is a prototype implementation, not production-hardened yet.

2. **DNS behavior**
- Uses resolver-based hostname lookup with cache, not yet a full packet-level DNS proxy listener.

3. **Rule lifecycle complexity**
- Hostname-to-IP mappings are dynamic; long-running environments need robust reconciliation and garbage collection strategy.

4. **Backend parity**
- nftables and iptables behavior may differ in edge cases due to backend semantics.

5. **Operational safeguards**
- Additional hardening is still needed for HA operation, rollback guarantees, and advanced telemetry.

---

## 5. How It Works (Technical Flow)

### 5.1 Runtime Discovery
- `monitor` module talks directly to Docker Engine HTTP API over the configured Unix socket:
- `GET /containers/json`
- `GET /containers/{id}/json`
- `GET /networks/{id}`
- `GET /info` (for firewall backend detection)

Collected data includes:
- container IDs and names,
- labels,
- attached network addresses,
- network subnets,
- Docker firewall backend (`nftables` or `iptables`).

### 5.2 Policy Parsing
- `labels` module parses labels under `portcullis.*`.
- Main concepts:
- `portcullis.enable=true`
- `portcullis.egress.<n>=ip:<cidr>,<proto:port>[,<proto:port>...]`
- `portcullis.egress.<n>=host:<fqdn>,<proto:port>[,<proto:port>...]`
- `portcullis.icc.mode=allow|deny|allow-listed`
- `portcullis.icc.allow.<n>=container:<id|name|alias>,<proto:port>[,<proto:port>...]`

Policy compile output is normalized into strongly typed rules.

### 5.3 DNS Cache and Resolution
- `dns` module provides `DnsProxyCache` implementing `HostnameIpResolver`.
- Behavior:
- TTL-based expiration,
- maximum cache size,
- LRU-style eviction,
- cache-hit fast path returns cached `Arc<[IpAddr]>`.

Allocation notes (important):
- On miss:
- allocate `Vec<IpAddr>` from upstream resolution,
- allocate one `Arc<[IpAddr]>` for cached entry,
- allocate key strings for map/LRU bookkeeping.
- On hit:
- no new IP vector; only cheap `Arc` clone and LRU touch.

### 5.4 Firewall Application
Portcullis chooses firewall backend at runtime:
- Docker reports `nftables` -> use nftables adapter (libnftables backend).
- Docker reports `iptables` -> use iptables adapter.

Rules are generated from:
- static IP/CIDR rules,
- resolved hostname IPs,
- container source identity,
- ICC mode.

ICC allowlist resolution details:
- `container:<value>` in ICC allowlist is resolved from Docker discovery data, not DNS.
- Matching keys include:
- container ID,
- container name (`/name` and `name`),
- Docker network aliases from endpoint metadata.

### 5.5 Logging Model
- `info`: major lifecycle activity and selections (startup cleanup, backend selection, snapshot/apply, refresh triggers).
- `debug`: runtime change details.
- `trace`: full snapshots, DNS cache internals, resolved address lists, full rule payloads, and executed firewall command arrays.

---

## 6. Internal API (Rust Modules)

## 6.1 `model`
Core types:
- `RuntimeSnapshot`
- `ContainerSnapshot`
- `ContainerPolicy`
- `EgressRule`
- `EgressTarget`
- `IccMode`

## 6.2 `labels`
Main API:
- `parse_policy(labels: &BTreeMap<String, String>) -> Result<Option<ContainerPolicy>, LabelParseError>`

## 6.3 `monitor`
Main interfaces:
- `trait DockerApi`
- `struct CommandDockerApi<R: CommandRunner>`
- `struct DockerMonitor<A: DockerApi>`
- `RuntimeChangeTracker` for change detection/logging

## 6.4 `dns`
Main interfaces:
- `trait HostnameIpResolver`
- `trait UpstreamResolver`
- `struct DnsProxyCache<R: UpstreamResolver>`
- `struct SystemUpstreamResolver`

## 6.5 `firewall`
Backend adapters:
- nftables:
- CLI runner and libnftables runner.
- iptables:
- adapter with iptables/ipset oriented command generation.

High-level usage pattern:
1. Build/obtain `RuntimeSnapshot`.
2. Resolve DNS-backed hostname rules.
3. Apply backend-specific rules.

---

## 7. Binary CLI
Portcullis binary accepts:
- `--docker-socket <path>`
- Path to Docker Unix socket.
- `--firewall-backend <auto|nftables|iptables>`
- `auto` selects backend based on Docker-reported firewall backend.
- `--log-level <error|warn|info|debug|trace>`
- Sets log verbosity.

Example:
```bash
portcullis \
  --docker-socket /var/run/docker.sock \
  --firewall-backend auto \
  --log-level trace
```

---

## 8. Policy Label Reference

### 8.1 Enable Policy
```text
portcullis.enable=true
```

### 8.2 Static CIDR Rule
```text
portcullis.egress.0=ip:1.1.1.1/32,tcp:443
```

### 8.3 Hostname Rule
```text
portcullis.egress.1=host:api.example.com,tcp:443
```

### 8.4 Multiple Ports
```text
portcullis.egress.2=ip:10.0.0.0/8,tcp:443,udp:53
```

### 8.5 ICC Mode
```text
portcullis.icc.mode=deny
```

### 8.6 ICC Allowlist Entry
```text
portcullis.icc.allow.0=container:db,tcp:5432
```

Behavior in `allow-listed` mode:
- allow only listed `container:port` ICC flows,
- deny other ICC flows between managed containers.

---

## 9. Docker Compose Examples

## 9.1 Minimal: HTTPS-Only Egress
```yaml
services:
  app:
    image: ghcr.io/acme/app:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=ip:1.1.1.1/32,tcp:443"
```

## 9.2 DNS + API Hostname
```yaml
services:
  api-client:
    image: ghcr.io/acme/client:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=host:api.stripe.com,tcp:443"
      - "portcullis.egress.1=ip:10.96.0.10/32,udp:53"
```

## 9.3 Multiple Destinations and Protocols
```yaml
services:
  worker:
    image: ghcr.io/acme/worker:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=host:s3.amazonaws.com,tcp:443"
      - "portcullis.egress.1=ip:169.254.169.254/32,tcp:80"
      - "portcullis.egress.2=ip:10.10.0.0/16,tcp:5432"
```

## 9.4 ICC Restricted
```yaml
services:
  internal-service:
    image: ghcr.io/acme/internal:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.icc.mode=deny"
      - "portcullis.egress.0=host:telemetry.acme.io,tcp:443"
```

## 9.5 ICC Allowlist Using Aliases
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

## 9.6 Mixed Workloads (Managed + Unmanaged)
```yaml
services:
  managed:
    image: ghcr.io/acme/managed:latest
    labels:
      - "portcullis.enable=true"
      - "portcullis.egress.0=host:api.github.com,tcp:443"

  unmanaged:
    image: alpine:latest
    command: ["sh", "-c", "sleep infinity"]
    # No portcullis labels -> not managed by Portcullis policy pipeline
```

---

## 10. Operational Recommendations
1. Start in `--log-level debug` in non-prod first; use `trace` only during deep diagnostics.
2. Validate generated rules in staging with representative DNS churn.
3. Keep policy explicit and small; avoid broad CIDRs where possible.
4. Monitor cache behavior (hit/miss, evictions) to tune TTL and max size.
5. Add CI integration tests against your exact Docker/firewall backend combination.

---

## 11. Future Work
1. Full UDP/TCP DNS proxy listener path.
2. Stronger transactional firewall updates and rollback guarantees.
3. Advanced metrics endpoint for cache/rule/reconcile internals.
4. Better lifecycle management for backend-specific hostname/IP sets.
5. Podman runtime provider implementation using the same abstraction.
