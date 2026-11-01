# Portcullis

[![CI](https://github.com/nikarh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/portcullis/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portcullis.svg)](https://crates.io/crates/portcullis)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Portcullis limits what Docker containers can connect to, using labels on your networks and containers.

## Why

By default a container can open connections to any address on the internet and to every other container on its network. That is convenient until one of them is compromised or misbehaves, and then nothing stops it from talking to whatever it wants. Docker has no built-in way to say "this service may only reach `api.stripe.com` on port 443 and the database on 5432". Portcullis adds that: you mark a network as enforced, every container on it loses outbound access by default, and each container gets back the destinations its labels list. The policy lives next to the service definition in your Compose file, so it is reviewed and versioned with everything else. Before enforcing anything, Portcullis can run in monitor mode and report every connection a policy would deny, so the labels can be written from what the services actually do.

## How it works

Portcullis is a daemon that runs on the Docker host. It watches the Docker API for containers and networks, turns their labels into firewall rules, and updates the rules whenever something changes. Each update happens in one atomic step, so there is never a moment with half-applied rules.

The rules are nftables rules, kept in two tables of its own: an `inet` table for traffic leaving a container's network or addressed to the Docker host, and a `bridge` table for everything entering a network's bridge from a container. A Linux bridge passes traffic between containers directly, without the IP-level hooks Docker's own rules use, so only the bridge table can see it. The bridge table is also where Portcullis checks that each frame really comes from the container it claims to come from. Both work next to Docker's rules whether Docker itself uses iptables or nftables.

A container can start sending before Portcullis has seen it start. Its first packets then come from an address the rules don't know yet. Portcullis doesn't deny them: the firewall holds them until the container's rules are in place and then runs them through those rules, so they are allowed or denied as if the rules had been there all along. TCP and UDP are only delayed, not lost. Packets whose source is still unknown after 2 seconds are denied as spoofed (see [Limitations and details](#limitations-and-details)).

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

Portcullis runs in the foreground until it gets SIGINT or SIGTERM. See [Stopping and removing Portcullis](#stopping-and-removing-portcullis) for what happens to its rules then.

| Option | Default | Description |
|---|---|---|
| `--docker-socket <path>` | `/var/run/docker.sock` | Docker API socket. A `unix://` prefix is accepted. |
| `--monitor` | off | Monitor mode on every network: report what would be denied, deny nothing. |
| `--deny-action <reject\|drop>` | `reject` | `reject` answers denied traffic with an ICMP "administratively prohibited" error, so applications fail immediately with "Host is unreachable". `drop` discards it silently, and applications wait for their own timeout. Traffic denied for its source or kind (reasons `source` and `frame`) is always dropped: a rejection would go to an address the sender only claims. |
| `--log-allowed <always\|monitor\|never>` | `monitor` | Which allowed connections and successful DNS lookups are reported. Denied ones always are. `monitor` reports them on networks in monitor mode only. |
| `--hostname-hold <seconds>` | `3600` | How long an address of a `host:` rule stays allowed after it was last seen, see [Hostname rules](#hostname-rules). |
| `--events-socket <path>` | off | Serve events as JSON lines on a Unix socket. |
| `--alert-exec <command>` | off | Run a command for every denial and warning, see [Alerts](#alerts). |
| `--alert-interval <seconds>` | `600` | Raise the same alert at most once per interval. |
| `--log-format <text\|json>` | `text` | Format of events (stdout) and diagnostic logs (stderr). |
| `--log-level <error\|warn\|info\|debug\|trace>` | `info` | Level of diagnostic logs. `trace` logs every firewall script that gets applied. |
| `--on-exit <keep\|remove>` | `keep` | What happens to the firewall rules when Portcullis stops, see [Stopping and removing Portcullis](#stopping-and-removing-portcullis). |

### Stopping and removing Portcullis

By default (`--on-exit keep`), the firewall rules stay in place when Portcullis stops, whether it stops cleanly or crashes. A restart or an upgrade doesn't leave containers unrestricted:

- Containers that were running keep their last rules. Changes to labels, networks and hostname addresses aren't picked up until Portcullis runs again.
- Containers that start on an enforced network in the meantime can't send anything: they have no rules yet, so their packets are held for Portcullis and then dropped by the kernel. They get their rules as soon as Portcullis is back.
- DNS answers are let through without inspection, and nothing is reported.

When Portcullis starts again, its first update replaces the old rules in one step.

To remove the rules, for example after deciding not to use Portcullis anymore, run:

```bash
sudo portcullis cleanup
```

With `--on-exit remove`, Portcullis removes its rules itself, when it starts and when it stops cleanly. Containers are then unrestricted while it isn't running. After a crash the rules stay, as with `keep`.

The rules live in the kernel only, so a reboot removes them either way.

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
| `reason` | Which part of the policy decided: `egress`, `dns`, `icc` (traffic to a container on the same network), `source` (a container sending with an address or MAC that isn't its own, ARP included), or `frame` (a kind of frame enforced networks don't carry, such as IPv6 or VLAN-tagged frames). |
| `protocol` | `tcp`, `udp`, `icmp` or another IP protocol number; for `source` and `frame`, also `arp`, `ipv6` or `ether type 0x....`. |
| `source`, `destination` | The addresses the packet claims. For egress, the destination the container asked for, before Docker's DNAT of published ports. Both are `null` for frames without IP addresses. |
| `container` | The container that sent it. For `source` and `frame`, this is the container behind the bridge port the frame came in on, whatever address or MAC it used. |
| `destination_container` | For `icc`, the container at the destination. |
| `domain`, `domain_source` | The destination's name, if known: `dns` when the container looked it up and Portcullis saw the answer, `rule` when the address belongs to one of the container's `host:` rules. |
| `query` | For denied DNS queries, the name asked for. |
| `detail` | For `source`, what's wrong, such as which container's address was used. |

A flow (container, destination, protocol and port) is reported at most once a minute, however many connections it makes; the kernel filters out repeats before they reach Portcullis. Replies and the rest of a connection are never reported. Other events:

| Event | When |
|---|---|
| `dns` | A container received a DNS answer: the name, its CNAME aliases, the answer addresses and the resolver. Reported where allowed connections are (`--log-allowed`). |
| `container` | A container address became managed (`action: managed`, with its `mode`) or stopped being managed (`released`). |
| `warning` | `invalid_label`, `invalid_network`, `dns_not_observable` (see [DNS visibility](#dns-visibility)), `events_lost` (the kernel produced log entries faster than Portcullis read them), or `alerts_suppressed` (see [Alerts](#alerts)). |
| `applied` | Rules were updated: the managed container addresses, and hostnames of `host:` rules with no known addresses. It comes after everything else the update caused. |
| `apply_failed` | Updating the rules failed; the previous rules stay in place. |

How much is written depends mostly on the mode. In enforce mode with the default `--log-allowed monitor`, only denials are reported, so once the labels are right there is little to nothing. Monitor mode reports every flow and every DNS lookup of the monitored containers; it is meant for rolling out, not to stay on.

Portcullis doesn't store events. Send them to whatever already collects your logs (journald, Loki, Elasticsearch, Vector) and search and alert there, or use the alert hook.

### Alerts

`--alert-exec <command>` runs `<command>` with `sh -c` for every `denied` connection, `apply_failed` and `warning`, with the event as one line of JSON on stdin. Monitor mode (`would_deny`) never raises alerts. The same alert (same container, reason, destination and port) is raised at most once per `--alert-interval`. A command that runs longer than 30 seconds is killed.

A container raises at most 10 alerts per `--alert-interval`. Its tenth comes with an `alerts_suppressed` warning, itself an alert, and from then until the interval ends its denials are only reported as events. A container probing thousands of destinations would otherwise queue thousands of alerts, and every alert after them, of any container, would arrive hours late. At most 256 alerts wait for the command at a time; more are dropped with a log message.

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

The Docker host counts as a destination too. Traffic to any of its addresses (the network's gateway, its other interfaces) follows the egress labels, so a container can't reach services on the host, or other containers' published ports through the host, unless a label allows it:

```yaml
labels:
  - portcullis.egress.host-proxy=ip:172.18.0.1,tcp:3128
```

The gateway's address depends on the network's subnet; give the network a fixed subnet in Compose (`ipam`) to know it in advance.

Rules match the destination a container asked for. Docker reaches a published port through the host with DNAT when its userland proxy is off (`"userland-proxy": false`), and always from other networks, so the packet then goes to the container behind the port. A label naming the host's address and the published port still allows it, and a connection to another container's published port is never mistaken for traffic between containers on the same network.

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

With `deny` and `allow-listed`, broadcast (`255.255.255.255`) and multicast (`224.0.0.0/4`) traffic is blocked too, since the bridge delivers it to every container on the network.

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
- which names are looked up. Rules allow or deny resolvers by address, not by domain: a container that may use a resolver can resolve any name through it. A compromised container can use that to send data out, encoded in the names it looks up, to whoever runs the DNS servers of a domain it chose, through any resolver it may use, Docker's included. Portcullis reports the lookups it sees (`dns` events, with `--log-allowed`), but doesn't stop them.
- what a container sends to port 53. The DNS labels allow traffic to that port, whether or not it is DNS. With `portcullis.dns.x=*`, a container can reach port 53 of any address on the internet, which works as a tunnel to anywhere.
- what a resolver answers. A container that may use a resolver someone else controls (or `*`) can be told any address for any name, and its `host:` rules then allow that address. Only other containers' rules are safe from it.
- DNS over TLS or HTTPS. That's ordinary traffic on ports 853 and 443, controlled by egress labels, not DNS labels.

#### DNS visibility

Portcullis can only see a container's lookups when Docker forwards them from the container's address, which means when the container has its own DNS servers or `dns` is set daemon-wide. Seeing them gives events their domains and lets [hostname rules](#hostname-rules) follow exactly what the container was told. The simplest setup is once per host, using the resolver from the host's `resolv.conf` or any other:

```json
{ "dns": ["192.168.1.1"] }
```

in `/etc/docker/daemon.json`, then restart Docker. For containers without it, Portcullis reports a `dns_not_observable` warning when they start.

### Hostname rules

An IP firewall can't match hostnames, so a `host:` rule allows the addresses the hostname resolves to. Portcullis learns them in two ways:

- It inspects DNS answers to managed containers. The firewall holds each answer until Portcullis has added its addresses to the matching `host:` rules of the container that received it (a CNAME the name resolved through also counts), then releases it unchanged. An answer only counts for that container: a container that may ask a resolver of its choice can't make another container's `host:` rules allow whatever that resolver claims. The container can connect to exactly the addresses it was told, including ones that change with every lookup (CDNs, DNS load balancing). Queries still go to the resolver the container uses; Portcullis never answers or changes them.
- When a hostname has no known addresses, Portcullis resolves it itself through the host's resolver. That covers containers that resolved it before Portcullis started, and containers whose lookups it can't see.

An address stays allowed for its DNS TTL, but at least `--hostname-hold` (an hour by default) after it was last seen, because applications often keep using an address longer than its TTL.

If Portcullis stops reading them (after a crash, for example; a clean shutdown removes all rules), held answers are released anyway, so DNS keeps working.

### Containers trying to get around the rules

Portcullis assumes a container may be compromised and actively try to get past its rules. With Docker's default capabilities, a container can send any frame it likes through a raw socket (`NET_RAW`). Portcullis makes sure that doesn't get it anywhere its labels don't allow, and reports every attempt:

- Every frame entering an enforced bridge has to come from a managed container's own port on the bridge (the host side of its network interface), with that container's MAC and, for IPv4 and ARP, its address. Borrowing another container's address, MAC or both doesn't borrow its rules or its connections. A container can't take over another container's MAC in the bridge's forwarding table, or claim another container's address, or the gateway's, in its neighbours' ARP caches. Portcullis finds each container's port by asking the kernel about the container's network namespace; it never runs anything inside the container.
- Established connections only pass once their source checks out. ICMP errors about a connection are only accepted from one of its two ends, so they can't be used to send data to wherever another container has a connection.
- Enforced bridges only carry IPv4 and ARP. IPv6, VLAN-tagged frames (the receiving container's kernel could unwrap them past the rules) and anything else are denied. So are frames to the link-local group addresses used by STP and LLDP, which the bridge hands to the host past its usual checks.
- Traffic between two containers has to be addressed to their shared network. A frame to another container's MAC addressed to that container's address on another network is denied, even with ICC allowed. Broadcast and multicast count as traffic to other containers.
- Traffic to the Docker host follows the egress labels, and rules see the destination the container asked for, before Docker's DNAT of published ports.
- When Docker gives a removed container's address to a new container, Portcullis deletes the old container's tracked connections first, so the new container can't keep using them.
- Fragmented packets are put back together before the rules look at them, so fragments can't hide or rewrite ports.
- Packets from a port Portcullis doesn't know yet (a container that just started) are held for at most 2 seconds and then denied. Flooding that queue makes the kernel drop them, it never lets them through.
- What a container learns from DNS answers is bounded: at most 4096 addresses per hostname at a time.

Reports can't be flooded away either. A flood of new flows can fill the set Portcullis uses to report each flow once a minute; denials are then still reported, up to 10 a second per rule. A container's alerts are limited as described under [Alerts](#alerts).

A well-behaved container never causes `source` or `frame` events: it sends with its own address and MAC, and Docker doesn't set it up to send IPv6 or VLAN frames on a network without IPv6. Such events are a strong sign that a container is compromised, or at least running tools that craft their own packets. They name the container behind the port the frame came from, whatever address or MAC it used, and raise alerts.

These are covered by the `bypass` end-to-end test scenario. What a firewall can't prevent is listed under [Limitations and details](#limitations-and-details).

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

- IPv6 is not supported, by design. Portcullis uses a network's IPv4 subnet and matches containers by their IPv4 address only. IPv6 traffic entering an enforced network's bridge is denied, so containers on an enforced network with IPv6 enabled can't use it at all.
- Containers can't use addresses that aren't theirs: traffic entering an enforced network's bridge is only accepted with a known container's address and MAC, from that container's port on the bridge. Anything else from a known container's port is denied at once; from a port Portcullis doesn't know yet, it is held for up to 2 seconds, in case it comes from a container that just started, and then denied. If Portcullis can't find a container's port (it logs a warning), that container's traffic is only checked by address and MAC, which another container with a raw socket can copy.
- `NET_RAW` (which Docker grants by default) and `NET_ADMIN` still let a container do things no firewall rule can stop, even though Portcullis keeps them from getting past its rules and reports their attempts. With a raw socket, a container can flood its network, or fill the kernel's connection tracking table, which affects every container on the host. It can also see broadcast and multicast traffic of its network, as any container can. With `NET_ADMIN` it can change its own interfaces and routes; Portcullis then denies whatever doesn't match the container's address and MAC, but the container can still disturb its own traffic. Drop `NET_RAW` from containers that don't need it (`cap_drop: [NET_RAW]` in Compose; `ping` is about the only common tool that needs it), and don't give `NET_ADMIN` to containers you don't trust.
- A container with a published port can exchange data with anyone allowed to connect to it: replies to incoming connections are always allowed. Egress labels limit only the connections a container opens.
- A network is enforced once Portcullis has seen it created, which usually takes milliseconds. Until then, its traffic isn't filtered at all. Containers that start on a brand-new network can get packets out in that window, for example when `docker compose up` creates the network and starts its containers right away. To close it, create enforced networks ahead of time (`docker network create`, or an `external` network in Compose) and start containers on them afterwards. Packets of containers that start on an already enforced network are held until their rules are in place, so nothing gets through there.
- A container attached to both an enforced and a non-enforced network is only restricted for traffic it sends from its enforced-network address. Traffic leaving through the other network is not filtered.
- DNS policies can't restrict everything a container resolves; see [What can and can't be controlled](#what-can-and-cant-be-controlled).
- Filtering traffic between containers needs connection tracking for bridged traffic. The kernel loads the `nf_conntrack_bridge` module for this the first time Portcullis installs its rules.
- Rules apply to new connections. Connections that were already open when a policy changed keep working until they close, as long as the container keeps its address and MAC. Replies to incoming connections are always allowed, so published ports keep working.
- A hostname rule allows the hostname's addresses, not the hostname. Any other service on the same addresses (common with CDNs and shared hosting) is reachable too.
- If a hostname has no known addresses, its rules allow nothing until a container looks it up or Portcullis can resolve it. Everything else is applied as usual. Portcullis retries its own lookup every 30 seconds.
- Domains on events are best effort. They are missing for containers whose DNS lookups Portcullis can't see, for connections to addresses obtained some other way, and for HTTPS hostnames (TLS SNI), which Portcullis doesn't look at.
- DNS answers over TCP that span more than one packet aren't inspected; they still reach the container.
- Portcullis uses NFLOG group 4242 and NFQUEUE 4242 and 4243. Other software on the host must not use the same numbers.
- Invalid labels are logged and ignored, and the rest of the container's labels still apply. Ignoring a label never opens anything up: an invalid `portcullis.icc.mode` counts as `deny`, invalid `portcullis.dns.*` labels leave the container with no DNS instead of the default, and an invalid `portcullis.enable` value on a network enforces it. An enforced network without a usable subnet is logged and not enforced.
- While Portcullis isn't running, its last rules stay in force (by default) but nothing is updated or reported, see [Stopping and removing Portcullis](#stopping-and-removing-portcullis). With `--on-exit remove`, containers are unrestricted while it isn't running.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
