---
title: Limitations
description: What Portcullis doesn't do, by design or by the nature of an IP firewall, and the details that follow from it.
sidebar:
  order: 1
---

[Limits and workarounds](/limits/escape-hatches/) has what to do about each of these.

## By design

- IPv6 is not supported. Portcullis uses a network's IPv4 subnet and matches containers by their IPv4 address only. IPv6 traffic entering an enforced network's bridge is denied, so containers on an enforced network with IPv6 enabled can't use it at all.
- Only bridge networks. Overlay, macvlan, ipvlan and host networking aren't covered, and the default `bridge` network can only be monitored.
- Only outbound connections. Egress labels limit the connections a container opens. A container with a published port can exchange data with anyone allowed to connect to it: replies to incoming connections are always allowed.
- Names only where the client sends them in the clear. A `host:` rule checks the name a TLS, HTTP or QUIC connection asks for (see [Names connections ask for](/policy/hostnames/#names-connections-ask-for)), not what it does after that, and allows connections that name nothing (other protocols, TLS without a server name, other UDP) by address, unless names are checked [strictly](/policy/hostnames/#strict-name-checks). By address, any other service on the same addresses that is reached that way (common with CDNs and shared hosting) is reachable too; see [Names](#names). A pattern allows every name it matches: under a domain where anyone can create names (`*.cloudfront.net`, `*.github.io`), that is anyone's server.

## What a container can still do

- `NET_RAW` (which Docker grants by default) and `NET_ADMIN` still let a container do things no firewall rule can stop, even though Portcullis keeps them from getting past its rules and reports their attempts. With a raw socket, a container can flood its network until it is [quarantined](/policy/limits/#quarantine), and use bandwidth and CPU with traffic its rules allow. It can also see broadcast and multicast traffic of its network, as any container can. With `NET_ADMIN` it can change its own interfaces and routes; Portcullis then denies whatever doesn't match the container's address and MAC, but the container can still disturb its own traffic. Drop `NET_RAW` from containers that don't need it (`cap_drop: [NET_RAW]` in Compose; `ping` is about the only common tool that needs it), and don't give `NET_ADMIN` to containers you don't trust.
- Containers can't use addresses that aren't theirs: traffic entering an enforced network's bridge is only accepted with a known container's address and MAC, from that container's port on the bridge. If Portcullis can't find a container's port because it can't identify the container's network namespace, or Docker didn't report it (it logs a warning, once), that container's traffic is only checked by address and MAC, which another container with a raw socket can copy.
- ARP reaches other containers of the network whatever their ICC rules: containers need it to find each other and the gateway. Portcullis only lets plain ARP requests and replies with the container's own address and MAC through, but two containers that both have a raw socket can still pass a few bytes per frame in the fields ARP itself has, such as the address a request asks about.
- A container attached to both an enforced and a non-enforced network is only restricted for traffic it sends from its enforced-network address. Traffic leaving through the other network is not filtered.
- DNS policies can't restrict everything a container resolves; see [What can and can't be controlled](/policy/dns/#what-can-and-cant-be-controlled).

## Timing

- A network is enforced once Portcullis has seen it created, which usually takes milliseconds. Until then, its traffic isn't filtered at all. Containers that start on a brand-new network can get packets out in that window, for example when `docker compose up` creates the network and starts its containers right away. Create enforced networks ahead of time to close it; see [When enforcement starts](/policy/networks/#when-enforcement-starts).
- Rules apply to new connections. Connections that were already open when a policy changed keep working until they close, as long as the container keeps its address and MAC. Replies to incoming connections are always allowed, so published ports keep working.
- If a hostname has no known addresses, its rules allow nothing until a container looks it up or Portcullis can resolve it. Everything else is applied as usual. Portcullis looks it up again every 30 seconds while the host's resolver doesn't answer, and four times per hold (every 15 minutes by default) while it says the name doesn't exist.
- A rule update doesn't wait for Portcullis's own first lookup of a hostname no rule used before; the lookup follows right after it, usually within milliseconds. A container whose lookups Portcullis [can't see](/policy/dns/#dns-visibility) and that connects to such a name right after starting can be denied until that lookup returns, if its own lookup answers first. A container whose lookups Portcullis sees isn't affected: its answer is held until the addresses in it are allowed. So always put a resolver whose answers Portcullis sees in front of containers with `host:` rules: Docker's DNS server with `dns` set in `/etc/docker/daemon.json` (see [DNS visibility](/policy/dns/#dns-visibility)), or a resolver container of your own ([Your own resolver](/examples/own-resolver/)). Then the race can't happen, and Portcullis gets the exact addresses each container was told.
- After a reboot, the rules put back from the saved copy have no hostname addresses (those may be days old), so hostname rules allow nothing until Portcullis's first lookups return, or until a container looks the name up.
- An application that keeps an address DNS no longer returns is denied once the address's [hold](/policy/hostnames/#how-long-an-address-stays-allowed) runs out, for new connections. That happens with names that return a different part of a pool at every lookup, to an application that resolves once and keeps one address for longer than the hold.
- While Portcullis isn't running, its last rules stay in force (by default) but nothing is updated or reported; see [While Portcullis isn't running](/guides/service/#while-portcullis-isnt-running). With `on-exit = "remove"`, containers are unrestricted while it isn't running.

## Names

What `host:` rules check, and what they can't:

- Inside TLS, an HTTP request can ask for another site on the same server than the server name (domain fronting), and HTTP/2 clients reuse a connection for other names its certificate covers (connection coalescing). Neither can be seen without decrypting the traffic.
- Connections that don't name a server are allowed by address unless names are checked strictly: other protocols, TLS without a server name, HTTP/2 without TLS, UDP other than QUIC. Protocols that start TLS later (SMTP and IMAP with STARTTLS, MySQL) are among them: their server name comes after their first bytes, and isn't read. Only Postgres's request for TLS before its ClientHello is understood.
- QUIC's server name is read from the first Initial packets of a UDP flow. Later packets aren't read: a client could start another QUIC connection, for another name, on the same flow.
- A ClientHello with Encrypted Client Hello (ECH) shows the provider's public name, which is checked like any other: such connections are denied unless that name has a rule.
- Plain HTTP stays watched for as long as connection tracking keeps the connection: every packet the client sends with data goes through Portcullis. After an `Upgrade` (WebSocket) or `CONNECT` that is allowed, the rest isn't read; with strict name checks they are denied.
- At most 65536 connections per mode (enforced, monitored) are checked at once, plain HTTP connections included. Beyond that, new connections through `host:` rules are denied, with the detail `too many connections being checked at once`, until others close.
- Data in a SYN (TCP Fast Open) is only allowed when it holds the whole ClientHello or request head.
- A connection whose first bytes don't arrive whole within 3 seconds is denied: they could still turn out to name another site.
- While Portcullis isn't running, new connections through `host:` rules can't get past their handshake. After it restarts, connections through `host:` rules that were still being checked are denied, plain HTTP ones included. Those whose check ended keep going. With [`on-exit = "remove"`](/guides/service/#while-portcullis-isnt-running), nothing is checked while it isn't running.
- Names are only checked for IPv4, as is everything else.

## Reports

- Domains on events are best effort. They are missing for containers whose DNS lookups Portcullis can't see, and for connections to addresses obtained some other way. Connections through `host:` rules have the name they asked for as `name`.
- DNS answers over TCP that span more than one packet aren't inspected; they still reach the container.

## The host

- Filtering traffic between containers needs connection tracking for bridged traffic. The kernel loads the `nf_conntrack_bridge` module for this the first time Portcullis installs its rules.
- Portcullis uses NFLOG group 4242, NFQUEUE 4242 to 4247, packet marks `0x70630001` to `0x70630006`, and four bits of connection marks (`0x00f00000`, [configurable](/reference/host-resources/#connection-marks)). Other software on the host must not use the same numbers. See [Files and kernel resources](/reference/host-resources/).
- Finding new containers without Docker doesn't work with rootless Docker, unusual cgroup layouts, or a wrong `docker-root`; see [Where it doesn't work](/internals/discovery/#where-it-doesnt-work).

## Labels

- Invalid labels are logged and ignored, and the rest of the container's labels still apply. Ignoring a label never opens anything up: an invalid `portcullis.icc.mode` counts as `deny`, invalid `portcullis.dns.*` labels leave the container with no DNS instead of the default, and an invalid `portcullis.enable` value on a network enforces it.
- An enforced network without a usable subnet is logged and not enforced.
- Docker labels can't be changed after a container or network is created: changing a policy means recreating the container, and changing `portcullis.enable` means recreating the network.
- A changed [policy file](/policy/files/) applies to a running container only when it restarts; Portcullis doesn't watch the files. A file that can't be used denies its container everything, and its values are never reported, so a mistake in one shows up as a warning that names the label but not what is wrong with the value.
