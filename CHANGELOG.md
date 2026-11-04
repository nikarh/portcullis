# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org).

## [0.1.2] - 2026-11-04

### Fixes

- **dns:** Let DNS answers through when Portcullis can't inspect them in time by @nikarh

## [0.1.1] - 2026-11-04

### Features

- **policy:** Add core models and label parser with unit tests by @nikarh
- **monitor:** Add docker-based container and network snapshot monitoring by @nikarh
- **firewall:** Add nftables apply and cleanup backend with tests by @nikarh
- **logging:** Add runtime change and nft execution logging by @nikarh
- **firewall:** Add libnftables backend with bindgen wrapper by @nikarh
- **cli:** Add pico-args runtime config for socket, backend, and log level by @nikarh
- **dns:** Add bounded ttl cache and nft hostname ip set integration by @nikarh
- **firewall:** Add iptables adapter and ICC allowlist by container alias by @nikarh
- **logging:** Log executed firewall commands across all adapters by @nikarh
- **logging:** Align libnftables runner logs with nft cli runner by @nikarh
- **monitor:** Add docker container event polling support by @nikarh
- **runtime:** Run as daemon with docker event-driven refresh and cleanup by @nikarh
- **logging:** Log signal reception before shutdown cleanup by @nikarh
- **iptables:** Auto-detect ipset and fallback to direct host rules by @nikarh
- **runtime:** Add fail-closed mode and strict startup semantics by @nikarh
- **policy:** Support network-labeled default deny enforcement by @nikarh
- **policy:** Add network enforcement and implicit docker dns allows by @nikarh
- **dns-policy:** Add per-container dns targets with default docker-only allow by @nikarh
- **monitor:** Include created containers and network-scoped enforcement by @nikarh
- **runtime:** Subscribe to docker network events for policy refresh by @nikarh
- **runtime:** Apply docker events incrementally with targeted state refresh by @nikarh
- **runtime:** Avoid zero-diff applies and remove resolv.conf reads by @nikarh
- **monitor:** Build runtime state from bulk container and network lists by @nikarh
- **events:** Use typed docker event parsing and server-side event filters by @nikarh
- **runtime:** Add channel-driven loop and DNS runtime by @nikarh
- **dns:** Resolve hostnames on demand during firewall apply in lazy mode by @nikarh
- **firewall:** Let established connections bypass the policy by @nikarh
- **monitor:** Rename the network opt-in label to portcullis.enable by @nikarh
- **labels:** Rework DNS targets around how Docker's DNS forwards by @nikarh
- **firewall:** Reject denied traffic by default by @nikarh
- **runtime:** Add an optional JSON event stream on a Unix socket by @nikarh
- Report every decision as events, with monitor mode, alerts and DNS inspection by @nikarh
- **dns:** Report DNS lookups only where allowed connections are by @nikarh
- **firewall:** Hold packets of containers whose rules aren't applied yet by @nikarh
- **events:** Report denied ARP and other frames, naming the sender by its port by @nikarh
- Keep the firewall rules when Portcullis stops, and add portcullis cleanup by @nikarh
- Warn about configurations that get containers around their rules by @nikarh
- Quarantine misbehaving containers and limit their connections by @nikarh
- **dns:** Limit the names a container can look up by @nikarh
- --version, and the version in the start log by @nikarh
- **dist:** Harden the systemd unit, and never give up restarting by @nikarh
- Builds of main say so in their version (PORTCULLIS_VERSION_SUFFIX) by @nikarh
- Read settings from /etc/portcullis/config.toml by @nikarh

### Fixes

- **bindgen:** Narrow libnftables symbol allowlist to satisfy clippy by @nikarh
- **monitor:** Support docker firewall backend object shape by @nikarh
- **firewall:** Use backend-neutral command error messages by @nikarh
- **monitor:** Decode chunked docker api responses before json parse by @nikarh
- **firewall:** Tolerate missing portcullis target during iptables cleanup by @nikarh
- **firewall:** Align docker hooks for iptables and nftables by @nikarh
- **runtime:** Ignore chunked transfer size lines in docker event stream by @nikarh
- **iptables:** Remove ipset dependency for hostname allow rules by @nikarh
- **runtime:** Fail fast on startup and tolerate event-time errors by @nikarh
- **monitor:** Ignore docker networks that have no subnet by @nikarh
- **monitor:** Only skip missing subnet for host and none networks by @nikarh
- **monitor:** Accept empty docker endpoint ip addresses by @nikarh
- **iptables:** Switch cleanup batching from shell to iptables-restore by @nikarh
- **firewall:** Remove leftover hostname resolver trait usage by @nikarh
- **iptables:** Refill ipsets atomically and destroy stale sets by @nikarh
- **labels:** Accept /name spelling in ICC allow-list targets by @nikarh
- **firewall:** Stop matching ICC allow-list targets by container id by @nikarh
- **iptables:** Return to DOCKER-USER instead of accepting allowed traffic by @nikarh
- **firewall:** Keep applying rules when a hostname can't be resolved by @nikarh
- **monitor:** Log and skip invalid labels instead of failing by @nikarh
- **labels:** Accept plain addresses in ip: egress targets by @nikarh
- **runtime:** Clean up firewall rules on SIGTERM by @nikarh
- **firewall:** Allow the upstream servers Docker's DNS forwards to by @nikarh
- **firewall:** Enforce ICC policies in an nftables bridge table by @nikarh
- **monitor:** Use a network's IPv4 subnet instead of its first one by @nikarh
- **firewall:** Stop containers from using addresses that aren't theirs by @nikarh
- **firewall:** Update nftables rules in place instead of recreating tables by @nikarh
- **firewall:** Deny VLAN-tagged frames on enforced bridges by @nikarh
- **firewall:** Deny ICC to broadcast and multicast addresses by @nikarh
- **firewall:** Apply egress rules to traffic addressed to the host by @nikarh
- **dns:** Learn hostname addresses per container by @nikarh
- **firewall:** Bind container addresses to their bridge port by @nikarh
- **firewall:** Warn when a container's bridge port can't be found by @nikarh
- **firewall:** Check where traffic comes from before letting established traffic through by @nikarh
- **firewall:** Bind ARP and every other frame to the sender's port and MAC by @nikarh
- **firewall:** Drop traffic denied for its source instead of rejecting it by @nikarh
- **firewall:** Deny frames to link-local group addresses by @nikarh
- **firewall:** Deny bridged traffic not addressed to the network by @nikarh
- **firewall:** Match egress rules against the destination a container asked for by @nikarh
- **firewall:** Forget the connections of addresses that change hands by @nikarh
- **events:** Report egress destinations as the container asked for them by @nikarh
- **firewall:** Keep reporting denials when the set of reported flows is full by @nikarh
- **events:** Limit alerts per container so a flood can't bury the next one by @nikarh
- **dns:** Bound what a container can learn from DNS answers by @nikarh
- **events:** Report each address a container claims with ARP by @nikarh
- Put the last rules back before Docker starts containers at boot by @nikarh
- **deps:** Upgrade hickory-proto to 0.26 and tokio past known advisories by @nikarh
- Keep reading the kernel's queues after overruns, stop on failures by @nikarh
- **docker:** Don't miss containers started while the first rules are applied by @nikarh
- Try failed rule updates again, backing off up to 5 minutes by @nikarh
- **deps:** Update bindgen to 0.73.2, with prettyplease 0.3 by @nikarh
- No color codes in diagnostic logs unless stderr is a terminal by @nikarh
- Don't lose bursts of reports to a receive buffer capped at rmem_max by @nikarh
- Number builds of main by commit count so their versions always grow by @nikarh

### Performance

- **runtime:** Avoid duplicate container refresh on network events by @nikarh
- **iptables:** Batch rule updates via iptables-restore by @nikarh
- **runtime:** Delay create-time apply until network attachment exists by @nikarh
- **iptables:** Batch startup and shutdown cleanup commands by @nikarh
- **iptables:** Detect ipset once at firewall initialization by @nikarh
- **monitor:** Minimize docker event queries and single-action updates by @nikarh
- **firewall:** Avoid per-refresh iptables chain swap churn by @nikarh
- **firewall:** Batch ipset updates via restore by @nikarh
- **firewall:** Dispatch packets to per-source chains by @nikarh
- **runtime:** Skip firewall apply when DNS results are unchanged by @nikarh
- **firewall:** Report each flow at most once a minute by @nikarh

### Documentation

- Add ICC allowlist and alias resolution documentation by @nikarh
- **readme:** Document daemon runtime and cleanup behavior by @nikarh
- **readme:** Clarify docker socket event subscription mode by @nikarh
- **architecture:** Describe docker socket api discovery path by @nikarh
- **firewall:** Document docker-compatible chain hook points by @nikarh
- **cli:** Document fail-closed runtime flag by @nikarh
- **labels:** Add network enforcement label documentation by @nikarh
- **policy:** Document implicit dns allow and network enforcement by @nikarh
- **labels:** Document container dns policy labels by @nikarh
- **monitor:** Document all-containers and network event discovery by @nikarh
- **runtime:** Describe incremental docker event processing by @nikarh
- **dns:** Document explicit host dns resolver labels by @nikarh
- Describe network-scoped ICC target lookup and backend parity by @nikarh
- Replace docs folder with a rewritten user-facing README by @nikarh
- State that IPv6 is unsupported by design by @nikarh
- Say denied rather than dropped for DNS queries by @nikarh
- Spell out what DNS policies can and can't control by @nikarh
- Explain why address and MAC spoofing together can't be blocked by @nikarh
- Document monitoring, events, alerts and DNS inspection by @nikarh
- Explain that new networks are unfiltered until Portcullis sees them by @nikarh
- Explain what keeps containers from getting around their rules by @nikarh
- Explain the new checks against containers getting around their rules by @nikarh
- Explain what happens to the rules when Portcullis stops, and how to remove them by @nikarh
- List per-container DNS learning and dropped spoofed traffic among the protections by @nikarh
- Describe the configuration checks and how to acknowledge them by @nikarh
- Describe quarantine and connection limits by @nikarh
- Explain how DNS gets abused, and limiting the names a container can look up by @nikarh
- Explain running Portcullis as a service, before Docker by @nikarh
- Installing from a release, what happens when something fails, upgrading by @nikarh
- **e2e:** Mention that CI runs the suite by @nikarh
- Verifying signed releases, and how releasing works by @nikarh
- Remove the crates.io badge; portcullis on crates.io is another project by @nikarh

[0.1.2]: https://github.com/nikarh/portcullis/compare/v0.1.1..v0.1.2

<!-- generated by git-cliff -->
