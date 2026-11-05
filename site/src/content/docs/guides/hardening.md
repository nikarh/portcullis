---
title: Hardening a host
description: A checklist of host and container settings that close the gaps a network policy can't.
sidebar:
  order: 4
---

Labels decide where a container may connect. These settings close what labels can't: the windows before rules are in place, the configurations that get around them, and what a container can do with traffic it is allowed to send.

## The host

- Run Portcullis as the packaged systemd service, so it starts before Docker and puts the last rules back at boot. See [Boot order](/guides/service/#boot-order).
- Keep `on-exit = "keep"` (the default), so a stopped or crashed Portcullis leaves containers restricted.
- Set `dns` in `/etc/docker/daemon.json`. Without it, Docker 29 resolves outside names from the host, where no container policy applies and Portcullis sees nothing. See [DNS visibility](/policy/dns/#dns-visibility).
- Send alerts somewhere a person sees them: `alert-exec`, or your log pipeline alerting on denied connections and warnings. See [Events and alerts](/guides/events-and-alerts/).
- Make sure nothing else on the host uses NFLOG group 4242, NFQUEUE 4242 to 4245, or marks `0x70630001` to `0x70630003`.

## Networks

- Create enforced networks before starting containers on them, as `external` networks in Compose, so that nothing gets out in the moment between Docker creating a network and Portcullis enforcing it. See [Existing networks](/examples/existing-networks/).
- Disable IPv6 on enforced networks. Portcullis denies IPv6 on them anyway, so it only adds a warning.
- Don't attach restricted containers to networks that aren't enforced; their traffic there isn't filtered (`unenforced_network`).

## Containers

Drop capabilities a container doesn't need. With Docker's defaults a container has `NET_RAW`, which lets it craft its own packets. Portcullis keeps such packets within the container's rules and quarantines the sender, but a container with a raw socket can still flood its network until it is cut off.

```yaml title="docker-compose.yml"
services:
  api:
    image: ghcr.io/acme/api:latest
    cap_drop: [NET_RAW]
    security_opt: [no-new-privileges:true]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443
```

- `cap_drop: [NET_RAW]` for every container that doesn't `ping`. Or `cap_drop: [ALL]` and add back what the image needs.
- No `NET_ADMIN`, no `privileged: true`, no Docker socket for containers you don't trust. Portcullis warns about each (`net_admin`, `privileged`, `docker_socket`); acknowledge the warning only where the container needs it.
- No `network_mode: host`: such containers aren't filtered at all (`unused_labels`).
- No `network_mode: "service:x"` unless you mean the container to share the other's rules (`shared_network`).
- Give containers CPU and memory limits (`cpus:`, `mem_limit:`). Portcullis limits connections, not bandwidth or CPU.

## Policies

- Use `portcullis.icc.mode=deny` for containers that never open connections to their neighbours, such as databases and caches, and `allow-listed` for the rest. The default `allow` lets a compromised container reach everything on its network.
- Prefer `host:` rules with exact names over patterns, and patterns over `ip:public`. A pattern under a domain where anyone can create names allows anyone's server.
- Allow only resolvers you trust. A resolver someone else controls can point your `host:` rules anywhere. Avoid `portcullis.dns.x=*`, which also opens port 53 everywhere.
- Add [`portcullis.domains`](/policy/domains/) to containers that handle secrets, so lookups can't carry data out.
- Set `portcullis.limit.new-connections` on containers that only make a few connections.
- Leave quarantine on (`quarantine = "isolate"`), and opt containers out with `portcullis.quarantine=off` only when they craft packets for a reason.
