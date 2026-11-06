---
title: Rolling out a policy
description: Go from no policy to an enforced one without breaking services, using monitor mode and portcullis audit.
sidebar:
  order: 1
---

Writing labels from memory misses things: telemetry, update checks, CDNs behind an API, the host's search domains. Monitor mode lets you write them from what services actually do, and then switch to enforcing with nothing left to discover.

## 1. Watch the network

There are three ways to put a network in monitor mode, depending on whether you can recreate it:

| How | Scope | Needs |
| --- | --- | --- |
| `portcullis.enable=monitor` on the network | that network | creating or recreating the network |
| `monitor-networks = ["backend"]` in the config | named networks, or `["*"]` for every bridge network | a restart of Portcullis, nothing else |
| `monitor = true` in the config | every network Portcullis watches, enforced ones included | a restart of Portcullis |

Docker only sets a network's labels when it creates it, and recreating a network means recreating its containers. `monitor-networks` watches existing networks as they are, which makes it the way in on a host that already runs services. It also watches the default `bridge` network, which can't have labels. A network's own label, if it has one, wins over `monitor-networks`, so `portcullis.enable=false` keeps a network out of `["*"]`.

On a network in monitor mode nothing is blocked. Every connection that the labels wouldn't allow is reported as `would_deny`, and every allowed connection and DNS lookup is reported too (with the default `log-allowed = "monitor"`). Monitor mode never raises alerts.

If containers already have Portcullis labels, they apply in monitor mode as they would when enforced: what they allow is reported as allowed, the rest as `would_deny`.

## 2. Collect events as JSON

`portcullis audit` reads JSON events and ignores other lines. Have the service write JSON:

```toml title="/etc/portcullis/config.toml"
log-format = "json"
```

Then restart it with `sudo systemctl restart portcullis`. The rules stay in place while it restarts.

Let the services run long enough to do everything they do: a full business cycle, scheduled jobs, a deploy, a backup. A day is a good start; a week catches weekly jobs.

## 3. Turn events into labels

```bash
journalctl -u portcullis -o cat --since "-7d" | portcullis audit
```

`audit` reads a file, or stdin when the file is `-` or missing. After you change labels, recreate the containers and audit again with `--since` set to when you did, so that what they did before doesn't come back. It prints, for each container, the labels that would have allowed what it tried:

```text
billing (12 denied or would-be-denied connections)
  portcullis.egress.api-stripe-com=host:api.stripe.com,tcp:443
  portcullis.icc.allow.db=container:db,tcp:5432
    (with portcullis.icc.mode=allow-listed)
```

To keep the list short, it:

- joins consecutive ports into ranges (`tcp:8000-8100`);
- suggests a [pattern](/policy/patterns/) for three or more hostnames under one domain with the same ports: `host:*.redd.it`, or `host:**.archive.org` when they are at different levels;
- suggests `ip:public` for ten or more public addresses with the same ports;
- lists packets that don't start a connection (`mid_stream`, see [Events](/reference/events/#connection)) apart, since they need no label;
- lists traffic labels can't allow (broadcast, protocols without a label), resolvers queried directly (as `portcullis.dns.*` labels), traffic that used an address or MAC that isn't the container's, and warnings.

:::caution[Review every suggestion]
The suggestions describe what happened, not what should happen. A compromised or misconfigured container produces suggestions too. Folded patterns and `ip:public` allow more than what was seen; narrow them where you can.
:::

Things `audit` can't infer:

- Whether a container should be allow-listed for ICC. It only suggests `container:` rules for connections that the current mode would deny. To narrow down a container that has the default `allow` mode, set `portcullis.icc.mode=allow-listed` while still in monitor mode, and audit again.
- Domain limits. To restrict the names a container may look up, add [`portcullis.domains`](/policy/domains/) labels in monitor mode; lookups outside the list are reported as `would_deny` with the query.
- Hostnames, when Portcullis can't see the container's DNS lookups. It then suggests `ip:` rules for the bare addresses. Set up [DNS visibility](/policy/dns/#dns-visibility) before collecting.

## 4. Enforce

Add the labels, then switch the network to `portcullis.enable=true`. That label also takes recreating the network; for networks you watched with `monitor-networks`, see [Existing networks](/examples/existing-networks/) for creating enforced networks ahead of time and attaching projects to them.

From then on every denial is reported as `denied` and raises an [alert](/guides/events-and-alerts/#alerts). With `log-allowed = "monitor"` (the default) allowed traffic is no longer reported, so once the labels are right there is little to nothing in the log.

If you used `monitor = true` globally, set it back to `false` and restart; it overrides every network's label.

## Changing a policy later

Container labels are set when a container is created, so changing a policy means recreating the container (`docker compose up -d` does it when labels change). Portcullis picks up the new labels as soon as Docker reports the container.

Rules apply to new connections. Connections that were open when a policy changed keep working until they close, as long as the container keeps its address and MAC.

To try a change before enforcing it, put the labels on a copy of the service on a network in monitor mode, or watch the reports right after the change with `sudo portcullis watch`.
