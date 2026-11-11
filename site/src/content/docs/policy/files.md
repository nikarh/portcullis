---
title: Policy files
description: Keep some of a container's policy labels in a file on the Docker host instead of in Docker's metadata.
sidebar:
  order: 11
---

Container labels are visible to anyone who can run `docker inspect`, and they end up in Compose files, image metadata and support bundles. When part of a policy shouldn't be, such as the address and port of a VPN endpoint, put it in a policy file on the Docker host and name the file in a label:

```yaml title="docker-compose.yml"
services:
  vpn-client:
    image: ghcr.io/acme/vpn-client:latest
    labels:
      - portcullis.policy-file=vpn-client
      - portcullis.dns.0=none
```

```ini title="/etc/portcullis/policies/vpn-client"
# The VPN endpoint
portcullis.egress.endpoint=ip:203.0.113.7,udp:51820
portcullis.icc.mode=deny
```

| Label | On | Value |
| --- | --- | --- |
| `portcullis.policy-file` | container | the name of a file in the policy directory |

## The file

One label per line, `<label>=<value>`, as in a file for `docker run --label-file`. Spaces around the label and the value are trimmed, and blank lines and lines starting with `#` are skipped. The labels and values are the same as on a container; every label of a container's policy can be in the file: `portcullis.egress.*`, `portcullis.icc.*`, `portcullis.dns.*`, `portcullis.domains.*`, `portcullis.limit.*`, `portcullis.quarantine`, `portcullis.hostname-hold` and `portcullis.ack`. A file can't name another file.

The file's labels are added to the container's. When the file sets a label the container also has, the file's value is used, and so is the last line when the file sets a label twice; both are reported with an `invalid_label` warning.

## Where files are

Files are read from the policy directory, `/etc/portcullis/policies` unless [`policy-dir`](/reference/configuration/#policy) says otherwise. Portcullis runs on the Docker host, so this is a directory on the host, not in a container.

The label names a file directly in the directory: no `/`, no `..`. A symbolic link in the directory may point to another file in it, not outside it. Since what the file says opens containers up, the directory and the file have to be owned by root (or the user Portcullis runs as) and not writable by group or others. Nothing needs to be able to read them but Portcullis:

```bash
sudo install -d -m 700 /etc/portcullis/policies
sudo install -m 600 vpn-client /etc/portcullis/policies/
```

Anyone who can set a container's labels can name any file in the directory, and so give their container the policy of another; Docker access is root access anyway.

## When it is read

When Portcullis learns of the container: when it is created, when it connects to a network (which it does every time it starts), and when Portcullis or Docker starts. A changed file applies to a running container at its next restart:

```bash
docker restart vpn-client
```

## What is kept private

Portcullis never logs or reports a value from a policy file. Warnings about it name the file and the label or line, and leave out the value: an invalid `portcullis.egress.endpoint` in the file is reported as `ignoring invalid portcullis.egress.endpoint in policy file vpn-client`, without saying what is wrong with it. Check a value by putting it on a test container as a label.

What the container does is still reported as usual: a [connection event](/reference/events/#connection) has its destination, whatever rule allowed or denied it, and a `host:` rule's name shows up in `unresolved_hosts` when it doesn't resolve.

## When the file can't be used

A container whose file is missing, can't be read, is outside the directory, is writable by others, is larger than 64 KiB, isn't text, or has a line that isn't `<label>=<value>`, is denied everything: no other containers, no destinations, no DNS, whatever its labels allow. Portcullis reports a `policy_file` warning with the reason. Fix the file and restart the container.

Invalid labels in a file that can be read are handled as on a container (see [Invalid labels](/policy/overview/#invalid-labels)): each is ignored, and the others apply. A line with a label that isn't one of a container's policy, such as `portcullis.egres.0` or a value written on a line of its own with an `=`, is ignored too, and reported with its line number.
