# Portcullis

[![CI](https://github.com/nikarh/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/nikarh/portcullis/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-nikarh.github.io%2Fportcullis-0e6b5f)](https://nikarh.github.io/portcullis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)

Portcullis limits what Docker containers can connect to, using labels on your networks and containers.

**Documentation: <https://nikarh.github.io/portcullis/>**

By default a container can open connections to any address on the internet and to every other container on its network. Portcullis is a daemon for the Docker host that changes that: you mark a network as enforced, every container on it loses outbound access by default, and each container gets back the destinations its labels list. The labels become nftables rules, kept up to date as containers come and go, and every decision is reported with the container, the destination and its domain.

```yaml
services:
  billing:
    image: ghcr.io/acme/billing:latest
    networks: [backend]
    labels:
      - portcullis.egress.stripe=host:api.stripe.com,tcp:443
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432

networks:
  backend:
    labels:
      - portcullis.enable=true
```

Before enforcing anything, Portcullis can run in monitor mode and report every connection a policy would deny, and `portcullis audit` turns those reports into labels.

It covers outbound connections (by address, range, public internet or hostname), traffic between containers on the same network, which resolvers a container may use and which names it may look up, containers sending with addresses or MACs that aren't theirs, and connection floods. It doesn't do IPv6, works on bridge networks only, and doesn't look inside traffic. See [Limitations](https://nikarh.github.io/portcullis/limits/limitations/).

## Install

Packages for Debian, Ubuntu and Arch Linux (x86_64 and aarch64, glibc 2.35 or newer) are in each [release](https://github.com/nikarh/portcullis/releases), and in signed apt and pacman repositories. See [Installation](https://nikarh.github.io/portcullis/start/installation/), then the [Quick start](https://nikarh.github.io/portcullis/start/quick-start/).

## Documentation

The documentation is the site at <https://nikarh.github.io/portcullis/>, built from [`site/`](site/), with a version for every release and one for `main`:

- [Introduction](https://nikarh.github.io/portcullis/start/introduction/) and [Quick start](https://nikarh.github.io/portcullis/start/quick-start/)
- [Policy labels](https://nikarh.github.io/portcullis/policy/overview/): every label and how a packet is decided
- [Configuration](https://nikarh.github.io/portcullis/reference/configuration/), [command line](https://nikarh.github.io/portcullis/reference/cli/) and [events](https://nikarh.github.io/portcullis/reference/events/)
- [Examples](https://nikarh.github.io/portcullis/examples/single-api/), [Troubleshooting](https://nikarh.github.io/portcullis/help/troubleshooting/), and [Limits and workarounds](https://nikarh.github.io/portcullis/limits/escape-hatches/)
- [How it works](https://nikarh.github.io/portcullis/internals/how-it-works/)

To preview it locally, run `mise run docs`. [Writing the docs](https://nikarh.github.io/portcullis/project/docs/) explains how it is organized and published.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
