---
title: Development
description: Building, testing and the end-to-end suite, for working on Portcullis itself.
sidebar:
  order: 2
---

## Building and checks

Building needs Rust (the toolchain in `rust-toolchain.toml`), the libnftables development headers and clang; see [Building from source](/start/installation/#building-from-source).

```bash
cargo fmt
cargo clippy --locked --all-targets
cargo test --locked
```

CI runs the same, plus `scripts/check-actions.sh` (every action pinned and allowed), `cargo deny`, a package build checked with `scripts/check-deb.sh`, the end-to-end suite, and the docs build. Clippy runs with `pedantic` and more denied; see `[lints]` in `Cargo.toml`.

Commits follow [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `docs:`, `test(e2e):` and so on. The changelog and release notes are generated from them with git-cliff.

## End-to-end tests

The suite in `e2e/` runs Portcullis against real Docker containers and checks what traffic gets through. Everything runs in a throwaway Debian VM under QEMU, so the host's firewall and network are never touched.

```bash
e2e/run.sh
E2E_SCENARIOS="icc egress" e2e/run.sh
KEEP_VM=1 e2e/run.sh                # leave the VM running for the next run
```

The host needs `qemu-system-x86_64`, `genisoimage` (or `mkisofs`), `ssh`, `rsync` and read/write access to `/dev/kvm`; no root and no daemons. The first run downloads a Debian cloud image and provisions the VM with Docker and Rust, which takes a few minutes.

Each scenario in `e2e/scenarios/<name>/` is a Compose project on an enforced network, plus a `test.sh` with checks that wait on Portcullis's event stream rather than on timeouts. [`e2e/README.md`](https://github.com/nikarh/portcullis/blob/main/e2e/README.md) describes the harness, the probes and every scenario.

## Docs

See [Writing the docs](/project/docs/).
