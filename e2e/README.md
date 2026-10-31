# End-to-end tests

The suite runs Portcullis against real Docker containers and checks what traffic gets through. Everything runs in a throwaway Debian VM under QEMU, so the host's firewall and network are never touched.

## Running

```bash
e2e/run.sh
E2E_SCENARIOS="icc egress" e2e/run.sh
KEEP_VM=1 e2e/run.sh                # leave the VM running for the next run
```

The host needs `qemu-system-x86_64`, `genisoimage` (or `mkisofs`), `ssh`, `rsync` and read/write access to `/dev/kvm`. No root and no daemons. The first run downloads a Debian cloud image and provisions the VM with Docker and Rust, which takes a few minutes; later runs boot the existing disk. VM files live in `~/.cache/portcullis-e2e`.

`e2e/vm.sh` manages the VM on its own: `up`, `sync` (copy the working tree and build), `ssh [command]`, `down`, and `destroy` (delete the disk).

## How it works

`suite.sh` runs inside the VM as root. It starts Portcullis, runs every scenario, stops Portcullis with SIGTERM and checks that no rules are left behind. A last pass runs Portcullis in DNS proxy mode.

Outbound targets live in a network namespace routed from the Docker host (`outside.sh`), so traffic to them is forwarded and filtered like traffic to the internet. It serves TCP 80, 443 and 8080 and UDP 9000 on `198.51.100.2` to `.5`, and a DNS server on `198.51.100.2` that resolves `api.test` to `.3` and `other.test` to `.4`. The Docker host resolves the same names through `/etc/hosts`.

Each scenario in `scenarios/<name>/` is a Compose project on a network with `portcullis.enable=true`, plus a `test.sh` with checks:

- `allowed <description> <probe>` retries the probe for up to 10 seconds, since rules are applied asynchronously after a container starts.
- `blocked <description> <probe>` runs the probe once. Call `wait_managed <address>` first, which waits until Portcullis installed rules for that container, so a blocked check can't pass just because rules aren't there yet.

The checks of a scenario run in parallel. Probes (`tcp`, `udp`, `dns`, `resolve`) run inside a container from `images/tester`, which also serves TCP 5432, 6379, 8080 and UDP 9000 for container-to-container checks. Every server answers with its address or hostname, and a probe only succeeds when it gets that answer.
