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

`suite.sh` runs inside the VM as root. It starts Portcullis (with an event socket, and an alert hook appending to a file), runs every scenario, stops Portcullis with SIGTERM, checks that its rules stayed in place and that `portcullis cleanup` removes them. Then it repeats two scenarios with `--deny-action drop` and `--on-exit remove`, and checks that stopping removed the rules.

Outbound targets live in a network namespace routed from the Docker host (`outside.sh`), so traffic to them is forwarded and filtered like traffic to the internet. It serves TCP 80, 443 and 8080 and UDP 9000 on `198.51.100.2` to `.5`, and a DNS server on `198.51.100.2` that resolves `api.test` to `.3`, `other.test` to `.4` and `dyn.test` to `.5`. The Docker host resolves `api.test` and `other.test` through `/etc/hosts`, but not `dyn.test`, so Portcullis can only learn its address from a container's lookup.

Each scenario in `scenarios/<name>/` is a Compose project on a network with `portcullis.enable=true`, plus a `test.sh` with checks. No check waits for a timeout to pass:

- `wait_managed <address>...` blocks until Portcullis's event stream (`--events-socket`) reports rules in place for those containers. Call it before checking anything a container's rules decide.
- `allowed <description> <probe>` passes only when the probe shows the peer's answer.
- `blocked <description> <probe>` passes only when the probe shows the rejection Portcullis sends ("Host is unreachable", or SERVFAIL from Docker's DNS server). In drop mode it passes when a kernel packet trace (`nft monitor trace`) shows one of Portcullis's chains dropping the probe.
- `event <description> <filters> <probe>` subscribes to the event stream, runs the probe, and passes when an event matches every filter (`key=value` or `key~text`, see `expect-event.py`).
- `wait_for_line <file> <pattern>` waits (through inotify) until a line of the file matches, for alerts.

The `bypass` scenario checks what a container can try with Docker's default capabilities to get around its rules: `craft` (`images/tester/craft.py`, using scapy) sends hand-made frames through a raw socket, with borrowed addresses and MACs, VLAN tags, overlapping fragments, broadcast and multicast destinations, and reports whether anything answered. Such probes can't always see a rejection (it goes to the borrowed address), so `unanswered` checks pass when the probe heard nothing back within its listening time (4 seconds), next to `allowed` checks that show the same probes do get answers where the rules allow them. A second DNS server on `198.51.100.4` lies about `api.test` (it says `198.51.100.5`).

The scenario also tries ARP from another container's MAC or claiming the gateway's address, IPv6, frames to link-local group addresses, spoofed traffic into another container's connection and ICMP errors about it, a container's address on its second network through its MAC, published ports through DNAT from another network, a removed container's connections from the next container with its address, and floods of reports and alerts. Most of these are checked through the event that reports them. Where the kernel or Docker would also stop an attempt (reverse path filtering, `br_netfilter` and Docker's raw table), the check turns that off for its duration, so it shows what Portcullis's own rules do.

To check what happens before Portcullis has applied rules for a container, the `fast-start` scenario stops Portcullis with SIGSTOP, starts a container that sends right away, and resumes Portcullis with SIGCONT.

Probes (`tcp`, `udp`, `dns`, `resolve`, `from_outside`) run inside a container from `images/tester`, which also serves TCP 5432, 6379, 8080 and UDP 9000 for container-to-container checks. Every server answers with its address or hostname. The checks of a scenario run in parallel; a failed check prints the probe's output.
