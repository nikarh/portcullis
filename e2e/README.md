# End-to-end tests

The suite runs Portcullis against real Docker containers and checks what traffic gets through. Everything runs in a throwaway Debian VM under QEMU, so the host's firewall and network are never touched.

## Running

```bash
e2e/run.sh
E2E_SCENARIOS="icc egress" e2e/run.sh
KEEP_VM=1 e2e/run.sh                # leave the VM running for the next run
```

The host needs `qemu-system-x86_64`, `genisoimage` (or `mkisofs`), `ssh`, `rsync` and read/write access to `/dev/kvm`. No root and no daemons. The first run downloads a Debian cloud image and provisions the VM with Docker and Rust, which takes a few minutes; later runs boot the existing disk. VM files live in `~/.cache/portcullis-e2e`.

CI runs the suite the same way on every push (`.github/workflows/ci.yml`), on a GitHub runner with KVM.

`e2e/vm.sh` manages the VM on its own: `up`, `sync` (copy the working tree and build), `ssh [command]`, `down`, and `destroy` (delete the disk). To run the suite against another build (an older version, to see a check fail), set `PORTCULLIS_BIN` to its path in the VM for `suite.sh`.

## How it works

`suite.sh` runs inside the VM as root. It starts Portcullis (with an event socket, and an alert hook appending to a file), runs every scenario, stops Portcullis with SIGTERM, checks that its rules stayed in place and that `portcullis cleanup` removes them. Then it repeats two scenarios with `--deny-action drop` and `--on-exit remove`, and checks that stopping removed the rules.

Outbound targets live in a network namespace routed from the Docker host (`outside.sh`), so traffic to them is forwarded and filtered like traffic to the internet. It serves TCP 80, 443 and 8080 and UDP 9000 on `198.51.100.2` to `.5`, and a DNS server on `198.51.100.2` that resolves `api.test` to `.3`, `other.test` to `.4` and `dyn.test` to `.5`. The Docker host resolves `api.test` and `other.test` through `/etc/hosts`, but not `dyn.test`, so Portcullis can only learn its address from a container's lookup. The same services listen on the public addresses `11.22.33.2` to `.5` (`198.51.100.0/24` is a documentation range, which `ip:public` leaves out), and the Docker host has the public address `11.22.33.1` of its own. The DNS server also answers names for patterns: `one.wild.test`, `deep.two.wild.test`, `wild.test`, `evilwild.test`, `s1.sub.test` and `t1.sub.test`, each with its own public address.

Each scenario in `scenarios/<name>/` is a Compose project on a network with `portcullis.enable=true`, plus a `test.sh` with checks. No check waits for a timeout to pass:

- `wait_managed <address>...` blocks until Portcullis's event stream (`--events-socket`) reports rules in place for those containers. Call it before checking anything a container's rules decide.
- `allowed <description> <probe>` passes only when the probe shows the peer's answer.
- `blocked <description> <probe>` passes only when the probe shows the rejection Portcullis sends ("Host is unreachable", or SERVFAIL from Docker's DNS server). In drop mode it passes when a kernel packet trace (`nft monitor trace`) shows one of Portcullis's chains dropping the probe.
- `event <description> <filters> <probe>` subscribes to the event stream, runs the probe, and passes when an event matches every filter (`key=value` or `key~text`, see `expect-event.py`).
- `wait_for_line <file> <pattern>` waits (through inotify) until a line of the file matches, for alerts.

The `bypass` scenario checks what a container can try with Docker's default capabilities to get around its rules: `craft` (`images/tester/craft.py`, using scapy) sends hand-made frames through a raw socket, with borrowed addresses and MACs, VLAN tags, overlapping fragments, broadcast and multicast destinations, and reports whether anything answered. Such probes can't always see a rejection (it goes to the borrowed address), so `unanswered` checks pass when the probe heard nothing back within its listening time (4 seconds), next to `allowed` checks that show the same probes do get answers where the rules allow them. A second DNS server on `198.51.100.4` lies about `api.test` (it says `198.51.100.5`).

The scenario also tries ARP from another container's MAC or claiming the gateway's address, ARP carrying data, a host service through the subnet's broadcast address, IPv6, frames to link-local group addresses, spoofed traffic into another container's connection and ICMP errors about it, a container's address on its second network through its MAC, published ports through DNAT from another network, a removed container's connections from the next container with its address, the address and MAC of a container that left its network, and floods of reports and alerts. Most of these are checked through the event that reports them. Where the kernel or Docker would also stop an attempt (reverse path filtering, `br_netfilter` and Docker's raw table), the check turns that off for its duration, so it shows what Portcullis's own rules do.

The `checks` scenario starts containers with configurations that get around the rules (a second network that isn't enforced, host networking, a shared network namespace, the Docker socket, `NET_ADMIN`, IPv6) and checks their warnings in the alert log, and that acknowledged ones stay quiet. The `flood` scenario checks quarantine (for a spoofed packet, and for too many denials), release on a restart through Docker but not by the container's restart policy, and the connection limits. The `domains` scenario checks that a container with `portcullis.domains` labels can only look up the names they list, through Docker's DNS, directly, and over TCP.

The `patterns` scenario checks port ranges and lists, protocols without ports, `*`, `ip:*` and `ip:public` (not the host, through any of its addresses or a published port, nor private, shared or link-local addresses), and name patterns of `host:`, `container:` and `portcullis.domains`: that a pattern doesn't match its domain itself, names a level too deep, or names that only end the same, and that `*` doesn't open DNS. The `multicast` scenario checks that `multicast:` lets cluster members reach each other through their group and port only, and nobody else send to it. The `updates` scenario floods traffic between two containers and out while containers starting and stopping make Portcullis update its rules dozens of times, and checks that no packet is lost, nothing of theirs is reported as denied, and containers stopping together cause no warnings.

The `restart` scenario checks that the rules stay in force while Portcullis is stopped, that `portcullis cleanup` removes them, and that a container given a removed container's address while Portcullis was stopped doesn't get that container's connections when it starts again.

The `boot` scenario plays a reboot: it stops Portcullis, deletes its tables (as a reboot would) and stops Docker, then starts Portcullis with a stand-in for systemd's notification socket (`wait-ready.py`), checks that the saved rules are back before Docker runs, and starts Docker, whose `restart: always` container tries a listed and an unlisted destination right away.

The `hostname-refresh` scenario restarts Portcullis with a hold of 20 seconds, and checks Portcullis's own lookups of `host:` names as holds run out, without any container changing: an address DNS keeps returning stays allowed past its hold, a name that moves (in the Docker host's `/etc/hosts`) gets its new address and keeps the old one for the rest of its hold, a container with a longer `portcullis.hostname-hold` keeps it longer, a name that starts resolving is allowed at the next lookup, and an address a container learned from its own lookup survives a restart of Portcullis. It is the one scenario whose checks wait for time to pass, since that is what it tests.

To check what happens before Portcullis has applied rules for a container, the `fast-start` scenario stops Portcullis with SIGSTOP, starts a container that sends right away, and resumes Portcullis with SIGCONT.

The `slow-docker` scenario starts a container on four enforced networks while a proxy (`slow-docker.py`) passes Portcullis's inspects of containers on to Docker only after 3 seconds, as Docker answers them once a container has finished starting, and checks that none of its first packets is denied as a spoofed source and that it isn't quarantined. It then does the same for a running container that is restarted, and recreated, while each part of Docker's event stream also comes half a second late.

The `monitor-start` scenario checks that Portcullis finds containers without Docker (see [Finding new containers](https://portcullis.arhipov.net/internals/discovery/)): Portcullis talks to Docker through a `socat` proxy, which the scenario pauses with SIGSTOP while containers start on a monitored and an enforced network. Their first connections must be reported with the container, and the enforced one's labels (read from Docker's files) must decide its traffic. It also checks, on the monitored network, that a veth on the bridge with no container behind it is let through after its hold and reported as an unknown source, that a spoofed address is reported with its sender, and that nothing is held while Portcullis is stopped.

Probes (`tcp`, `udp`, `dns`, `resolve`, `ping_probe`, `from_outside`) run inside a container from `images/tester`, which also serves TCP 5432, 6379, 8080 and UDP 9000 for container-to-container checks. Every server answers with its address or hostname. The checks of a scenario run in parallel; a failed check prints the probe's output.

## Load

`stress.sh` measures Portcullis under load, in the VM with nothing else running: many containers on many networks (`STRESS_CONTAINERS`, default 500, on `STRESS_NETWORKS`, default 20), each with egress, ICC and hostname labels; the time from `docker run` to a container's rules; containers starting and going (`STRESS_CHURN_ROUNDS` rounds of `STRESS_CHURN_BATCH`); and floods of denied connections and DNS lookups from one container. After each phase it prints the number and duration of rule updates, Portcullis's CPU time and memory, and the size of its rules. `STRESS_PERF=1` records a `perf` profile of the updates.

```bash
e2e/vm.sh up && e2e/vm.sh sync
e2e/vm.sh ssh sudo STRESS_CONTAINERS=1000 STRESS_NETWORKS=40 /home/debian/portcullis/e2e/stress.sh
```
