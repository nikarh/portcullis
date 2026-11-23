#!/usr/bin/env bash
# Compares what the kernel holds after rule updates over netlink with what it holds after
# nft puts the same rules in place (src/firewall/kernel_tests.rs). Runs inside the test VM
# as the user that builds Portcullis; the tests run as root (through sudo), each in network
# namespaces of their own. e2e/run.sh runs it before the suite.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
runner="CARGO_TARGET_$(uname -m | tr '[:lower:]' '[:upper:]')_UNKNOWN_LINUX_GNU_RUNNER"
export "${runner}=sudo -E"
exec ~/.cargo/bin/cargo test --release --locked -- --ignored kernel_ "$@"
