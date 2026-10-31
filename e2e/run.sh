#!/usr/bin/env bash
# Run the e2e suite in a disposable VM (see vm.sh). Arguments go to suite.sh.
#
#   e2e/run.sh                 both backends
#   e2e/run.sh iptables        one backend
#   KEEP_VM=1 e2e/run.sh       leave the VM running afterwards
#   E2E_SCENARIOS=icc e2e/run.sh   run only some scenarios
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${E2E_DIR}/vm.sh" up
if [[ -z "${KEEP_VM:-}" ]]; then
  trap '"${E2E_DIR}/vm.sh" down' EXIT
fi
"${E2E_DIR}/vm.sh" sync
"${E2E_DIR}/vm.sh" ssh sudo E2E_SCENARIOS="'${E2E_SCENARIOS:-}'" /home/debian/portcullis/e2e/suite.sh "$@"
