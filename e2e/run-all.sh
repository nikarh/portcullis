#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${SCRIPT_DIR}/lib.sh"

require_tools
ensure_binary

scenarios=(
  "icc-allowlisted"
  "icc-deny"
  "egress-subnets"
)

for scenario in "${scenarios[@]}"; do
  log "running scenario: ${scenario}"
  "${SCRIPT_DIR}/scenarios/${scenario}/run.sh"
  log "scenario passed: ${scenario}"
done

log "all e2e scenarios passed"
