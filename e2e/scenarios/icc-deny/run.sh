#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib.sh
source "${SCRIPT_DIR}/../../lib.sh"

COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
cleanup "${COMPOSE_FILE}"

dc "${COMPOSE_FILE}" up -d --build
trap 'cleanup "${COMPOSE_FILE}"' EXIT

apply_policy trace

expect_cmd_fails "icc=deny blocks TCP to peer" check_tcp "${COMPOSE_FILE}" peer 8080
