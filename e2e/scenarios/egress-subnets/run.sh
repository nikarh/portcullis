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

expect_cmd_succeeds "egress allowlist permits explicit TCP destination" check_tcp "${COMPOSE_FILE}" 172.31.0.10 8080
expect_cmd_fails "egress allowlist blocks non-whitelisted TCP destination" check_tcp "${COMPOSE_FILE}" 172.31.0.11 8080
expect_cmd_succeeds "egress allowlist permits explicit UDP destination" check_udp_echo "${COMPOSE_FILE}" 172.31.0.20 9000
expect_cmd_fails "egress allowlist blocks non-whitelisted UDP destination" check_udp_echo "${COMPOSE_FILE}" 172.31.0.21 9000
