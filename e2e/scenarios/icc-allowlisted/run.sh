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

expect_cmd_succeeds "allow-listed ICC permits alias-based TCP" check_tcp "${COMPOSE_FILE}" api-alias 8080
expect_cmd_fails "allow-listed ICC blocks unlisted TCP" check_tcp "${COMPOSE_FILE}" blocked-api 9090
expect_cmd_succeeds "allow-listed ICC permits UDP" check_udp_echo "${COMPOSE_FILE}" udp-allowed 9000
expect_cmd_fails "allow-listed ICC blocks unlisted UDP" check_udp_echo "${COMPOSE_FILE}" udp-blocked 9000
