#!/usr/bin/env bash
# A fake "internet" for the tests: a network namespace routed from the Docker host, so
# traffic from containers to it is forwarded (and filtered) like real outbound traffic.
#
# Addresses (all inside the namespace):
#   198.51.100.2  DNS (dnsmasq, udp+tcp/53), TCP 80/443/8080, UDP echo 9000
#   198.51.100.3  same services, the address of api.test
#   198.51.100.4  same services, the address of other.test, and a DNS server that lies:
#                 it resolves api.test to 198.51.100.5
#   198.51.100.5  same services, the address of dyn.test, which only this DNS server knows
#   11.22.33.2-5  same services, on public addresses (198.51.100.0/24 is a documentation
#                 range, which ip:public leaves out)
# The Docker host reaches it via 198.51.100.1, and has a public address of its own on the
# link to it, 11.22.33.1.
#
# The DNS server on 198.51.100.2 also answers names for the pattern tests; dnsmasq answers
# a name and every name below it:
#   one.wild.test 11.22.33.2, deep.two.wild.test 11.22.33.3, wild.test 11.22.33.4,
#   evilwild.test 11.22.33.5, s1.sub.test 11.22.33.2, t1.sub.test 11.22.33.3
#
#   outside.sh up | down
set -euo pipefail

NS=pc-outside
HOST_IF=pc-out0
ADDRESSES=(198.51.100.2 198.51.100.3 198.51.100.4 198.51.100.5)
PUBLIC_ADDRESSES=(11.22.33.2 11.22.33.3 11.22.33.4 11.22.33.5)
RUN_DIR=/run/portcullis-e2e

up() {
  down
  mkdir -p "${RUN_DIR}"
  ip netns add "${NS}"
  ip link add "${HOST_IF}" type veth peer name eth0 netns "${NS}"
  ip addr add 198.51.100.1/24 dev "${HOST_IF}"
  ip link set "${HOST_IF}" up
  ip -n "${NS}" link set lo up
  ip -n "${NS}" link set eth0 up
  for address in "${ADDRESSES[@]}"; do
    ip -n "${NS}" addr add "${address}/24" dev eth0
  done
  ip -n "${NS}" route add default via 198.51.100.1
  for address in "${PUBLIC_ADDRESSES[@]}"; do
    ip -n "${NS}" addr add "${address}/32" dev eth0
  done
  ip route add 11.22.33.0/24 via 198.51.100.2 dev "${HOST_IF}"
  ip addr add 11.22.33.1/32 dev "${HOST_IF}"

  # Every listener answers with its own address, so tests can tell which one they reached.
  for port in 80 443 8080; do
    ip netns exec "${NS}" setsid socat -T2 "TCP-LISTEN:${port},fork,reuseaddr" \
      SYSTEM:'echo $SOCAT_SOCKADDR' >/dev/null 2>&1 &
  done
  # One UDP socket per address, so replies come from the address the client sent to.
  for address in "${ADDRESSES[@]}" "${PUBLIC_ADDRESSES[@]}"; do
    ip netns exec "${NS}" setsid socat -T2 "UDP-RECVFROM:9000,bind=${address},fork" \
      "SYSTEM:echo ${address}" >/dev/null 2>&1 &
  done
  ip netns exec "${NS}" setsid dnsmasq --keep-in-foreground --no-resolv --no-hosts \
    --listen-address=198.51.100.2 --bind-interfaces --pid-file="${RUN_DIR}/dnsmasq.pid" \
    --address=/api.test/198.51.100.3 --address=/other.test/198.51.100.4 \
    --address=/dyn.test/198.51.100.5 \
    --address=/one.wild.test/11.22.33.2 --address=/deep.two.wild.test/11.22.33.3 \
    --address=/wild.test/11.22.33.4 --address=/evilwild.test/11.22.33.5 \
    --address=/s1.sub.test/11.22.33.2 --address=/t1.sub.test/11.22.33.3 \
    >/dev/null 2>&1 &
  ip netns exec "${NS}" setsid dnsmasq --keep-in-foreground --no-resolv --no-hosts \
    --listen-address=198.51.100.4 --bind-interfaces --pid-file="${RUN_DIR}/dnsmasq-rogue.pid" \
    --address=/api.test/198.51.100.5 \
    >/dev/null 2>&1 &

  # Wait until the services listen.
  for _ in $(seq 50); do
    if ip netns exec "${NS}" ss -ltn | grep -q ':8080 ' \
      && ip netns exec "${NS}" ss -lun | grep -q '198.51.100.2:53 ' \
      && ip netns exec "${NS}" ss -lun | grep -q '198.51.100.4:53 '; then
      return 0
    fi
    sleep 0.1
  done
  echo "outside services did not start" >&2
  return 1
}

down() {
  if ip netns list | grep -qw "${NS}"; then
    ip netns pids "${NS}" | xargs -r kill 2>/dev/null || true
    ip netns del "${NS}"
  fi
  ip link del "${HOST_IF}" 2>/dev/null || true
  ip route del 11.22.33.0/24 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac
