# A container recreated in its predecessor's place gets its address, and is often found
# (from its bridge port) before Docker reports the predecessor gone. The connections it
# makes meanwhile are its own, made under its rules: they must outlive the predecessor's
# removal. Forgetting them then turns the peer's next packet on them into a new connection
# of the peer's, which the peer's rules may not allow.

stop_portcullis
start_docker_proxy
start_portcullis --docker-socket "${DOCKER_PROXY}"
proxy_ip=10.250.77.10
backend_ip="$(svc_ip backend net)"
wait_managed "${proxy_ip}" "${backend_ip}"

# Docker's API paused: Portcullis finds the new container from its first packet, and
# hears of the old one's removal only afterwards.
kill -STOP -- "-${DOCKER_PROXY_PID}"
dc up -d --no-deps --force-recreate proxy >/dev/null 2>&1

# hold <backend>: in the proxy, connect to the backend, send a line, print its echo, then
# wait for one more line the backend sends unasked. The output goes to /tmp/held.
HOLD_SCRIPT='
import socket, sys
out = open("/tmp/held", "w", buffering=1)
try:
    s = socket.create_connection((sys.argv[1], 7000), timeout=60)
    s.sendall(b"one\n")
    out.write("first: " + s.recv(100).decode().strip() + "\n")
    out.write("second: " + s.recv(100).decode().strip() + "\n")
except OSError as error:
    out.write("failed: %s\n" % error)
'
in_svc proxy rm -f /tmp/held
dc exec -d -T proxy python3 -c "${HOLD_SCRIPT}" "${backend_ip}"

# held_line <prefix>: wait (15 seconds at most) for a line of /tmp/held in the proxy.
held_line() {
  local deadline=$((SECONDS + 15)) output
  until output="$(in_svc proxy cat /tmp/held 2>/dev/null)" \
    && grep -Eq "^($1|failed):" <<<"${output}"; do
    ((SECONDS < deadline)) || break
    sleep 0.1
  done
  printf '%s\n' "${output}"
  grep -q "^$1: " <<<"${output}"
}
check "recreated: its connection to the backend is answered" held_line first
flush_checks

# Docker's API back: the old container's removal comes through. The marker starts after it,
# so once the marker's rules are in place, the removal has been handled.
kill -CONT -- "-${DOCKER_PROXY_PID}"
dc --profile late up -d --no-deps marker >/dev/null 2>&1
wait_managed "$(svc_ip marker net)"

docker exec "$(dc ps -q backend)" touch /tmp/go
pushed() { held_line second && in_svc proxy grep -q '^second: push$' /tmp/held; }
check "recreated: the backend still answers on the connection after the old one is removed" pushed
flush_checks

stop_portcullis
stop_docker_proxy
start_portcullis
