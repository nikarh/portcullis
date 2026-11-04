wait_managed "$(svc_ip anchor net)"

# Portcullis can't apply rules while it's stopped, so the container's first packets are
# certainly sent before its rules exist. It's created first, so that Portcullis is stopped
# only while the container starts: Docker's DNS server gives up on a query after a few
# seconds, however long Portcullis would have held it.
FAST_OUTPUT="$(dc --profile late create fast 2>&1)"
fast_id="$(dc --profile late ps -aq fast)"
kill -STOP "${PORTCULLIS_PID}"
[[ -n "${fast_id}" ]] && FAST_OUTPUT="$(docker start "${fast_id}" 2>&1)"
kill -CONT "${PORTCULLIS_PID}"
if [[ -n "${fast_id}" ]]; then
  docker wait "${fast_id}" >/dev/null
  FAST_OUTPUT="$(docker logs "${fast_id}" 2>&1)"
fi

# The probe's lines, or everything when there are none (to show what went wrong).
probe_output() {
  grep "^$1: " <<<"${FAST_OUTPUT}" | sed "s/^$1: //" | grep . || printf '%s\n' "${FAST_OUTPUT}"
}
fast_tcp() { probe_output tcp; }
fast_udp() { probe_output udp; }
fast_dns() { probe_output dns; }
fast_denied() { probe_output denied; }

allowed "TCP sent before the rules existed" fast_tcp
allowed "UDP sent before the rules existed" fast_udp
allowed "a lookup sent before the rules existed" fast_dns
check "blocked: denied traffic sent before the rules existed" \
  expect_rejection fast_denied
