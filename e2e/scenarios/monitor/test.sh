peer_ip="$(svc_ip peer net)"
wait_managed "$(svc_ip app net)" "$(svc_ip loner net)" "${peer_ip}"
allowed "outbound traffic passes" tcp app 198.51.100.5 80
allowed "denied ICC passes" tcp loner "${peer_ip}" 5432
EVENT_SAVE="${RESULTS_DIR}/monitor-events.jsonl"
: >"${EVENT_SAVE}"
event "outbound traffic is reported as would-deny" 'event=connection verdict=would_deny reason=egress container~app destination=198.51.100.5 destination_port=80' tcp app 198.51.100.5 80
event "ICC is reported as would-deny" 'event=connection verdict=would_deny reason=icc container~loner destination_container~peer destination_port=5432' tcp loner "${peer_ip}" 5432
event "DNS lookups are reported" 'event=dns container~app name=api.test answers~198.51.100.3' resolve app api.test
event "allowed connections are reported too" 'event=connection verdict=allowed reason=icc container~app destination_container~peer' tcp app "${peer_ip}" 5432
flush_checks
audit_suggests() {
  local output
  output="$("${PORTCULLIS_BIN}" audit "${EVENT_SAVE}")"
  printf '%s\n' "${output}"
  grep -Fq "portcullis.egress.198-51-100-5=ip:198.51.100.5,tcp:80" <<<"${output}" \
    && grep -Eq "portcullis.icc.allow.pc-monitor-peer-1=container:pc-monitor-peer-1,tcp:5432" <<<"${output}"
}
check "audit: suggests labels for what would be denied" audit_suggests
unset EVENT_SAVE
