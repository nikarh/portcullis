wait_managed "$(svc_ip app net)"
blocked "before the container looked the name up" tcp app 198.51.100.5 80
flush_checks
allowed "the lookup" resolve app dyn.test
# The answer is only released after its address is allowed.
flush_checks
allowed "the address from the answer" tcp app 198.51.100.5 80
event "the connection is labelled with the name" 'event=connection verdict=denied container~app domain=dyn.test domain_source=dns destination_port=443' tcp app 198.51.100.5 443
flush_checks

# Looking the name up again allows the address for another full hold (an hour), from the
# new answer on, not from the first one.
sleep 3
allowed "the lookup again" resolve app dyn.test
flush_checks
left="$(seconds_allowed 198.51.100.5)"
if [[ -n "${left}" ]] && ((left >= 3599)); then
  pass "a new answer renews the address (${left}s left)"
else
  fail "a new answer renews the address (${left:-no}s left, expected at least 3599s)"
fi
