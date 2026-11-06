# Portcullis's own lookups of host: names, on a schedule. Waiting is the point here: what is
# checked is what happens as holds run out, without any container changing.
hosts_entry() {
  sed -i "/ $1 # portcullis-e2e\$/d" /etc/hosts
  [[ -z "${2:-}" ]] || printf '%s %s # portcullis-e2e\n' "$2" "$1" >>/etc/hosts
}
# wait_allowed <seconds> <service> <address>: until a connection gets through.
wait_allowed() {
  local deadline=$((SECONDS + $1))
  until expect_answer tcp "$2" "$3" 80 >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 1
  done
}

hosts_entry moving.test 198.51.100.3
hosts_entry late.test
stop_portcullis
start_portcullis --hostname-hold 20
wait_managed "$(svc_ip app net)" "$(svc_ip patient net)"

allowed "the address Portcullis looked up" tcp app 198.51.100.3 80
flush_checks
# Long after its hold (20s) from the first lookup: the lookups since renewed it.
sleep 25
allowed "the address DNS still returns, past its hold" tcp app 198.51.100.3 80
flush_checks

# The name moves: the new address is allowed after the next lookup, the old one keeps the
# rest of its hold, then runs out. A container with a longer hold keeps it longer.
hosts_entry moving.test 198.51.100.4
check "the new address, without a rule update" wait_allowed 8 app 198.51.100.4
allowed "the old address, for the rest of its hold" tcp app 198.51.100.3 80
flush_checks
sleep 21
blocked "the old address, once its hold ran out" tcp app 198.51.100.3 80
allowed "the old address, to a container with a longer hold" tcp patient 198.51.100.3 80
flush_checks

# A name that doesn't exist is asked for again at the usual pace (every 5 seconds here).
blocked "a name that doesn't resolve" tcp app 198.51.100.5 80
flush_checks
hosts_entry late.test 198.51.100.5
check "the name once it resolves" wait_allowed 10 app 198.51.100.5
flush_checks

hosts_entry moving.test
hosts_entry late.test
stop_portcullis
start_portcullis
