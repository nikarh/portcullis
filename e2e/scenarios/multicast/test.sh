# shellcheck shell=bash
wait_managed "$(svc_ip node-a cluster)" "$(svc_ip node-b cluster)" "$(svc_ip client cluster)"
node_b="$(in_svc node-b hostname)"

# mcast <service> <group> <port>: send to a group and print the answers. The sender doesn't
# hear itself, so an answer comes from another member, through the bridge.
mcast() {
  in_svc "$1" sh -c "printf ping | socat -t2 -T2 - UDP4-DATAGRAM:$2:$3,ip-multicast-loop=0" 2>&1
}
# The members may not have joined the group yet when their rules are in place: try a few
# times. A denial fails every try.
answered_by_b() {
  local output try
  for try in 1 2 3; do
    output="$(mcast "$@")"
    printf '%s\n' "${output}"
    grep -qx "${node_b}" <<<"${output}" && return 0
    sleep "${try}"
  done
  return 1
}
check "allowed: a member reaches the others through its group and port" answered_by_b node-a 224.2.2.3 54327
event "the group on another port is denied" "event=connection verdict=denied reason=icc container~node-a destination=224.2.2.3 destination_port=54328" \
  mcast node-a 224.2.2.3 54328
event "another group is denied" "event=connection verdict=denied reason=icc container~node-a destination=224.2.2.4 destination_port=54327" \
  mcast node-a 224.2.2.4 54327
event "a container without the label can't send to the group" "event=connection verdict=denied reason=icc container~client destination=224.2.2.3 destination_port=54327" \
  mcast client 224.2.2.3 54327
flush_checks
# The group opens nothing else: not TCP to the members, nor their addresses.
blocked "a member's TCP port, by unicast" tcp node-a "$(svc_ip node-b cluster)" 8080
allowed "the client's own rule still applies" tcp client "$(svc_ip node-a cluster)" 8080
