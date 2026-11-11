# shellcheck shell=bash
wait_managed "$(svc_ip node-a cluster)" "$(svc_ip node-b cluster)" "$(svc_ip client cluster)"
node_b="$(in_svc node-b hostname)"

# mcast <service> <group> <port>: send to a group and print the answers. The sender doesn't
# hear itself, so an answer comes from another member, through the bridge.
mcast() {
  in_svc "$1" sh -c "printf ping | socat -t2 -T2 - UDP4-DATAGRAM:$2:$3,ip-multicast-loop=0" 2>&1
}
# listening <service>: block until the member's discovery server is up: bound to UDP 54327
# (D437 in /proc/net/udp) and in group 224.2.2.4 (040202E0 in /proc/net/igmp), which only
# that server joins, together with 224.2.2.3. A container's rules can be in place before
# its command has got that far.
listening() {
  in_svc "$1" sh -c 'for _ in $(seq 100); do
    grep -q ":D437 " /proc/net/udp && grep -q 040202E0 /proc/net/igmp && exit 0
    sleep 0.1
  done
  echo "the discovery server did not start"
  exit 1'
}
answered_by_b() {
  listening node-a && listening node-b || return 1
  local output
  output="$(mcast "$@")"
  printf '%s\n' "${output}"
  grep -qx "${node_b}" <<<"${output}"
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
