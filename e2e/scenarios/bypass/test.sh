attacker_ip="$(svc_ip attacker net)"
victim_ip="$(svc_ip victim net)"
victim_other_ip="$(svc_ip victim other)"
wait_managed "${attacker_ip}" "${victim_ip}" "${victim_other_ip}" "$(svc_ip control net)" \
  "$(svc_ip outsider other)"
subnet="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "${PROJECT}_net")"
gateway="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "${PROJECT}_net")"
other_gateway="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "${PROJECT}_other")"
subnet_broadcast="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1]).broadcast_address)' "${subnet}")"
victim_mac="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJECT}_net\").MacAddress}}" "${PROJECT}-victim-1")"
# The attacker's port on the bridge: the host side of its eth0.
attacker_link="$(in_svc attacker cat /sys/class/net/eth0/iflink </dev/null)"
attacker_port="$(ip -o link | awk -F': ' -v link="${attacker_link}" '$1 == link { split($2, name, "@"); print name[1] }')"
host_service 7777
# A UDP service on the host too: TCP ignores segments that came in a multicast frame.
setsid socat UDP-RECVFROM:7778,fork SYSTEM:'echo host' </dev/null >/dev/null 2>&1 &
host_udp_service=$!
# A UDP flow of the victim, for the attacker to try to get into.
in_svc victim sh -c 'printf flow | socat -t2 -T2 - UDP:198.51.100.4:9000,sourceport=5555' >/dev/null

# The probes work.
allowed "control: hand-made UDP to another container" craft control udp --dst "${victim_ip}" --dport 9000
allowed "control: a host service its labels list" tcp control 198.51.100.1 7777
allowed "attacker: a hand-made SYN to a listed address" craft attacker tcp --dst 198.51.100.3 --dport 80 --wait 1
allowed "victim: its listed host" tcp victim 198.51.100.3 80

# Other containers, past the ICC rules.
unanswered "ICC in a frame with a VLAN 0 tag" craft attacker udp --dst "${victim_ip}" --dport 9000 --vlan 0
unanswered "ICC in a frame with two VLAN tags" craft attacker udp --dst "${victim_ip}" --dport 9000 --vlan 0,0
unanswered "ICC to the broadcast address" craft attacker udp --dst 255.255.255.255 --dport 9000
unanswered "ICC to the subnet's broadcast address" craft attacker udp --dst "${subnet_broadcast}" --dport 9000
unanswered "ICC to a multicast group" craft attacker udp --dst 224.0.0.1 --dport 9000
event "ICMP errors about another container's connection" "event=connection verdict=denied reason=egress container~attacker protocol=icmp destination=198.51.100.4" \
  craft attacker icmp-error --dst 198.51.100.4 --about "${victim_ip}:5555" --dport 9000

# The bridge itself: the victim's MAC in its forwarding table, or other containers' and
# the gateway's addresses in their neighbours' ARP caches.
event "ARP from another container's MAC" "event=connection verdict=denied reason=source container~attacker protocol=arp detail~MAC" \
  craft attacker arp --src-mac "${victim_mac}"
event "ARP claiming the gateway's address" "event=connection verdict=denied reason=source container~attacker protocol=arp source=${gateway} detail~instead" \
  craft attacker arp --src "${gateway}"
event "IPv6" "event=connection verdict=denied reason=frame container~attacker protocol=ipv6" craft attacker ipv6
flush_checks
# The bridge learns where a MAC is from the frames it gets; a frame from the victim's MAC
# would send the victim's traffic to the attacker.
hijack_then_reach() {
  craft attacker arp --src-mac "${victim_mac}" >/dev/null
  local output
  # To the MAC directly: an ARP lookup would make the victim answer, from its own port.
  output="$(craft control udp --dst "${victim_ip}" --dport 9000 --to-mac "${victim_mac}")"
  printf '%s\n' "${output}"
  grep -q '^answered' <<<"${output}"
}
check "allowed: the victim's traffic after ARP from its MAC elsewhere" hijack_then_reach
flush_checks

# The host itself.
blocked "a host service through the gateway" tcp attacker "${gateway}" 7777
blocked "a host service on another host address" tcp attacker 198.51.100.1 7777
blocked "a published port through the gateway" tcp attacker "${gateway}" 18080
blocked "a published port on another host address" tcp attacker 198.51.100.1 18080
# A bridge hands frames to link-local group addresses to the host on the container's
# port, past the bridge's checks. Reverse path filtering would drop them too; turn it off
# so the check shows Portcullis's rules.
sysctl -qw "net.ipv4.conf.${attacker_port}.rp_filter=0"
unanswered "a host service in a frame to the LLDP address" \
  craft attacker udp --dst 198.51.100.1 --dport 7778 --to-mac 01:80:c2:00:00:0e --src 172.30.99.1
event "frames to link-local group addresses are reported" "event=connection verdict=denied reason=frame container~attacker detail~01:80:c2:00:00:03" \
  craft attacker tcp --dst 198.51.100.1 --dport 7777 --to-mac 01:80:c2:00:00:03 --src 172.30.99.2 --wait 1

# Outside, past the egress rules.
unanswered "ICMP to a listed address" ping_probe attacker 198.51.100.3
unanswered "a frame with a VLAN 0 tag" craft attacker udp --dst 198.51.100.4 --dport 9000 --vlan 0
unanswered "fragments rewriting a listed port" craft attacker udp --dst 198.51.100.3 --dport 9001 --fragment 8 --overlap 9000
check "rejected: a TCP header split over fragments" expect_rejection craft attacker tcp --dst 198.51.100.3 --dport 443 --fragment 8
event "another container's address, into its connection" "event=connection verdict=denied reason=source container~attacker source=${victim_ip} destination=198.51.100.4 detail~victim" \
  craft attacker udp --dst 198.51.100.4 --dport 9000 --src "${victim_ip}" --sport 5555 --wait 1
unanswered "its own address with another MAC" craft attacker udp --dst 198.51.100.4 --dport 9000 --src-mac 02:00:00:00:00:99
flush_checks

# Alone: borrowing the victim's MAC disturbs the victim's traffic.
unanswered "another container's address and MAC" craft attacker udp --dst 198.51.100.4 --dport 9000 --src "${victim_ip}" --src-mac "${victim_mac}"
flush_checks

# A container on two networks, through its MAC on one and its address on the other. Where
# br_netfilter passes bridged traffic through the IP hooks, the egress rules and Docker's
# raw table drop it too; turn that off so the check shows the bridge table's rules.
bridge_nf="$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
# Anything the victim sends tells the bridge where its MAC is, should a check above have
# managed to move it.
in_svc victim ping -c 1 -W 1 "${gateway}" >/dev/null 2>&1
echo 0 >/proc/sys/net/bridge/bridge-nf-call-iptables
unanswered "a container's address on another network, through its MAC" \
  craft attacker tcp --dst "${victim_other_ip}" --dport 8080 --to-mac "${victim_mac}"
event "reported as ICC" "event=connection verdict=denied reason=icc container~attacker destination=${victim_other_ip} destination_container~victim" \
  craft attacker udp --dst "${victim_other_ip}" --dport 9000 --to-mac "${victim_mac}" --wait 1
flush_checks
echo "${bridge_nf}" >/proc/sys/net/bridge/bridge-nf-call-iptables

# From another network, Docker reaches published ports with DNAT: the rules see the
# address and port the container asked for, as its labels list them.
allowed "outsider: a published port through the host, as its label lists" tcp outsider 198.51.100.1 18080
blocked "outsider: the same port through another host address" tcp outsider "${gateway}" 18080
event "reported as asked for" "event=connection verdict=denied reason=egress container~outsider destination=${other_gateway} destination_port=18080" \
  tcp outsider "${other_gateway}" 18080
flush_checks

# Unknown sources are held for Portcullis; filling the queue must not let them through.
flood_then_spoof() {
  craft attacker flood --dst "${victim_ip}" --dport 9000 --count 3000
  craft attacker udp --dst "${victim_ip}" --dport 9000 --src 10.99.0.7
}
expect_no_answer_flood() {
  local output
  output="$(flood_then_spoof)"
  printf '%s\n' "${output}"
  ! grep -q '^answered' <<<"${output}" && grep -Eq '^(nothing|rejected)' <<<"${output}"
}
check "unanswered: an unknown source after a flood of them" expect_no_answer_flood
flush_checks

# A resolver one container may use can't widen another container's hostname rules.
allowed "attacker: a lookup from the lying resolver" dns attacker 198.51.100.4 api.test
flush_checks
allowed "attacker: the address its own resolver gave" tcp attacker 198.51.100.5 80
blocked "victim: an address another container's resolver gave" tcp victim 198.51.100.5 80
flush_checks

# Reports and alerts can't be flooded away: denials after tens of thousands of others are
# still reported, and the flood raises a handful of alerts, not tens of thousands.
scan_then_deny() {
  craft attacker scan --dst 198.51.100.9 --count 70000
  expect_event "event=connection verdict=denied reason=egress container~attacker destination=198.51.100.8 destination_port=80" \
    tcp attacker 198.51.100.8 80
}
check "reported: a denial after 70000 others" scan_then_deny
flush_checks
check "alerts of the flood are held back" wait_for_line "${ALERT_LOG}" '"kind":"alerts_suppressed","container":"pc-bypass-attacker-1"'
flush_checks

# The next container to get a removed container's address doesn't get its connections.
in_svc victim sh -c 'printf flow | socat -t2 -T2 - UDP:198.51.100.4:9000,sourceport=5556' >/dev/null
dc rm -sf victim >/dev/null 2>&1
heir="${PROJECT}-heir"
docker run -d --name "${heir}" --network "${PROJECT}_net" --ip "${victim_ip}" "${TESTER_IMAGE}" >/dev/null
wait_managed "${victim_ip}"
heir_flow() {
  local output
  output="$(docker exec "${heir}" sh -c 'printf flow | socat -t3 -T3 - UDP:198.51.100.4:9000,sourceport=5556' 2>&1)"
  printf 'answer: %s\n' "${output}"
  [[ "${output}" != *198.51.100.4* ]]
}
check "unanswered: a removed container's connection, from the next one with its address" heir_flow
flush_checks
docker rm -f "${heir}" >/dev/null
kill "${host_udp_service}"
stop_host_service
