attacker_ip="$(svc_ip attacker net)"
victim_ip="$(svc_ip victim net)"
wait_managed "${attacker_ip}" "${victim_ip}" "$(svc_ip control net)"
subnet="$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "${PROJECT}_net")"
gateway="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "${PROJECT}_net")"
subnet_broadcast="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1]).broadcast_address)' "${subnet}")"
victim_mac="$(in_svc victim cat /sys/class/net/eth0/address)"
host_service 7777

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

# The host itself.
blocked "a host service through the gateway" tcp attacker "${gateway}" 7777
blocked "a host service on another host address" tcp attacker 198.51.100.1 7777
blocked "a published port through the gateway" tcp attacker "${gateway}" 18080
blocked "a published port on another host address" tcp attacker 198.51.100.1 18080

# Outside, past the egress rules.
unanswered "ICMP to a listed address" ping_probe attacker 198.51.100.3
unanswered "a frame with a VLAN 0 tag" craft attacker udp --dst 198.51.100.4 --dport 9000 --vlan 0
unanswered "fragments rewriting a listed port" craft attacker udp --dst 198.51.100.3 --dport 9001 --fragment 8 --overlap 9000
check "rejected: a TCP header split over fragments" expect_rejection craft attacker tcp --dst 198.51.100.3 --dport 443 --fragment 8
unanswered "another container's address" craft attacker udp --dst 198.51.100.4 --dport 9000 --src "${victim_ip}"
unanswered "its own address with another MAC" craft attacker udp --dst 198.51.100.4 --dport 9000 --src-mac 02:00:00:00:00:99
flush_checks

# Alone: borrowing the victim's MAC disturbs the victim's traffic.
unanswered "another container's address and MAC" craft attacker udp --dst 198.51.100.4 --dport 9000 --src "${victim_ip}" --src-mac "${victim_mac}"
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
stop_host_service
