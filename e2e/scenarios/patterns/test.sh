# shellcheck shell=bash
wait_managed "$(svc_ip ports net)" "$(svc_ip public net)" "$(svc_ip anywhere net)" \
  "$(svc_ip wild net)" "$(svc_ip deep net)" "$(svc_ip glob net)" "$(svc_ip names net)" \
  "$(svc_ip client icc)"
gateway="$(docker network inspect -f '{{(index .IPAM.Config 0).Gateway}}' "${PROJECT}_net")"

# Ranges include both ends, lists name each port, * any port of the protocol.
allowed "ports: the first port of a range" tcp ports 198.51.100.2 443
allowed "ports: the last port of a range" tcp ports 198.51.100.2 8080
blocked "ports: a port below a range" tcp ports 198.51.100.2 80
flush_checks
allowed "ports: the first port of a list" tcp ports 198.51.100.3 80
allowed "ports: the second port of a list" tcp ports 198.51.100.3 8080
blocked "ports: a port between those of a list" tcp ports 198.51.100.3 443
allowed "ports: udp:* allows UDP" udp ports 198.51.100.5 9000
blocked "ports: udp:* doesn't allow TCP" tcp ports 198.51.100.5 80
allowed "ports: * allows TCP" tcp ports 198.51.100.4 80
allowed "ports: * allows UDP" udp ports 198.51.100.4 9000
allowed "ports: * allows ICMP" ping_probe ports 198.51.100.4
flush_checks
blocked "ports: * doesn't allow DNS, which only DNS labels do" dns ports 198.51.100.4 api.test
allowed "ports: icmp allows ping" ping_probe ports 11.22.33.2
blocked "ports: icmp doesn't allow TCP" tcp ports 11.22.33.2 80
unanswered "ports: icmp only to its destination" ping_probe ports 11.22.33.3
flush_checks

# ip:public: public addresses only, none of the host's, however reached. The kernel limits
# the rejections it sends one container to a few at once: a handful of checks at a time.
allowed "public: a public address" tcp public 11.22.33.3 80
blocked "public: only the protocols listed" udp public 11.22.33.3 9000
blocked "public: a documentation range" tcp public 198.51.100.3 80
blocked "public: the gateway, the host" tcp public "${gateway}" 22
flush_checks
blocked "public: the host's own public address" tcp public 11.22.33.1 22
# A flow is reported once a minute: this is the only probe of it.
event "public: a published port, through the host's public address, denied as asked for" "event=connection verdict=denied reason=egress container~public destination=11.22.33.1 destination_port=18081" \
  tcp public 11.22.33.1 18081
blocked "public: a private address" tcp public 10.0.2.2 80
flush_checks
blocked "public: the link-local metadata address" tcp public 169.254.169.254 80
flush_checks
blocked "public: a shared (CGNAT) address" tcp public 100.64.0.1 80
# ip:* includes all of them.
allowed "anywhere: a public address" tcp anywhere 11.22.33.3 80
allowed "anywhere: the host" tcp anywhere 11.22.33.1 22
allowed "anywhere: a published port through the host" tcp anywhere 11.22.33.1 18081
flush_checks

# Patterns: addresses only from the container's own lookups of matching names.
blocked "wild: nothing before a lookup" tcp wild 11.22.33.2 80
flush_checks
for name in one.wild.test deep.two.wild.test wild.test evilwild.test; do
  in_svc wild nslookup -timeout=3 "${name}" >/dev/null 2>&1
done
for name in s1.sub.test t1.sub.test; do
  in_svc glob nslookup -timeout=3 "${name}" >/dev/null 2>&1
done
for name in deep.two.wild.test wild.test; do
  in_svc deep nslookup -timeout=3 "${name}" >/dev/null 2>&1
done
allowed "wild: a name one level below" tcp wild 11.22.33.2 80
blocked "wild: a name two levels below" tcp wild 11.22.33.3 80
blocked "wild: the domain itself" tcp wild 11.22.33.4 80
blocked "wild: a name that only ends the same" tcp wild 11.22.33.5 80
allowed "deep: a name two levels below" tcp deep 11.22.33.3 80
blocked "deep: the domain itself" tcp deep 11.22.33.4 80
allowed "glob: a name the label pattern matches" tcp glob 11.22.33.2 80
blocked "glob: a name it doesn't" tcp glob 11.22.33.3 80
event "wild: the connection is labelled with the name" 'event=connection verdict=denied container~wild domain=one.wild.test domain_source=dns destination_port=443' \
  tcp wild 11.22.33.2 443
flush_checks

# The same patterns limit the names a container may look up.
allowed "names: a name one level below" resolve names one.wild.test
blocked "names: a name two levels below" resolve names deep.two.wild.test
blocked "names: the domain itself" resolve names wild.test
flush_checks

# Container patterns match names and aliases on the shared network.
allowed "client: the first matching container" tcp client "$(svc_ip worker-a icc)" 8080
allowed "client: the second matching container" tcp client "$(svc_ip worker-b icc)" 8080
blocked "client: a matching container, another port" tcp client "$(svc_ip worker-a icc)" 5432
blocked "client: a container that doesn't match" tcp client "$(svc_ip db icc)" 8080
allowed "client: container:* with icmp" ping_probe client "$(svc_ip db icc)"
