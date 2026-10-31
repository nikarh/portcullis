for service in only-ip only-host host-and-ip any none none-with-dns; do
  wait_managed "$(svc_ip "${service}" net)"
done
allowed "ip: resolution through Docker's DNS via the listed resolver" resolve only-ip api.test
blocked "ip: the host's resolver" dns only-ip 10.0.2.3 deb.debian.org
blocked "ip: other traffic to the resolver address" tcp only-ip 198.51.100.2 80
allowed "host: resolution through Docker's DNS via the host's resolver" resolve only-host deb.debian.org
blocked "host: another resolver" dns only-host 198.51.100.2 api.test
allowed "host + ip: the host's resolver" dns host-and-ip 10.0.2.3 deb.debian.org
allowed "host + ip: the listed resolver" dns host-and-ip 198.51.100.2 api.test
allowed "*: any resolver" dns any 198.51.100.2 api.test
blocked "none: direct queries to the host's resolver" dns none 10.0.2.3 deb.debian.org
allowed "none: container names still resolve" resolve none any
# Without --dns, Docker 29 forwards from the host's network namespace, out of the policy's reach.
allowed "none without --dns: Docker's DNS still resolves through the host" resolve none deb.debian.org
blocked "none with --dns: Docker's DNS can't reach the container's resolver" resolve none-with-dns api.test
