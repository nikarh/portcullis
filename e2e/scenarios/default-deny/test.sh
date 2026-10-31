wait_managed "$(svc_ip app net)"
wait_managed "$(svc_ip peer net)"
allowed "container on a plain network reaches outside" tcp free 198.51.100.5 80
blocked "outbound TCP" tcp app 198.51.100.5 80
blocked "outbound UDP" udp app 198.51.100.5 9000
blocked "DNS straight to a resolver that is not an upstream" dns peer 198.51.100.2 api.test
allowed "DNS straight to the container's own --dns upstream" dns app 198.51.100.2 api.test
allowed "container on the same network" tcp app "$(svc_ip peer net)" 5432
allowed "name resolution through Docker's DNS using the container's --dns" resolve app api.test
allowed "name resolution through Docker's DNS using the host's resolvers" resolve peer deb.debian.org
