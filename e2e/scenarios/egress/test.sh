wait_managed "$(svc_ip app net)"
allowed "listed address and port" tcp app 198.51.100.3 80
blocked "listed address, other port" tcp app 198.51.100.3 443
blocked "unlisted address" tcp app 198.51.100.5 80
allowed "listed UDP port" udp app 198.51.100.4 9000
blocked "unlisted UDP address" udp app 198.51.100.5 9000
allowed "address inside a listed CIDR" tcp app 198.51.100.2 8080
blocked "address outside a listed CIDR" tcp app 198.51.100.4 8080
