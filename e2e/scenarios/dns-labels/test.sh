wait_managed "$(svc_ip by-ip net)"
wait_managed "$(svc_ip any net)"
wait_managed "$(svc_ip runtime net)"
allowed "dns ip: listed resolver" dns by-ip 198.51.100.2 api.test
allowed "dns *: any resolver" dns any 198.51.100.2 api.test
allowed "dns runtime: resolver from --dns" dns runtime 198.51.100.2 api.test
blocked "dns ip: other traffic to the resolver address" tcp by-ip 198.51.100.2 80
