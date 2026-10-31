wait_managed "$(svc_ip app net)"
wait_managed "$(svc_ip loner net)"
allowed "allow-listed: service name, first replica" tcp app "$(svc_ip db net 1)" 5432
allowed "allow-listed: service name, second replica" tcp app "$(svc_ip db net 2)" 5432
blocked "allow-listed: listed container, unlisted port" tcp app "$(svc_ip db net 1)" 6379
allowed "allow-listed: network alias" tcp app "$(svc_ip cache net)" 6379
allowed "allow-listed: container name" tcp app "$(svc_ip named net)" 8080
blocked "allow-listed: unlisted container" tcp app "$(svc_ip other net)" 5432
allowed "unrestricted container can still connect to the allow-listed one" tcp db "$(svc_ip app net)" 5432
blocked "deny: outgoing ICC" tcp loner "$(svc_ip other net)" 5432
allowed "deny: incoming ICC from an unrestricted container" tcp other "$(svc_ip loner net)" 5432
