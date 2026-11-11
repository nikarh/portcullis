FROM alpine:3.22
RUN apk add --no-cache bind-tools netcat-openbsd socat scapy iputils-ping
COPY craft.py /usr/local/bin/craft
COPY udp-answer.py /usr/local/bin/udp-answer
# Serve TCP 5432/6379/8080 and UDP 9000, answering with the container's hostname.
CMD ["sh", "-c", "for p in 5432 6379 8080; do socat TCP-LISTEN:$p,fork,reuseaddr SYSTEM:hostname & done; exec udp-answer 9000"]
