#!/bin/sh
# Reads an HTTP request head, then answers with the address it was sent to (see outside.sh).
while IFS= read -r line; do
  [ "${line%"$(printf '\r')"}" = "" ] && break
done
printf 'HTTP/1.0 200 OK\r\n\r\n%s\n' "${SOCAT_SOCKADDR}"
