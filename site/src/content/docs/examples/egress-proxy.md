---
title: Egress through a filtering proxy
description: Send a container's HTTP and HTTPS through a proxy that filters by hostname, for when allowing a hostname's addresses is too wide.
sidebar:
  label: Filtering proxy
  order: 6
---

An IP firewall can't match hostnames. A `host:` rule allows the addresses a name resolves to, and behind a CDN those addresses serve thousands of other sites. A pattern such as `host:*.cloudfront.net` allows anyone's server. When that's too wide, let the application reach only a proxy, and let the proxy decide by hostname (the TLS SNI or the `CONNECT` target) or by URL.

Portcullis then does what it does well: it makes the proxy the only way out.

## Proxy as a container

```yaml title="docker-compose.yml"
services:
  app:
    image: ghcr.io/acme/app:latest
    networks: [backend]
    environment:
      HTTP_PROXY: http://proxy:3128
      HTTPS_PROXY: http://proxy:3128
      NO_PROXY: localhost
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.proxy=container:proxy,tcp:3128
      - portcullis.dns.0=none

  proxy:
    image: ubuntu/squid:latest
    volumes:
      - ./squid.conf:/etc/squid/squid.conf:ro
    networks: [backend]
    labels:
      - portcullis.icc.mode=deny
      - portcullis.egress.web=ip:public,tcp:80,443

networks:
  backend:
    labels:
      - portcullis.enable=true
```

`portcullis.icc.allow.proxy=container:proxy,tcp:3128` is the application's only way to anything: it has no egress labels, so it reaches nothing outside the network itself.

`portcullis.dns.0=none` denies DNS queries the application sends to resolvers itself. It still resolves container names, such as `proxy`, through Docker's DNS. With an explicit proxy, the proxy resolves the destination names, so the application doesn't need outside names. Docker's DNS forwards outside lookups for containers with their own DNS servers, or with a daemon-wide `dns` setting, from the container's address, where `none` denies them; without either, Docker 29 resolves them from the host, which no label controls (see [What can and can't be controlled](/policy/dns/#what-can-and-cant-be-controlled)). Set `dns` in `/etc/docker/daemon.json` so that `none` covers Docker's DNS too.

`portcullis.egress.web=ip:public,tcp:80,443` lets the proxy reach any public web server. The proxy's own allow-list decides which ones. A minimal Squid allow-list:

```text title="squid.conf"
http_port 3128
acl allowed dstdomain .github.com api.stripe.com
http_access allow allowed
http_access deny all
```

`ip:public` keeps the proxy itself away from the host and the LAN, whatever its configuration says.

## Proxy on the host

A proxy that runs on the Docker host is reached through the network's gateway, which is the host's address on that network. Traffic to the host follows egress labels like any other destination. Give the network a fixed subnet so the gateway's address is known in advance:

```yaml title="docker-compose.yml"
services:
  app:
    image: ghcr.io/acme/app:latest
    networks: [backend]
    environment:
      HTTPS_PROXY: http://172.30.0.1:3128
    labels:
      - portcullis.egress.proxy=ip:172.30.0.1,tcp:3128

networks:
  backend:
    labels:
      - portcullis.enable=true
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
```

The proxy on the host has no Portcullis rules. Restrict it with its own configuration and the host firewall.

## What this doesn't cover

- Applications that ignore proxy settings fail to connect, and their attempts are reported as denied `egress` events. That's usually how you find them.
- A proxy that intercepts TLS to filter by URL path needs its CA trusted in the application. Filtering by `CONNECT` target or SNI doesn't.
- Protocols other than HTTP(S) need their own proxy, or `host:`/`ip:` rules.
