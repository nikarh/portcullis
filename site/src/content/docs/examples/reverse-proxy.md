---
title: A reverse proxy with the Docker socket
description: Run Traefik on an enforced network, limited to its backends and the ACME API, and acknowledge its Docker socket.
sidebar:
  label: Reverse proxy
  order: 4
---

Traefik takes requests on published ports 80 and 443, forwards them to backends on the same network, gets certificates from Let's Encrypt, and reads the Docker socket to find its routes.

```yaml title="docker-compose.yml"
services:
  traefik:
    image: traefik:v3
    command:
      - --providers.docker=true
      - --providers.docker.exposedbydefault=false
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.le.acme.httpchallenge.entrypoint=web
      - --certificatesresolvers.le.acme.email=ops@example.com
      - --certificatesresolvers.le.acme.storage=/certs/acme.json
    ports: ["80:80", "443:443"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - certs:/certs
    networks: [web]
    labels:
      - portcullis.ack=docker-socket
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.app=container:app,tcp:8080
      - portcullis.egress.acme=host:acme-v02.api.letsencrypt.org,tcp:443

  app:
    image: ghcr.io/acme/app:latest
    networks: [web]
    labels:
      - portcullis.icc.mode=deny
      - traefik.enable=true
      - traefik.http.routers.app.rule=Host(`app.example.com`)
      - traefik.http.routers.app.tls.certresolver=le
      - traefik.http.services.app.loadbalancer.server.port=8080

networks:
  web:
    labels:
      - portcullis.enable=true

volumes:
  certs:
```

## What each label does

`portcullis.ack=docker-socket` acknowledges the `docker_socket` [configuration check](/policy/checks/). Without it, Portcullis reports a warning, and raises an alert, every time it starts and whenever the container starts.

`portcullis.icc.mode=allow-listed` with `container:app,tcp:8080` lets Traefik reach the backend on its port, and no other container. Add one entry per backend, or a pattern such as `container:*,tcp:8080` when every backend listens on the same port.

`portcullis.egress.acme=host:acme-v02.api.letsencrypt.org,tcp:443` lets Traefik talk to the ACME API. The HTTP-01 challenge is an incoming request to port 80, which needs no label: replies to connections made to the container are always allowed. With the DNS-01 challenge, Traefik also has to reach your DNS provider's API; add a `host:` rule for it.

`portcullis.icc.mode=deny` on `app` keeps the backend from opening connections to Traefik or anything else on the network. It still answers Traefik's requests.

## The Docker socket

:::danger
The acknowledgement only silences the warning. A container with the Docker socket can start containers outside any rule, attach itself to other networks, or change its own labels by recreating itself. Portcullis can't restrict access over a Unix socket. Mounting it read-only does not help: the Docker API takes write requests over a read-only mount.
:::

To narrow it, put a Docker API proxy that only allows the read calls Traefik needs between Traefik and the socket, and give only the proxy the socket. Then Traefik needs a `container:` rule to the proxy, and the proxy gets the acknowledgement instead.

## What this doesn't cover

- Who can reach ports 80 and 443. Portcullis doesn't filter incoming connections; use the host firewall for that, see [Escape hatches](/limits/escape-hatches/#filtering-incoming-connections).
- Traefik's own plugins, update checks or telemetry, if enabled, need egress labels of their own. Run the network in monitor mode first and read what `portcullis audit` suggests.
