---
title: An application with a database and a cache
description: Let an API reach its database and cache, and nothing else on the network; give the database no outbound access.
sidebar:
  label: Database and cache
  order: 2
---

An API uses PostgreSQL and Redis, and sends telemetry to one host. The database and the cache never open connections of their own.

```yaml title="docker-compose.yml"
services:
  api:
    image: ghcr.io/acme/api:latest
    networks: [backend]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432
      - portcullis.icc.allow.cache=container:redis,tcp:6379
      - portcullis.egress.telemetry=host:telemetry.acme.io,tcp:443

  db:
    image: postgres:16
    networks: [backend]
    labels:
      - portcullis.icc.mode=deny

  redis:
    image: redis:7
    networks: [backend]
    labels:
      - portcullis.icc.mode=deny

networks:
  backend:
    labels:
      - portcullis.enable=true
```

## What each label does

`portcullis.icc.mode=allow-listed` on `api` blocks connections to other containers on `backend`, except for the `portcullis.icc.allow.*` entries.

`portcullis.icc.allow.db=container:db,tcp:5432` allows TCP 5432 to the container Docker's DNS resolves `db` to from `api`. Compose gives every container its service name as a network alias, so `db` matches the container `myproject-db-1`. If a service runs several replicas, all of them match. Only addresses on a network both containers share are allowed.

`portcullis.egress.telemetry=host:telemetry.acme.io,tcp:443` allows the API one destination outside the network.

`portcullis.icc.mode=deny` on `db` and `redis` stops them from opening connections to other containers. They still answer the API's connections: the mode only controls connections the container starts, and replies are always allowed. With no egress labels they can't reach anything outside the network either.

## Variations

To let several services of one kind through, use a [pattern](/policy/patterns/): `container:worker-*,tcp:8080` matches every service whose name starts with `worker-`.

A service on two networks can only reach a target through a network they share. Put the database on a network of its own with the API, and the API on a second one with the frontend, if the frontend must not even see the database's address.

## What this doesn't cover

- Who may connect to `db` is decided by the labels of the connecting container, not by `db`'s. Any container on `backend` with ICC mode `allow` (the default) can reach it. Give every container on the network an explicit mode.
- With `deny` and `allow-listed`, broadcast and multicast are blocked too. A service that needs multicast takes a `multicast:` entry, see [A multicast cluster](/examples/multicast-cluster/).
