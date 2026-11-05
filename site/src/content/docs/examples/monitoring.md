---
title: Prometheus scraping exporters
description: Let Prometheus scrape exporters on its network and node_exporter on the host, with exporters that open no connections of their own.
sidebar:
  label: Prometheus
  order: 9
---

Prometheus scrapes exporters running next to it, and `node_exporter` running on the Docker host. Grafana queries Prometheus. None of them needs the internet.

```yaml title="docker-compose.yml"
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks: [metrics]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.exporters=container:*-exporter,tcp:9100-9199
      - portcullis.egress.node=ip:172.29.0.1,tcp:9100

  postgres-exporter:
    image: quay.io/prometheuscommunity/postgres-exporter:latest
    networks: [metrics, db]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.db=container:db,tcp:5432

  redis-exporter:
    image: oliver006/redis_exporter:latest
    networks: [metrics, db]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.redis=container:redis,tcp:6379

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    networks: [metrics]
    labels:
      - portcullis.icc.mode=allow-listed
      - portcullis.icc.allow.prometheus=container:prometheus,tcp:9090

networks:
  metrics:
    labels:
      - portcullis.enable=true
    ipam:
      config:
        - subnet: 172.29.0.0/24
          gateway: 172.29.0.1
  db:
    name: shop-db
    external: true
```

`shop-db` is the enforced network the database and Redis run on, created ahead of time (see [Rolling out on a host with running stacks](/examples/existing-networks/)).

## What each label does

`container:*-exporter,tcp:9100-9199` on Prometheus matches every container on a shared network whose name or alias ends in `-exporter`, on the port range exporters conventionally use (`postgres-exporter` listens on 9187, `redis_exporter` on 9121). A new exporter named that way is covered without touching Prometheus. List exporters one by one with exact ports for a tighter rule.

`portcullis.egress.node=ip:172.29.0.1,tcp:9100` lets Prometheus reach `node_exporter` on the Docker host through the network's gateway. Traffic to the host's addresses follows egress labels, so without this label it's denied. The fixed subnet in `ipam` makes the gateway's address known in advance.

Each exporter is allow-listed to the one service it reads. The exporters are on two networks, and `container:` rules only match addresses on a network both containers share: `postgres-exporter` reaches `db` on `shop-db`, not anything on `metrics`. Since both networks are enforced, there is no `unenforced_network` warning.

Grafana may only query Prometheus. Its published port 3000 is reachable from outside; replies to those connections are always allowed.

## Alerting out

Alertmanager, if added, needs to reach wherever it sends notifications, for example:

```yaml
  alertmanager:
    image: prom/alertmanager:latest
    networks: [metrics]
    labels:
      - portcullis.icc.mode=deny
      - portcullis.egress.ntfy=host:ntfy.example.com,tcp:443
```

and Prometheus needs `container:alertmanager,tcp:9093` in its allow-list.

## What this doesn't cover

- Grafana plugin installs, update checks and usage reporting reach the internet. With no egress labels they're denied and reported. Turn them off in Grafana's configuration, or allow them.
- Portcullis exposes no metrics of its own. Its events are JSON lines; count them in your log pipeline, see [Events and alerts](/guides/events-and-alerts/).
