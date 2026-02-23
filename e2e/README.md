# E2E Test Suite

This suite validates real container connectivity with Docker Compose and Portcullis firewall enforcement.

## Coverage
- same subnet ICC with `allow-listed` mode
- same subnet ICC with `deny` mode
- different subnet egress allowlist behavior
- TCP checks (`nc -z`)
- UDP checks (`socat` echo path)
- positive and negative assertions for each scenario

## Prerequisites
- Docker + Docker Compose plugin
- Linux host with firewall capabilities available to Portcullis
- Portcullis binary built (`cargo build --release`) or let `run-all.sh` build it

## Run all scenarios
```bash
./e2e/run-all.sh
```

## Run single scenario
```bash
./e2e/scenarios/icc-allowlisted/run.sh
./e2e/scenarios/icc-deny/run.sh
./e2e/scenarios/egress-subnets/run.sh
```

## Scenario notes
- `icc-allowlisted`
- verifies `portcullis.icc.allow.<n>=container:<id|name|alias>,<proto:port>`
- includes alias-based target resolution

- `icc-deny`
- verifies all ICC traffic is blocked for managed source container

- `egress-subnets`
- verifies explicit IP+port allowlist across different subnets
- verifies non-whitelisted destinations are blocked

## Important operational note
These tests apply real host firewall rules for container traffic. Run on a disposable test host or controlled CI runner.
