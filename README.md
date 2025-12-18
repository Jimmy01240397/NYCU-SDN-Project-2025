# NYCU-SDN-Project-2025

## How to run

1. Set your env in `docker-compose.yml`

2. Include `openvswitch` kernel module

```bash
modprobe openvswitch
```

3. `docker compose up -d`

## How to add onos app

Push your app to `sandbox/onos/apps`

## How to set frr config

For main net frr, configs are at `sandbox/routeserver/frr`

For transit net frr, configs are at `sandbox/transitrouter/frr`

