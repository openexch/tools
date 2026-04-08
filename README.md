# Open Exchange — Tools

Standalone test and simulation tools for the Open Exchange platform. These are language-mismatched (Go/Python) utilities that are used across multiple services.

## Tools

### binance-replay

Go-based market data simulator. Replays realistic order book activity via WebSocket and HTTP, simulating a Binance-like data feed for local development and testing.

```bash
cd binance-replay
go build
./binance-replay
```

### loadgen

Go-based HTTP load generator for stress-testing API endpoints.

```bash
cd loadgen
go build
./loadgen
```

### chaos

Python chaos engineering test suite for validating cluster resilience under failure conditions.

```bash
python chaos/chaos-master.py
```

## Prerequisites

- Go 1.22+ (for binance-replay and loadgen)
- Python 3.10+ (for chaos)
- Running Open Exchange cluster (matching engine, OMS, gateways)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
