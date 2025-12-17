# End-to-End Integration Tests

Complete system tests with all JoinMarket components.

## Quick Start

```bash
# Run ALL tests with a single profile:
docker compose --profile all up -d --build
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests

# Cleanup
docker compose --profile all down -v
```

## Docker Compose Profiles

The unified `docker-compose.yml` uses profiles to organize services:

| Profile | Services | Use Case |
|---------|----------|----------|
| (default) | bitcoin, miner, directory, orderbook-watcher | Core infrastructure |
| `maker` | + maker | Single maker bot |
| `taker` | + taker | Single taker client |
| `e2e` | + maker1, maker2 | E2E tests (our implementation) |
| `reference` | + tor, jam, maker1, maker2 | Reference JAM compatibility tests |
| `all` | e2e + reference (everything) | **Full test suite** |
| `neutrino` | + neutrino, maker-neutrino, taker-neutrino | Light client testing |

## Running Tests

### Full Test Suite (Recommended)

Run ALL tests including reference compatibility:

```bash
# Start all services
docker compose --profile all up -d --build

# Run complete test suite
pytest -lv \
  --cov=jmcore --cov=jmwallet --cov=directory_server \
  --cov=orderbook_watcher --cov=maker --cov=taker \
  jmcore orderbook_watcher directory_server jmwallet maker taker tests

# Cleanup
docker compose --profile all down -v
```

### E2E Tests Only (Faster)

Tests our implementation without reference JAM:

```bash
docker compose --profile e2e up -d --build
pytest tests/e2e/test_complete_system.py -v
docker compose --profile e2e down -v
```

### Reference Tests Only

Tests compatibility with upstream JoinMarket:

```bash
docker compose --profile reference up -d --build
pytest tests/e2e/test_reference_coinjoin.py -v -s
docker compose --profile reference down -v
```

### Skip Reference Tests (When Not Running)

If you run the full test suite without the `reference` profile, reference tests
are **automatically skipped** (not failed):

```bash
# Only core services
docker compose up -d

# Reference tests will be skipped automatically
pytest -lv tests/
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     JoinMarket Test System                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │
│  │   Bitcoin    │◄───│  Directory   │◄───│   Orderbook  │            │
│  │   Regtest    │    │   Server     │    │   Watcher    │            │
│  └──────────────┘    └──────────────┘    └──────────────┘            │
│         ▲                    ▲                                        │
│         │            ┌───────┴────────┐                               │
│         │            │                 │                               │
│  ┌──────┴──────┐  ┌─▼──────────┐  ┌──▼────────┐                       │
│  │   Miner     │  │  Maker 1   │  │  Maker 2  │                       │
│  │  (auto)     │  └────────────┘  └───────────┘                       │
│  └─────────────┘                                                      │
│                                                                       │
│  Reference Profile Only:                                              │
│  ┌──────────────┐    ┌──────────────┐                                │
│  │     Tor      │───►│     JAM      │                                │
│  │   (.onion)   │    │  (Reference) │                                │
│  └──────────────┘    └──────────────┘                                │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Pre-Generated Tor Keys

The reference tests use a **deterministic Tor hidden service** for reproducibility:
- Onion address: `tsc2niuqhhnl35q4tzpyyuogcxscgxhotjrk3ldaynfsgysoctlgwxqd.onion`
- Keys stored in: `tests/e2e/reference/tor_keys/`
- No dynamic configuration needed!

## Test Wallets

Pre-configured test wallet mnemonics (regtest only!):

| Wallet | Mnemonic |
|--------|----------|
| Maker 1 | `avoid whisper mesh corn already blur sudden fine planet chicken hover sniff` |
| Maker 2 | `minute faint grape plate stock mercy tent world space opera apple rocket` |
| Taker | `burden notable love elephant orbit couch message galaxy elevator exile drop toilet` |
| Generic | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |

## Service URLs

| Service | URL |
|---------|-----|
| Bitcoin RPC | http://localhost:18443 |
| Directory Server | localhost:5222 |
| Orderbook Watcher | http://localhost:8080 |
| Neutrino (if enabled) | http://localhost:8334 |

## Troubleshooting

### Check Service Status

```bash
docker compose --profile all ps
docker compose logs <service-name>
```

### Reference Tests Failing?

Make sure JAM is running:
```bash
docker compose --profile reference ps | grep jam
```

If not running, tests should skip automatically. If they fail instead, check:
```bash
docker compose --profile reference logs jam
```

### Wallet Has Zero Balance

The auto-miner and test fixtures should fund wallets automatically. If needed:

```bash
ADDR="bcrt1q..."
docker compose exec bitcoin bitcoin-cli -regtest -rpcuser=test -rpcpassword=test generatetoaddress 110 $ADDR
```

## CI/CD

The GitHub Actions workflow runs all tests automatically:

1. **Unit tests**: Each component tested independently
2. **E2E tests**: Full system integration tests
3. **Reference tests**: Compatibility with upstream JoinMarket (main branch only)

See `.github/workflows/test.yaml` for details.

## Security Notes

⚠️ **These are development/test environments only!**

- Never use on mainnet
- Never use real mnemonics
- Never store real funds
- Only for testing on regtest

---

**Status:** E2E tests fully automated ✓
