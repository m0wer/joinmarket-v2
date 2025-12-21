# JoinMarket Wallet Library (jmwallet)

Modern Hierarchical Deterministic (HD) wallet implementation for JoinMarket refactor.

```
jmwallet/
├── src/jmwallet/
│   ├── backends/         # Blockchain backends (Bitcoin Core, Neutrino)
│   ├── wallet/           # BIP32/39/84 implementation
│   └── __init__.py
├── tests/               # Unit tests
└── pyproject.toml       # Package metadata
```

## Features

- **Multi-backend architecture** (Bitcoin Core RPC, Neutrino SPV)
- **No BerkeleyDB dependency** (works with Bitcoin Core v30+)
- **BIP32/BIP39/BIP84** HD wallet implementation
- **JoinMarket mixdepth support** (5 isolation levels)
- **P2WPKH address generation** (BIP173 bech32)
- **UTXO management + coin selection**
- **Transaction signing utilities** (P2WPKH inputs)

### Solving the BerkeleyDB Problem

Reference JoinMarket requires Bitcoin Core wallet (BerkeleyDB) for `importaddress`, which breaks on Bitcoin Core v30+.

**jmwallet solution:** Connect directly to Bitcoin Core's RPCs (`scantxoutset`, `getblockchaininfo`, etc.) — **no wallet.dat needed!** This makes it compatible with modern Bitcoin Core without deprecated settings.

## Installation

```bash
cd jmwallet
pip install -e .[dev]
```

## Quick Start

```python
import asyncio
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.wallet.service import WalletService

async def main():
    backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test",
    )

    wallet = WalletService(
        mnemonic="abandon abandon ... about",
        backend=backend,
        network="regtest",
    )

    await wallet.sync_all()
    balance = await wallet.get_total_balance()
    print(f"Balance: {balance:,} sats")

    utxos = wallet.select_utxos(mixdepth=0, target_amount=50_000)
    print(f"Selected {len(utxos)} UTXOs")

asyncio.run(main())
```

## Backends

### Bitcoin Core Backend
- Uses `scantxoutset` RPC to find UTXOs
- No need to import addresses into wallet
- Works with v30+ (descriptor wallets)
- **Best for:** Maximum security, production deployments

```python
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend

backend = BitcoinCoreBackend(
    rpc_url="http://127.0.0.1:8332",
    rpc_user="user",
    rpc_password="password",
)
```

### Neutrino Backend (BIP157/158)
- Lightweight SPV using compact block filters
- No full node required (~500MB vs ~500GB)
- Privacy-preserving (downloads filters, not addresses)
- **Best for:** Beginners, low-resource environments, mobile

```python
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig

config = NeutrinoConfig(
    base_url="http://localhost:8080",
    network="mainnet",
    timeout=30.0
)
backend = NeutrinoBackend(config)
```

**Running the Neutrino server:**

The Neutrino server is maintained separately at [github.com/m0wer/neutrino-api](https://github.com/m0wer/neutrino-api).

```bash
# With Docker Compose (from jm-refactor root)
docker-compose --profile neutrino up -d neutrino

# Or run standalone
docker run -d \
  -p 8334:8334 \
  -v neutrino-data:/data/neutrino \
  -e NETWORK=mainnet \
  -e LOG_LEVEL=info \
  ghcr.io/m0wer/neutrino-api
```
