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

## Command Line Interface

The `jm-wallet` CLI provides wallet management commands for generating mnemonics, checking balances, and managing fidelity bonds.

### Installation

After installing the package, the CLI is available as `jm-wallet`:

```bash
pip install -e jmwallet
jm-wallet --help
```

### Generate New Wallet

Generate a secure BIP39 mnemonic:

```bash
# Generate 24-word mnemonic (recommended)
jm-wallet generate

# Generate 12-word mnemonic
jm-wallet generate --words 12

# Save to file
jm-wallet generate --save --output ~/.jm/wallets/my-wallet.mnemonic
```

**IMPORTANT**: Write down your mnemonic and store it securely offline. Anyone with this phrase can spend your Bitcoin.

### View Wallet Balance

Display balances for all mixdepths:

```bash
# Using mnemonic from environment
export MNEMONIC="your twelve or twenty four word mnemonic phrase here"
jm-wallet info

# Using mnemonic file
jm-wallet info --mnemonic-file ~/.jm/wallets/my-wallet.mnemonic

# With custom backend (mainnet full node)
jm-wallet info \
  --network mainnet \
  --backend full_node \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user bitcoin \
  --rpc-password yourpassword
```

Output example:
```
Total Balance: 10,500,000 sats (0.10500000 BTC)

Balance by mixdepth:
  Mixdepth 0:       5,000,000 sats  |  bc1q...
  Mixdepth 1:       3,000,000 sats  |  bc1q...
  Mixdepth 2:       2,500,000 sats  |  bc1q...
  Mixdepth 3:               0 sats  |  bc1q...
  Mixdepth 4:               0 sats  |  bc1q...
```

### List Fidelity Bonds

View all fidelity bonds (time-locked UTXOs) in your wallet:

```bash
jm-wallet list-bonds \
  --mnemonic-file ~/.jm/wallets/my-wallet.mnemonic \
  --network mainnet
```

Output example:
```
Found 2 fidelity bond(s):

Bond #1:
  UTXO:        abcd1234...5678:0
  Value:       10,000,000 sats (0.10000000 BTC)
  Locktime:    1735689600 (2025-01-01 00:00:00)
  Confirms:    144
  Bond Value:  5,234,567
Bond #2:
  UTXO:        efgh9012...3456:1
  Value:       5,000,000 sats (0.05000000 BTC)
  Locktime:    1767225600 (2026-01-01 00:00:00)
  Confirms:    72
  Bond Value:  3,456,789
```

### Using with Maker/Taker

The `jm-wallet` CLI is independent of the maker and taker bots. Use it for:

1. **Initial Setup**: Generate and store your mnemonic securely
2. **Balance Checks**: Monitor your wallet without running a bot
3. **Fidelity Bonds**: View your bonds before starting a maker

For CoinJoin operations, use `jm-maker` or `jm-taker` CLIs with the same mnemonic.

## Wallet Structure

JoinMarket uses a mixdepth structure for privacy:

- **Mixdepth 0-4**: Separate balance pools
- **Internal Branches**:
  - Branch 0: External (receive addresses)
  - Branch 1: Internal (change addresses)
  - Branch 2: Fidelity bonds (time-locked UTXOs)

**Privacy Note**: Never merge coins across mixdepths outside of CoinJoin!

## Security Considerations

### Mnemonic Storage

- **NEVER** commit mnemonics to version control
- **NEVER** send mnemonics over unencrypted channels
- Store encrypted mnemonic files with restricted permissions (`chmod 600`)
- Consider hardware wallet integration for production use

### File Permissions

The CLI automatically sets restrictive permissions on saved mnemonic files:

```bash
# Check permissions
ls -l ~/.jm/wallets/my-wallet.mnemonic
# Should show: -rw------- (owner read/write only)
```

### Environment Variables

For automation, use environment variables instead of command-line arguments (prevents exposure in shell history):

```bash
export MNEMONIC="your mnemonic here"
jm-wallet info
```
