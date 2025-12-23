# JoinMarket Maker Bot

A maker (yield generator) bot for JoinMarket CoinJoin transactions. Makers provide liquidity for privacy-enhancing CoinJoin transactions and earn fees in return.

## Features

- Protocol v5 compatible with reference JoinMarket and Neutrino backends
- Fidelity bond support for improved offer visibility
- PoDLE verification (anti-sybil protection)
- Transaction verification (prevents loss of funds)
- Support for Bitcoin full node or Neutrino light client backends
- Tor integration for privacy

## Requirements

- Python 3.11+
- Tor (for connecting to directory nodes and serving hidden service)
- Bitcoin backend: full node (Bitcoin Core, Knots, etc.) or Neutrino

## Installation

```bash
# Install dependencies
pip install -e ../jmcore
pip install -e ../jmwallet
pip install -e .
```

## Quick Start

### 0. Generate a wallet (optional)

If you don't have a mnemonic yet, generate one with the wallet CLI:

```bash
# Generate and display a new 24-word mnemonic
jm-wallet generate

# Or save to encrypted file
jm-wallet generate --save --output ~/.jm/wallets/maker.mnemonic
```

**IMPORTANT**: Write down your mnemonic and store it securely offline. Anyone with this phrase can spend your Bitcoin.

For more wallet management commands (checking balances, listing fidelity bonds), see the [jmwallet README](../jmwallet/README.md).

### 1. Generate a wallet address

```bash
jm-maker generate-address --mnemonic "your twelve word mnemonic phrase here"
```

### 2. Fund your wallet

Send bitcoin to the generated address. For best results, fund multiple mixdepths.

### 3. Start the maker bot

```bash
jm-maker start --mnemonic "your twelve word mnemonic phrase here"
```

The bot will:
1. Sync your wallet with the blockchain
2. Create offers based on your available balance
3. Connect to JoinMarket directory servers
4. Announce offers and wait for takers

## CLI Reference

### `jm-maker start`

Start the maker bot and begin publishing offers.

```
Options:
  --mnemonic TEXT              BIP39 mnemonic phrase [required]
  --network [mainnet|testnet|signet|regtest]
                               Protocol network [default: mainnet]
  --bitcoin-network [mainnet|testnet|signet|regtest]
                               Bitcoin network for addresses (defaults to --network)
  --backend-type TEXT          Backend: full_node | neutrino [default: full_node]
  --rpc-url TEXT               Bitcoin full node RPC URL [env: BITCOIN_RPC_URL]
  --rpc-user TEXT              Bitcoin full node RPC user [env: BITCOIN_RPC_USER]
  --rpc-password TEXT          Bitcoin full node RPC password [env: BITCOIN_RPC_PASSWORD]
  --neutrino-url TEXT          Neutrino REST API URL [env: NEUTRINO_URL]
  --min-size INTEGER           Minimum CoinJoin size in sats [default: 100000]
  --cj-fee-relative TEXT       Relative fee (e.g., 0.001 = 0.1%) [default: 0.001]
  --cj-fee-absolute INTEGER    Absolute fee in sats [default: 500]
  --tx-fee-contribution INTEGER
                               Tx fee contribution in sats [default: 0]
  --directory-servers TEXT     Directory servers host:port (multiple allowed)
  --fidelity-bond-locktimes INTEGER
                               Fidelity bond locktimes to scan for (multiple allowed)
```

### `jm-maker generate-address`

Generate a new receive address for funding.

```
Options:
  --mnemonic TEXT              BIP39 mnemonic phrase [required]
  --network [mainnet|testnet|signet|regtest]
                               Network [default: mainnet]
  --bitcoin-network [mainnet|testnet|signet|regtest]
                               Bitcoin network for addresses
  --backend-type TEXT          Backend type [default: full_node]
```

## Configuration

### Fee Settings

| Option | Default | Description |
|--------|---------|-------------|
| `--cj-fee-relative` | 0.001 | Relative fee as decimal (0.001 = 0.1%) |
| `--cj-fee-absolute` | 500 | Absolute fee in satoshis |
| `--tx-fee-contribution` | 0 | Mining fee contribution per tx |
| `--min-size` | 100000 | Minimum CoinJoin amount (sats) |

### Backend Configuration

**Full Node (Bitcoin Core, Knots, etc.):**
```bash
jm-maker start \
  --mnemonic "..." \
  --backend-type full_node \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user youruser \
  --rpc-password yourpassword
```

**Neutrino (light client):**
```bash
jm-maker start \
  --mnemonic "..." \
  --backend-type neutrino \
  --neutrino-url http://127.0.0.1:8334
```

### Fidelity Bonds

Fidelity bonds increase your offer visibility in the orderbook. To use fidelity bonds:

1. Create a timelocked UTXO at the fidelity bond address (mixdepth 0, internal branch 2)
2. Specify the locktime when starting the maker:

```bash
jm-maker start \
  --mnemonic "..." \
  --fidelity-bond-locktimes 1735689600 \
  --fidelity-bond-locktimes 1767225600
```

The locktime should be a Unix timestamp. Common practice is to use dates like January 1st of future years.

## Docker

### Build

```bash
docker build -t jm-maker -f Dockerfile ..
```

### Docker Compose with Full Node

```yaml
services:
  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC: "your twelve word mnemonic phrase here"
      NETWORK: mainnet
      BACKEND_TYPE: full_node
      BITCOIN_RPC_URL: http://bitcoind:8332
      BITCOIN_RPC_USER: rpcuser
      BITCOIN_RPC_PASSWORD: rpcpassword
      CJ_FEE_RELATIVE: "0.001"
      MIN_SIZE: "100000"
    depends_on:
      - bitcoind
      - tor
    networks:
      - jm-network

  bitcoind:
    image: kylemanna/bitcoind
    volumes:
      - bitcoin-data:/bitcoin/.bitcoin
    networks:
      - jm-network

  tor:
    image: dperson/torproxy
    environment:
      TOR_NewCircuitPeriod: 30
    networks:
      - jm-network

networks:
  jm-network:

volumes:
  bitcoin-data:
```

### Docker Compose with Neutrino

```yaml
services:
  maker:
    build:
      context: ..
      dockerfile: maker/Dockerfile
    environment:
      MNEMONIC: "your twelve word mnemonic phrase here"
      NETWORK: mainnet
      BACKEND_TYPE: neutrino
      NEUTRINO_URL: http://neutrino:8334
      CJ_FEE_RELATIVE: "0.001"
      MIN_SIZE: "100000"
    depends_on:
      - neutrino
      - tor
    networks:
      - jm-network

  neutrino:
    image: lightninglabs/neutrino:latest
    command:
      - --mainnet
      - --rpcuser=neutrino
      - --rpcpass=neutrino
    volumes:
      - neutrino-data:/data
    networks:
      - jm-network

  tor:
    image: dperson/torproxy
    networks:
      - jm-network

networks:
  jm-network:

volumes:
  neutrino-data:
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MNEMONIC` | BIP39 mnemonic phrase |
| `NETWORK` | Protocol network (mainnet, testnet, signet, regtest) |
| `BITCOIN_NETWORK` | Bitcoin network for addresses |
| `BACKEND_TYPE` | Backend type (full_node, neutrino) |
| `BITCOIN_RPC_URL` | Full node RPC URL |
| `BITCOIN_RPC_USER` | Full node RPC username |
| `BITCOIN_RPC_PASSWORD` | Full node RPC password |
| `NEUTRINO_URL` | Neutrino REST API URL |
| `DIRECTORY_SERVERS` | Comma-separated directory servers |
| `CJ_FEE_RELATIVE` | Relative CoinJoin fee |
| `CJ_FEE_ABSOLUTE` | Absolute CoinJoin fee |
| `TX_FEE_CONTRIBUTION` | Transaction fee contribution |
| `MIN_SIZE` | Minimum CoinJoin size |
| `FIDELITY_BOND_LOCKTIMES` | Comma-separated fidelity bond locktimes |

## Security Considerations

- **Never share your mnemonic phrase**
- Store the mnemonic securely (hardware wallet, encrypted storage)
- The maker bot verifies all transactions before signing to prevent fund loss
- Use Tor for privacy when connecting to directory servers
- Consider running on a dedicated machine or VM

## Troubleshooting

### "No offers created"
- Check that your wallet has sufficient balance
- Minimum offer size is 100,000 sats by default

### "Failed to connect to directory server"
- Ensure Tor is running and accessible
- Check that the directory server addresses are correct

### "Transaction verification failed"
- This is a safety feature - the transaction proposed by the taker was invalid
- No action needed, your funds are safe

## License

MIT
