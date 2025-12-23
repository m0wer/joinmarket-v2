# JoinMarket Taker Client

A taker (CoinJoin initiator) client for JoinMarket privacy-enhancing transactions. Takers pay fees to makers in exchange for mixing their bitcoin with other participants.

## Features

- Protocol v5 compatible with reference JoinMarket and Neutrino backends
- Smart maker selection with fidelity bond weighting
- PoDLE commitment generation (anti-sybil)
- Transaction building with input/output shuffling for privacy
- Tumbler support for automated multi-CoinJoin mixing
- Configurable broadcast policy for maximum privacy
- Support for Bitcoin full node or Neutrino light client backends

## Requirements

- Python 3.11+
- Tor (for connecting to directory nodes)
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
jm-wallet generate --save --output ~/.jm/wallets/taker.mnemonic
```

**IMPORTANT**: Write down your mnemonic and store it securely offline. Anyone with this phrase can spend your Bitcoin.

### 1. Check your wallet balance

```bash
export MNEMONIC="your twelve word mnemonic phrase here"
jm-wallet info

# Or using a saved mnemonic file
jm-wallet info --mnemonic-file ~/.jm/wallets/taker.mnemonic
```

For more wallet management commands (listing fidelity bonds, etc.), see the [jmwallet README](../jmwallet/README.md).

### 2. Fund your wallet

Send bitcoin to one of the displayed addresses.

### 3. Execute a CoinJoin

```bash
jm-taker coinjoin --amount 1000000 --destination INTERNAL
```

This will mix 1,000,000 sats (0.01 BTC) to the next mixdepth in your wallet.

## CLI Reference

### `jm-taker coinjoin`

Execute a single CoinJoin transaction.

```
Options:
  -a, --amount INTEGER         Amount in sats (0 for sweep) [required]
  -d, --destination TEXT       Destination address or 'INTERNAL' [default: INTERNAL]
  -m, --mixdepth INTEGER       Source mixdepth [default: 0]
  -n, --counterparties INTEGER Number of makers [default: 3]
  --mnemonic TEXT              BIP39 mnemonic phrase [env: MNEMONIC]
  --network TEXT               Protocol network [default: mainnet]
  --bitcoin-network TEXT       Bitcoin network for addresses
  -b, --backend TEXT           Backend: full_node | neutrino [default: full_node]
  --rpc-url TEXT               Full node RPC URL [env: BITCOIN_RPC_URL]
  --rpc-user TEXT              Full node RPC user [env: BITCOIN_RPC_USER]
  --rpc-password TEXT          Full node RPC password [env: BITCOIN_RPC_PASSWORD]
  --neutrino-url TEXT          Neutrino REST API URL [env: NEUTRINO_URL]
  -D, --directory TEXT         Directory servers (comma-separated) [env: DIRECTORY_SERVERS]
  --max-abs-fee INTEGER        Max absolute fee in sats [default: 500]
  --max-rel-fee TEXT           Max relative fee (0.001=0.1%) [default: 0.001]
  -l, --log-level TEXT         Log level [default: INFO]
```

### `jm-taker tumble`

Run an automated tumbler schedule for enhanced privacy.

```
Arguments:
  SCHEDULE_FILE                Path to schedule JSON file [required]

Options:
  --mnemonic TEXT              BIP39 mnemonic phrase [env: MNEMONIC]
  --network TEXT               Bitcoin network [default: mainnet]
  -b, --backend TEXT           Backend: full_node | neutrino [default: full_node]
  --rpc-url TEXT               Full node RPC URL [env: BITCOIN_RPC_URL]
  --rpc-user TEXT              Full node RPC user [env: BITCOIN_RPC_USER]
  --rpc-password TEXT          Full node RPC password [env: BITCOIN_RPC_PASSWORD]
  --neutrino-url TEXT          Neutrino REST API URL [env: NEUTRINO_URL]
  -D, --directory TEXT         Directory servers (comma-separated) [env: DIRECTORY_SERVERS]
  -l, --log-level TEXT         Log level [default: INFO]
```

## Examples

### Basic CoinJoin to Internal Address

Mix funds within your wallet (to the next mixdepth):

```bash
jm-taker coinjoin --amount 500000 --destination INTERNAL
```

### CoinJoin to External Address

Send mixed funds to an external address:

```bash
jm-taker coinjoin --amount 500000 --destination bc1qexampleaddress...
```

### Sweep Entire Mixdepth

Mix all funds from a mixdepth (amount=0 means sweep):

```bash
jm-taker coinjoin --amount 0 --mixdepth 2 --destination INTERNAL
```

### Custom Fee Limits

Set stricter fee limits:

```bash
jm-taker coinjoin \
  --amount 1000000 \
  --max-abs-fee 200 \
  --max-rel-fee 0.0005
```

### More Counterparties

Use more makers for enhanced privacy:

```bash
jm-taker coinjoin --amount 1000000 --counterparties 6
```

## Tumbler Schedule

The tumbler executes a series of CoinJoins according to a schedule file.

### Schedule Format

```json
{
  "entries": [
    {
      "mixdepth": 0,
      "amount": 0.5,
      "counterparty_count": 4,
      "destination": "INTERNAL",
      "wait_time": 300
    },
    {
      "mixdepth": 1,
      "amount": 500000,
      "counterparty_count": 3,
      "destination": "INTERNAL",
      "wait_time": 600
    },
    {
      "mixdepth": 2,
      "amount": 0,
      "counterparty_count": 5,
      "destination": "bc1qfinaladdress...",
      "wait_time": 0
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `mixdepth` | Source mixdepth (0-4) |
| `amount` | Sats (integer) or fraction of balance (0-1 float). 0 = sweep |
| `counterparty_count` | Number of makers (1-20) |
| `destination` | Address or "INTERNAL" for next mixdepth |
| `wait_time` | Seconds to wait after this CoinJoin completes |

### Running the Tumbler

```bash
jm-taker tumble schedule.json
```

## Configuration

### Fee Limits

| Option | Default | Description |
|--------|---------|-------------|
| `--max-abs-fee` | 500 | Maximum absolute fee per maker (sats) |
| `--max-rel-fee` | 0.001 | Maximum relative fee (0.1%) |

These limits protect you from overpaying. Offers exceeding these limits are filtered out.

### Maker Selection

The taker uses fidelity bond weighted selection by default. Makers with larger fidelity bonds are more likely to be selected, which incentivizes good behavior and long-term participation.

### Backend Configuration

**Full Node (Bitcoin Core, Knots, etc.):**
```bash
jm-taker coinjoin \
  --amount 1000000 \
  --backend full_node \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user youruser \
  --rpc-password yourpassword
```

**Neutrino (light client):**
```bash
jm-taker coinjoin \
  --amount 1000000 \
  --backend neutrino \
  --neutrino-url http://127.0.0.1:8334
```

## Docker

### Build

```bash
docker build -t jm-taker -f Dockerfile ..
```

### Docker Compose with Full Node

```yaml
services:
  taker:
    build:
      context: ..
      dockerfile: taker/Dockerfile
    environment:
      MNEMONIC: "your twelve word mnemonic phrase here"
      NETWORK: mainnet
      BITCOIN_RPC_URL: http://bitcoind:8332
      BITCOIN_RPC_USER: rpcuser
      BITCOIN_RPC_PASSWORD: rpcpassword
    command: >
      jm-taker coinjoin
        --amount 1000000
        --destination INTERNAL
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
  taker:
    build:
      context: ..
      dockerfile: taker/Dockerfile
    environment:
      MNEMONIC: "your twelve word mnemonic phrase here"
      NETWORK: mainnet
      NEUTRINO_URL: http://neutrino:8334
    command: >
      jm-taker coinjoin
        --amount 1000000
        --backend neutrino
        --destination INTERNAL
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
| `BITCOIN_RPC_URL` | Full node RPC URL |
| `BITCOIN_RPC_USER` | Full node RPC username |
| `BITCOIN_RPC_PASSWORD` | Full node RPC password |
| `NEUTRINO_URL` | Neutrino REST API URL |
| `DIRECTORY_SERVERS` | Comma-separated directory servers |

## Privacy Considerations

### Broadcast Policy

The transaction broadcast policy affects your privacy:

- **SELF**: Taker broadcasts via own node. Links your IP to the transaction.
- **RANDOM_PEER** (default): Random selection from makers + self. Plausible deniability.
- **NOT_SELF**: Only makers broadcast. Maximum privacy, but no fallback if makers fail.

### Tips for Better Privacy

1. **Use more counterparties**: More makers means more possible sources for each output
2. **Use the tumbler**: Multiple CoinJoins over time break the transaction graph
3. **Wait between CoinJoins**: Add `wait_time` in tumbler schedules
4. **Use Tor**: All connections go through Tor by default
5. **Avoid round amounts**: The taker amount in CoinJoins can be an identifier

## Troubleshooting

### "No suitable makers found"
- Check that directory servers are reachable
- Lower your fee limits if they're too strict
- Try during peak hours when more makers are online

### "PoDLE commitment failed"
- Ensure your UTXOs have sufficient confirmations (default: 5)
- Check that UTXO value is at least 20% of CoinJoin amount

### "CoinJoin failed: timeout"
- Increase `--maker-timeout` if makers are slow to respond
- Try with fewer counterparties

### "Insufficient balance"
- Check `jm-wallet info` for available balance
- Remember that some balance is reserved for fees

## License

MIT
