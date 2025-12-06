# JoinMarket Directory Server

Relay server for peer discovery and message routing in the JoinMarket network.

## Features

- **Peer Discovery**: Register and discover active peers
- **Message Routing**: Forward public broadcasts and private messages
- **Connection Management**: Handle peer connections and disconnections
- **Handshake Protocol**: Verify peer compatibility and network
- **High Performance**: Async I/O with optimized message handling
- **Observability**: Structured logging with loguru
- **Tor Hidden Service**: Run behind Tor for privacy (via separate container)

## Installation

```bash
# Install jmcore first
cd ../jmcore
pip install -e .

# Install directory server
cd ../directory_server
pip install -e .

# Development
pip install -e ".[dev]"
```

## Configuration

Create a `.env` file or set environment variables:

```bash
# Network
NETWORK=mainnet  # mainnet, testnet, signet, regtest
HOST=127.0.0.1
PORT=5222

# Server
MAX_PEERS=10000
MESSAGE_RATE_LIMIT=100
LOG_LEVEL=INFO
```

## Running

### Docker Compose (Recommended)

The recommended deployment uses Docker Compose with an isolated network where the directory server runs behind a Tor hidden service for privacy.

#### Initial Setup

**Important**: The Tor directories and configuration must be set up with proper permissions before starting Docker Compose. If not created manually, Docker will create them as root, causing permission errors.

```bash
# 1. Create directory structure with correct permissions
mkdir -p tor/conf tor/data tor/run
chmod 755 tor/conf tor/run
chmod 700 tor/data
chown -R 1000:1000 tor/

# 2. Create Tor configuration file
cat > tor/conf/torrc << 'EOF'
# JoinMarket Directory Server Hidden Service
HiddenServiceDir /var/lib/tor
HiddenServiceVersion 3
HiddenServicePort 5222 joinmarket_directory_server:5222
EOF

# 3. Start both directory server and Tor (uses pre-built image)
docker compose up -d

# 4. View logs
docker compose logs -f

# 5. Get your onion address (available after first tor startup)
cat tor/data/hostname

# Stop services
docker compose down
```

By default, docker-compose.yml uses the pre-built image `ghcr.io/m0wer/joinmarket-v2-directory-server:master`. To build locally, uncomment the `build` section and comment out the `image` line in docker-compose.yml.

#### Directory Structure After Setup

```
directory_server/
└── tor/
    ├── conf/
    │   └── torrc                    # Tor config (755, uid 1000)
    ├── data/                        # Hidden service keys (700, uid 1000)
    │   ├── hostname                 # Your .onion address (auto-generated)
    │   ├── hs_ed25519_public_key    # Public key (auto-generated)
    │   ├── hs_ed25519_secret_key    # Private key (auto-generated)
    │   └── authorized_clients/      # For client auth (optional)
    └── run/                         # Tor runtime files (755, uid 1000)
```

#### Vanity Onion Address (Optional)

To create a vanity onion address with a custom prefix:

```bash
# 1. Generate vanity address (can take hours/days depending on prefix length)
docker run --rm -it --network none -v $PWD:/keys \
  ghcr.io/cathugger/mkp224o:master -d /keys prefix

# 2. Move generated keys to tor data directory
# Note: mkp224o creates a directory named "prefix<randomchars>.onion"
mv prefix*.onion/hs_ed25519_public_key prefix*.onion/hs_ed25519_secret_key prefix*.onion/hostname tor/data/

# 3. Set correct ownership (uid 1000 required by tor container)
chown -R 1000:1000 tor/data/

# 4. Restart tor to use the new keys
docker compose restart tor

# 5. Verify your new vanity address
cat tor/data/hostname
```

**Note**: Longer prefixes take exponentially longer to generate. A 5-character prefix may take hours, 6+ characters may take days. The vanity generator will create `hs_ed25519_public_key` and `hs_ed25519_secret_key` files which replace the auto-generated ones.

#### Network Architecture & Security

The Docker Compose setup provides maximum security through network isolation:

- **directory_server**: Runs on isolated internal network (`joinmarket_directory_internal`) with **no external internet access**
  - Cannot make outbound connections to the internet
  - Cannot be reached directly from the internet
  - Only accessible through the Tor hidden service
- **tor**: Acts as a secure gateway
  - Connected to both internal network (`joinmarket_directory_internal`) and external network (`joinmarket_directory_external`)
  - Forwards hidden service traffic to directory_server on port 5222
  - Provides .onion address for privacy

This architecture ensures:
- The directory server cannot leak information or be exploited to make external connections
- All connections are anonymized through Tor
- Attack surface is minimized through network isolation
- Even if the directory server is compromised, it cannot access the internet directly



### Development (Local)

```bash
# Start the directory server directly
jm-directory-server

# With custom config
jm-directory-server --config custom.env

# Development mode with debug logging
LOG_LEVEL=DEBUG jm-directory-server
```

**Note**: When running locally, you need to set up Tor separately and configure it to forward traffic to your local directory server.

## Health Check & Monitoring

The directory server provides comprehensive health check and monitoring capabilities.

### Health Check Endpoint

An HTTP server runs on port 8080 (configurable via `HEALTH_CHECK_HOST` and `HEALTH_CHECK_PORT`) providing:

**`GET /health`** - Basic health check
```bash
curl http://localhost:8080/health
# {"status": "healthy"}
```

**`GET /status`** - Detailed server statistics
```bash
curl http://localhost:8080/status
# {
#   "network": "mainnet",
#   "uptime_seconds": 3600,
#   "server_status": "running",
#   "max_peers": 1000,
#   "stats": {
#     "total_peers": 150,
#     "connected_peers": 150,
#     "passive_peers": 45,
#     "active_peers": 105
#   },
#   "connected_peers": {
#     "total": 150,
#     "nicks": ["maker1", "taker1", ...]
#   },
#   "passive_peers": {
#     "total": 45,
#     "nicks": ["taker1", "taker2", ...]
#   },
#   "active_peers": {
#     "total": 105,
#     "nicks": ["maker1", "maker2", ...]
#   },
#   "active_connections": 150
# }
```

### CLI Tool

Use `jm-directory-ctl` to query server status:

```bash
# Check server health
jm-directory-ctl health

# Get detailed status (human-readable)
jm-directory-ctl status

# Get status as JSON
jm-directory-ctl status --json

# Query remote server
jm-directory-ctl status --host 192.168.1.10 --port 8080
```

### Signal-based Status Logging

Send `SIGUSR1` signal to trigger detailed status logging to the server logs:

```bash
# Docker
docker kill -s SIGUSR1 joinmarket_directory_server

# Local process
kill -USR1 $(pgrep jm-directory-server)
```

This will log comprehensive status including:
- Network type and uptime
- Connected peers count and list
- Passive peers (orderbook watchers/takers - NOT-SERVING-ONION)
- Active peers (makers - serving onion address)
- Active connections

### Docker Health Check

The Docker image includes automatic health checks using the CLI command:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["jm-directory-server", "health"]
```

Check container health status:
```bash
docker ps  # Shows (healthy) or (unhealthy)
docker inspect joinmarket_directory_server | grep -A 10 Health
```

### Monitoring Metrics

The server tracks:
- **Connected Peers**: Total number of handshaked peers
- **Passive Peers**: Peers not serving onion (typically orderbook watchers/takers)
  - These peers connect via `NOT-SERVING-ONION` and primarily watch offers
  - Usually takers or bots monitoring the orderbook
  - Don't host their own hidden service
- **Active Peers**: Peers serving onion address (typically makers)
  - These peers host their own hidden service (e.g., `xyz123....onion:5222`)
  - Usually makers publishing liquidity offers to the orderbook
  - Other peers can connect directly to them
- **Active Connections**: Current TCP connections
- **Uptime**: Server uptime in seconds
- **Network**: mainnet/testnet/signet/regtest

### Configuration

Add to your `.env` file:
```bash
# Health check server (optional, defaults shown)
HEALTH_CHECK_HOST=127.0.0.1
HEALTH_CHECK_PORT=8080
```

For Docker deployments, set `HEALTH_CHECK_HOST=0.0.0.0` to allow health checks from the Docker network.

## Architecture

### Components

1. **DirectoryServer**: Main server orchestration
   - Accept incoming connections
   - Handle disconnections
   - Coordinate components

2. **PeerRegistry**: Maintains peer state
   - Register/unregister peers
   - Track peer metadata
   - Peer discovery

3. **MessageRouter**: Routes messages between peers
   - Public message broadcasting
   - Private message routing
   - Message validation

4. **HandshakeHandler**: Handles peer handshakes
   - Protocol version negotiation
   - Network compatibility check
   - Peer authentication

### Message Flow

```
Client -> [Tor Hidden Service] -> Directory Server -> [Tor] -> Client
                                        |
                                   PeerRegistry
                                   MessageRouter
                                   ConnectionPool
```

The directory server is Tor-agnostic and only handles TCP connections. Tor privacy and anonymization is provided by running the server behind a Tor hidden service in a separate, isolated container. The directory server itself does not implement SOCKS5 or Tor protocols - it simply accepts TCP connections that are forwarded by the Tor container.

## Development

```bash
# Run tests
pytest

# Run load tests
pytest tests/test_load.py -v -s

# With coverage
pytest --cov

# Lint
ruff check src tests

# Format
ruff format src tests

# Type check
mypy src
```

### Performance

**Async architecture enables handling significantly more clients with the same hardware compared to the original implementation.**

Production testing with real clients showed excellent resource efficiency:
- **Memory**: <100 MB RAM under normal load
- **CPU**: Minimal usage, server remains responsive
- **Concurrency**: Handles hundreds of simultaneous connections efficiently

Load tests verified performance across real-world scenarios (50-200 concurrent peers):

- **Throughput**: 439 msg/sec peak, 37-206 msg/sec sustained
- **Memory**: ~8 KB per peer (1.6 MB for 200 peers)
- **Scalability**: Linear scaling, no degradation under load
- **Stability**: No memory leaks or failures

Run load tests: `pytest tests/test_load.py -v`

## API

### Handshake

Client connects and sends:
```json
{
  "type": 793,
  "line": "{\"app-name\":\"JoinMarket\",\"proto-ver\":9,...}"
}
```

Directory responds:
```json
{
  "type": 795,
  "line": "{\"app-name\":\"JoinMarket\",\"directory\":true,...}"
}
```

### Peerlist

Directory sends peer list:
```json
{
  "type": 789,
  "line": "nick1;onion1.onion:5222,nick2;onion2.onion:5222"
}
```

### Public Message

Client broadcasts:
```json
{
  "type": 687,
  "line": "nick!PUBLIC!absorder 12345 ..."
}
```

### Private Message

Client sends to peer:
```json
{
  "type": 685,
  "line": "alice!bob!fill 12345 ..."
}
```

## Performance

- Handles 1000+ concurrent connections
- Sub-10ms message routing latency
- Efficient memory usage with connection pooling
- Rate limiting to prevent abuse

## Security

- Tor hidden service for privacy (via separate container)
- Isolated network with no external access except through Tor
- Protocol version enforcement
- Network segregation (mainnet/testnet)
- Message validation and sanitization
- Rate limiting per peer
