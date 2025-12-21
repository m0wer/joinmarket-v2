"""
Blockchain backend implementations.

Available backends:
- BitcoinCoreBackend: Full node via Bitcoin Core RPC (no wallet, uses scantxoutset)
- NeutrinoBackend: Lightweight BIP157/BIP158 SPV client
- MempoolBackend: Mempool.space API (third-party, no setup required)

Protocol v6 Support:
All backends support verify_utxo_with_metadata() for Neutrino-compatible
UTXO verification. Check backend.requires_neutrino_metadata() to determine
if the backend needs scriptPubKey/blockheight hints from peers.
"""

from jmwallet.backends.base import (
    UTXO,
    BlockchainBackend,
    Transaction,
    UTXOVerificationResult,
)
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend, NeutrinoConfig

__all__ = [
    "BlockchainBackend",
    "BitcoinCoreBackend",
    "NeutrinoBackend",
    "NeutrinoConfig",
    "Transaction",
    "UTXO",
    "UTXOVerificationResult",
]
