"""
Proof of Discrete Log Equivalence (PoDLE) verification for makers.

This module re-exports PoDLE verification functions from jmcore for backward compatibility.
All new code should import directly from jmcore.podle.

PoDLE is used to prevent sybil attacks in JoinMarket by requiring takers
to prove ownership of a UTXO without revealing which UTXO until after
the maker commits to participate.

Reference: https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8
"""

from jmcore.podle import (
    PoDLEError,
    deserialize_revelation,
    parse_podle_revelation,
    verify_podle,
)

__all__ = [
    "PoDLEError",
    "deserialize_revelation",
    "parse_podle_revelation",
    "verify_podle",
]
