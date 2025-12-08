"""
Proof of Discrete Log Equivalence (PoDLE) generation for takers.

This module re-exports PoDLE generation functions from jmcore and provides
taker-specific utilities for UTXO selection and commitment generation.

PoDLE is used to prevent sybil attacks in JoinMarket by requiring takers
to prove ownership of a UTXO without revealing which UTXO until after
the maker commits to participate.

Protocol flow:
1. Taker generates commitment C = H(P2) where P2 = k*J (k = private key, J = NUMS point)
2. Taker sends commitment C to maker
3. Maker accepts and sends pubkey
4. Taker reveals P, P2, sig, e as the "revelation"
5. Maker verifies: P = k*G and P2 = k*J (same k)

Reference: https://gist.github.com/AdamISZ/9cbba5e9408d23813ca8
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from jmcore.podle import (
    PoDLECommitment,
    PoDLEError,
    generate_podle,
    serialize_revelation,
)
from loguru import logger

if TYPE_CHECKING:
    from jmwallet.wallet.models import UTXOInfo

__all__ = [
    "PoDLECommitment",
    "PoDLEError",
    "generate_podle",
    "generate_podle_for_coinjoin",
    "select_podle_utxo",
    "serialize_revelation",
]


def select_podle_utxo(
    utxos: list[UTXOInfo],
    cj_amount: int,
    min_confirmations: int = 5,
    min_percent: int = 20,
) -> UTXOInfo | None:
    """
    Select the best UTXO for PoDLE commitment.

    Criteria:
    - Must have at least min_confirmations
    - Must be at least min_percent of cj_amount

    Args:
        utxos: Available UTXOs
        cj_amount: CoinJoin amount
        min_confirmations: Minimum confirmations required
        min_percent: Minimum value as percentage of cj_amount

    Returns:
        Best UTXO for PoDLE or None if no suitable UTXO
    """
    min_value = int(cj_amount * min_percent / 100)

    eligible = [u for u in utxos if u.confirmations >= min_confirmations and u.value >= min_value]

    if not eligible:
        logger.warning(
            f"No suitable UTXOs for PoDLE: need {min_confirmations}+ confirmations "
            f"and value >= {min_value} sats ({min_percent}% of {cj_amount})"
        )
        return None

    # Prefer older UTXOs with more value
    eligible.sort(key=lambda u: (u.confirmations, u.value), reverse=True)

    selected = eligible[0]
    logger.info(
        f"Selected UTXO for PoDLE: {selected.txid}:{selected.vout} "
        f"(value={selected.value}, confs={selected.confirmations})"
    )

    return selected


def generate_podle_for_coinjoin(
    wallet_utxos: list[UTXOInfo],
    cj_amount: int,
    private_key_getter: Any,  # Callable[[str], bytes]
    min_confirmations: int = 5,
    min_percent: int = 20,
    index: int = 0,
) -> PoDLECommitment | None:
    """
    Generate PoDLE for a CoinJoin transaction.

    Args:
        wallet_utxos: All wallet UTXOs
        cj_amount: Target CoinJoin amount
        private_key_getter: Function to get private key for address
        min_confirmations: Minimum UTXO confirmations
        min_percent: Minimum UTXO value as % of cj_amount
        index: NUMS point index

    Returns:
        PoDLECommitment or None if no suitable UTXO
    """
    utxo = select_podle_utxo(
        utxos=wallet_utxos,
        cj_amount=cj_amount,
        min_confirmations=min_confirmations,
        min_percent=min_percent,
    )

    if utxo is None:
        return None

    # Get private key for the UTXO's address
    private_key = private_key_getter(utxo.address)
    if private_key is None:
        logger.error(f"Could not get private key for address {utxo.address}")
        return None

    utxo_str = f"{utxo.txid}:{utxo.vout}"

    return generate_podle(
        private_key_bytes=private_key,
        utxo_str=utxo_str,
        index=index,
    )
