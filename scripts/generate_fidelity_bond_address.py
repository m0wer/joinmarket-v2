#!/usr/bin/env python3
"""
Generate a fidelity bond (timelocked P2WSH) address for a given mnemonic.

Usage:
    python generate_fidelity_bond_address.py <mnemonic> <locktime> [--network=regtest]

Example:
    python generate_fidelity_bond_address.py \
        "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff" \
        1735689600 --network=regtest

Output:
    <p2wsh_address>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "jmcore" / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent / "jmwallet" / "src"))

from jmcore.btc_script import mk_freeze_script
from jmwallet.wallet.address import script_to_p2wsh_address
from jmwallet.wallet.bip32 import HDKey, mnemonic_to_seed


def get_fidelity_bond_address(
    mnemonic: str,
    locktime: int,
    index: int = 0,
    network: str = "regtest",
) -> tuple[str, str]:
    """
    Generate a fidelity bond P2WSH address.

    Path: m/84'/1'/0'/2/index (coin type 1 for testnet/regtest)

    Args:
        mnemonic: BIP39 mnemonic phrase
        locktime: Unix timestamp for the timelock
        index: Address index (default 0)
        network: Network type (mainnet, testnet, regtest)

    Returns:
        Tuple of (address, pubkey_hex)
    """
    seed = mnemonic_to_seed(mnemonic)
    master_key = HDKey.from_seed(seed)

    # Use coin type 1 for testnet/regtest, 0 for mainnet
    coin_type = 0 if network == "mainnet" else 1

    # Fidelity bonds: mixdepth 0, branch 2
    path = f"m/84'/{coin_type}'/0'/2/{index}"
    key = master_key.derive(path)
    pubkey_hex = key.get_public_key_bytes(compressed=True).hex()

    # Create timelock script: <locktime> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG
    script = mk_freeze_script(pubkey_hex, locktime)

    # Convert to P2WSH address
    address = script_to_p2wsh_address(script, network)

    return address, pubkey_hex


def main():
    parser = argparse.ArgumentParser(
        description="Generate a fidelity bond (timelocked P2WSH) address"
    )
    parser.add_argument("mnemonic", help="BIP39 mnemonic phrase (in quotes)")
    parser.add_argument("locktime", type=int, help="Unix timestamp for locktime")
    parser.add_argument(
        "--index", type=int, default=0, help="Address index (default: 0)"
    )
    parser.add_argument(
        "--network",
        choices=["mainnet", "testnet", "regtest"],
        default="regtest",
        help="Network type (default: regtest)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show verbose output"
    )

    args = parser.parse_args()

    address, pubkey = get_fidelity_bond_address(
        mnemonic=args.mnemonic,
        locktime=args.locktime,
        index=args.index,
        network=args.network,
    )

    if args.verbose:
        print(f"Mnemonic: {args.mnemonic}", file=sys.stderr)
        print(f"Locktime: {args.locktime}", file=sys.stderr)
        print(f"Index: {args.index}", file=sys.stderr)
        print(f"Network: {args.network}", file=sys.stderr)
        print(f"Pubkey: {pubkey}", file=sys.stderr)
        print(f"Address: {address}", file=sys.stderr)

    # Print just the address for scripting
    print(address)


if __name__ == "__main__":
    main()
