"""
JoinMarket Wallet CLI - Manage wallets, generate addresses, and handle fidelity bonds.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
from pathlib import Path

import typer
from loguru import logger

app = typer.Typer(
    name="jm-wallet",
    help="JoinMarket Wallet Management",
    add_completion=False,
)


def setup_logging(level: str = "INFO") -> None:
    """Configure loguru logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )


# BIP39 wordlist (English) - first 100 words for demonstration
# In production, should use the full 2048-word list
BIP39_WORDLIST = [
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actress",
    "actual",
    "adapt",
    "add",
    "addict",
    "address",
    "adjust",
    "admit",
    "adult",
    "advance",
    "advice",
    "aerobic",
    "affair",
    "afford",
    "afraid",
    "again",
    "age",
    "agent",
    "agree",
    "ahead",
    "aim",
    "air",
    "airport",
    "aisle",
    "alarm",
    "album",
    "alcohol",
    "alert",
    "alien",
    "all",
    "alley",
    "allow",
    "almost",
    "alone",
    "alpha",
    "already",
    "also",
    "alter",
    "always",
    "amateur",
    "amazing",
    "among",
    "amount",
    "amused",
    "analyst",
    "anchor",
    "ancient",
    "anger",
    "angle",
    "angry",
    "animal",
    "ankle",
    "announce",
    "annual",
    "another",
    "answer",
    "antenna",
    "antique",
    "anxiety",
    "any",
    "apart",
    "apology",
    "appear",
    "apple",
    "approve",
    "april",
    "arch",
    "arctic",
    "area",
    "arena",
    "argue",
    "arm",
    "armed",
    "armor",
    "army",
    "around",
    "arrange",
    "arrest",
    "arrive",
    "arrow",
    "art",
    "artefact",
    "artist",
    "artwork",
    "ask",
    "aspect",
    "assault",
    "asset",
    "assist",
    "assume",
]


def generate_mnemonic(word_count: int = 24) -> str:
    """
    Generate a BIP39 mnemonic from secure entropy.

    Args:
        word_count: Number of words (12 or 24)

    Returns:
        BIP39 mnemonic phrase
    """
    # For production, we need proper BIP39 library
    # This is a placeholder implementation
    # TODO: Use mnemonic library for proper BIP39 generation with checksum

    if word_count not in (12, 24):
        raise ValueError("word_count must be 12 or 24")

    # Generate random words (NOT BIP39 compliant - needs proper implementation)
    words = [secrets.choice(BIP39_WORDLIST[:100]) for _ in range(word_count)]
    return " ".join(words)


@app.command()
def generate(
    word_count: int = typer.Option(24, "--words", "-w", help="Number of words (12 or 24)"),
    save: bool = typer.Option(False, "--save", "-s", help="Save to encrypted file"),
    output_file: Path | None = typer.Option(
        None, "--output", "-o", help="Output file path for encrypted mnemonic"
    ),
) -> None:
    """Generate a new BIP39 mnemonic phrase."""
    setup_logging()

    try:
        mnemonic = generate_mnemonic(word_count)

        if save:
            if output_file is None:
                output_file = Path.home() / ".jm" / "wallets" / "default.mnemonic"

            # Create parent directory
            output_file.parent.mkdir(parents=True, exist_ok=True)

            # TODO: Implement encryption
            # For now, just save plaintext with warning
            output_file.write_text(mnemonic)
            os.chmod(output_file, 0o600)  # Restrict permissions

            logger.warning(
                f"Mnemonic saved to {output_file} (PLAINTEXT - encryption not yet implemented)"
            )
            typer.echo(f"\nMnemonic saved to: {output_file}")
            typer.echo("KEEP THIS FILE SECURE - IT CONTROLS YOUR FUNDS!")
        else:
            typer.echo("\n" + "=" * 80)
            typer.echo("GENERATED MNEMONIC - WRITE THIS DOWN AND KEEP IT SAFE!")
            typer.echo("=" * 80)
            typer.echo(f"\n{mnemonic}\n")
            typer.echo("=" * 80)
            typer.echo("\nThis mnemonic controls your Bitcoin funds.")
            typer.echo("Anyone with this phrase can spend your coins.")
            typer.echo("Store it securely offline - NEVER share it with anyone!")
            typer.echo("=" * 80 + "\n")

    except Exception as e:
        logger.error(f"Failed to generate mnemonic: {e}")
        raise typer.Exit(1)


@app.command()
def info(
    mnemonic: str = typer.Option(None, "--mnemonic", envvar="MNEMONIC", help="BIP39 mnemonic"),
    mnemonic_file: Path | None = typer.Option(
        None, "--mnemonic-file", "-f", help="Path to mnemonic file"
    ),
    network: str = typer.Option("mainnet", "--network", "-n", help="Bitcoin network"),
    backend_type: str = typer.Option(
        "full_node", "--backend", "-b", help="Backend: full_node | neutrino"
    ),
    rpc_url: str = typer.Option("http://127.0.0.1:8332", "--rpc-url", envvar="BITCOIN_RPC_URL"),
    rpc_user: str = typer.Option("", "--rpc-user", envvar="BITCOIN_RPC_USER"),
    rpc_password: str = typer.Option("", "--rpc-password", envvar="BITCOIN_RPC_PASSWORD"),
    neutrino_url: str = typer.Option(
        "http://127.0.0.1:8334", "--neutrino-url", envvar="NEUTRINO_URL"
    ),
    log_level: str = typer.Option("INFO", "--log-level", "-l"),
) -> None:
    """Display wallet information and balances by mixdepth."""
    setup_logging(log_level)

    # Load mnemonic
    if mnemonic_file:
        if not mnemonic_file.exists():
            logger.error(f"Mnemonic file not found: {mnemonic_file}")
            raise typer.Exit(1)
        mnemonic = mnemonic_file.read_text().strip()

    if not mnemonic:
        logger.error("Mnemonic required. Use --mnemonic, --mnemonic-file, or MNEMONIC env var")
        raise typer.Exit(1)

    asyncio.run(
        _show_wallet_info(
            mnemonic, network, backend_type, rpc_url, rpc_user, rpc_password, neutrino_url
        )
    )


async def _show_wallet_info(
    mnemonic: str,
    network: str,
    backend_type: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
    neutrino_url: str,
) -> None:
    """Show wallet info implementation."""
    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.backends.neutrino import NeutrinoBackend
    from jmwallet.wallet.service import WalletService

    # Create backend
    if backend_type == "neutrino":
        backend = NeutrinoBackend(neutrino_url=neutrino_url, network=network)
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(rpc_url=rpc_url, rpc_user=rpc_user, rpc_password=rpc_password)

    # Create wallet
    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
    )

    try:
        await wallet.sync_all()

        total_balance = await wallet.get_total_balance()
        print(f"\nTotal Balance: {total_balance:,} sats ({total_balance / 1e8:.8f} BTC)")
        print("\nBalance by mixdepth:")

        for md in range(5):
            balance = await wallet.get_balance(md)
            addr = wallet.get_receive_address(md, 0)
            print(f"  Mixdepth {md}: {balance:>15,} sats  |  {addr}")

    finally:
        await wallet.close()


@app.command()
def list_bonds(
    mnemonic: str = typer.Option(None, "--mnemonic", envvar="MNEMONIC"),
    mnemonic_file: Path | None = typer.Option(None, "--mnemonic-file", "-f"),
    network: str = typer.Option("mainnet", "--network", "-n"),
    backend_type: str = typer.Option("full_node", "--backend", "-b"),
    rpc_url: str = typer.Option("http://127.0.0.1:8332", "--rpc-url", envvar="BITCOIN_RPC_URL"),
    rpc_user: str = typer.Option("", "--rpc-user", envvar="BITCOIN_RPC_USER"),
    rpc_password: str = typer.Option("", "--rpc-password", envvar="BITCOIN_RPC_PASSWORD"),
    log_level: str = typer.Option("INFO", "--log-level", "-l"),
) -> None:
    """List all fidelity bonds in the wallet."""
    setup_logging(log_level)

    # Load mnemonic
    if mnemonic_file:
        if not mnemonic_file.exists():
            logger.error(f"Mnemonic file not found: {mnemonic_file}")
            raise typer.Exit(1)
        mnemonic = mnemonic_file.read_text().strip()

    if not mnemonic:
        logger.error("Mnemonic required")
        raise typer.Exit(1)

    asyncio.run(
        _list_fidelity_bonds(mnemonic, network, backend_type, rpc_url, rpc_user, rpc_password)
    )


async def _list_fidelity_bonds(
    mnemonic: str,
    network: str,
    backend_type: str,
    rpc_url: str,
    rpc_user: str,
    rpc_password: str,
) -> None:
    """List fidelity bonds implementation."""
    from datetime import datetime

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
    from jmwallet.wallet.service import WalletService

    # Import fidelity bond utilities from maker
    # This creates a dependency - ideally we'd move fidelity.py to jmcore
    try:
        from maker.fidelity import find_fidelity_bonds
    except ImportError:
        logger.error("Failed to import fidelity bond utilities")
        raise typer.Exit(1)

    backend = BitcoinCoreBackend(rpc_url=rpc_url, rpc_user=rpc_user, rpc_password=rpc_password)

    wallet = WalletService(
        mnemonic=mnemonic,
        backend=backend,
        network=network,
        mixdepth_count=5,
    )

    try:
        await wallet.sync_all()

        bonds = find_fidelity_bonds(wallet)

        if not bonds:
            print("\nNo fidelity bonds found in wallet.")
            return

        print(f"\nFound {len(bonds)} fidelity bond(s):\n")
        print("=" * 120)

        for i, bond in enumerate(bonds, 1):
            locktime_dt = datetime.fromtimestamp(bond.locktime)
            print(f"Bond #{i}:")
            print(f"  UTXO:        {bond.txid}:{bond.vout}")
            print(f"  Value:       {bond.value:,} sats ({bond.value / 1e8:.8f} BTC)")
            print(f"  Locktime:    {bond.locktime} ({locktime_dt.strftime('%Y-%m-%d %H:%M:%S')})")
            print(f"  Confirms:    {bond.confirmation_time}")
            print(f"  Bond Value:  {bond.bond_value:,}")
            print("-" * 120)

    finally:
        await wallet.close()


def main() -> None:
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
