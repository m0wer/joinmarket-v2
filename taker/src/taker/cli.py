"""
Command-line interface for JoinMarket Taker.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from jmcore.models import NetworkType, get_default_directory_nodes
from jmwallet.backends.bitcoin_core import BitcoinCoreBackend
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from loguru import logger

from taker.config import MaxCjFee, Schedule, ScheduleEntry, TakerConfig
from taker.taker import Taker

app = typer.Typer(
    name="jm-taker",
    help="JoinMarket Taker - Execute CoinJoin transactions",
    add_completion=False,
)


def setup_logging(level: str) -> None:
    """Configure loguru logging."""
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )


@app.command()
def coinjoin(
    amount: int = typer.Option(..., "--amount", "-a", help="Amount in sats (0 for sweep)"),
    destination: str = typer.Option(
        "INTERNAL",
        "--destination",
        "-d",
        help="Destination address (or 'INTERNAL' for next mixdepth)",
    ),
    mixdepth: int = typer.Option(0, "--mixdepth", "-m", help="Source mixdepth"),
    counterparties: int = typer.Option(3, "--counterparties", "-n", help="Number of makers"),
    mnemonic: str = typer.Option(
        None, "--mnemonic", envvar="MNEMONIC", help="Wallet mnemonic phrase"
    ),
    network: str = typer.Option("mainnet", "--network", help="Protocol network for handshakes"),
    bitcoin_network: str = typer.Option(
        None, "--bitcoin-network", help="Bitcoin network for addresses (defaults to --network)"
    ),
    backend_type: str = typer.Option(
        "full_node", "--backend", "-b", help="Backend type: full_node | neutrino"
    ),
    rpc_url: str = typer.Option(
        "http://127.0.0.1:8332",
        "--rpc-url",
        envvar="BITCOIN_RPC_URL",
        help="Bitcoin full node RPC URL",
    ),
    rpc_user: str = typer.Option(
        "", "--rpc-user", envvar="BITCOIN_RPC_USER", help="Bitcoin full node RPC user"
    ),
    rpc_password: str = typer.Option(
        "", "--rpc-password", envvar="BITCOIN_RPC_PASSWORD", help="Bitcoin full node RPC password"
    ),
    neutrino_url: str = typer.Option(
        "http://127.0.0.1:8334",
        "--neutrino-url",
        envvar="NEUTRINO_URL",
        help="Neutrino REST API URL",
    ),
    directory_servers: str = typer.Option(
        None,
        "--directory",
        "-D",
        envvar="DIRECTORY_SERVERS",
        help="Directory servers (comma-separated). Defaults to mainnet directory nodes.",
    ),
    max_abs_fee: int = typer.Option(500, "--max-abs-fee", help="Max absolute fee in sats"),
    max_rel_fee: str = typer.Option("0.001", "--max-rel-fee", help="Max relative fee (0.001=0.1%)"),
    bondless_makers_allowance: float = typer.Option(
        0.125, "--bondless-allowance", help="Fraction of time to choose makers randomly (0.0-1.0)"
    ),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Execute a single CoinJoin transaction."""
    setup_logging(log_level)

    if not mnemonic:
        logger.error("Mnemonic required. Set via --mnemonic or MNEMONIC env var")
        raise typer.Exit(1)

    # Parse network
    try:
        network_type = NetworkType(network)
    except ValueError:
        logger.error(f"Invalid network: {network}")
        raise typer.Exit(1)

    # Parse bitcoin network (defaults to protocol network)
    actual_bitcoin_network = bitcoin_network or network
    try:
        bitcoin_network_type = NetworkType(actual_bitcoin_network)
    except ValueError:
        logger.error(f"Invalid bitcoin network: {actual_bitcoin_network}")
        raise typer.Exit(1)

    # Parse directory servers: use provided list or default for network
    if directory_servers:
        dir_servers = [s.strip() for s in directory_servers.split(",")]
    else:
        dir_servers = get_default_directory_nodes(network_type)

    # Build backend config based on type
    if backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url,
            "network": actual_bitcoin_network,
        }
    else:
        backend_config = {
            "rpc_url": rpc_url,
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
        }

    # Build config
    config = TakerConfig(
        mnemonic=mnemonic,
        network=network_type,
        bitcoin_network=bitcoin_network_type,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=dir_servers,
        destination_address=destination,
        amount=amount,
        mixdepth=mixdepth,
        counterparty_count=counterparties,
        max_cj_fee=MaxCjFee(abs_fee=max_abs_fee, rel_fee=max_rel_fee),
        bondless_makers_allowance=bondless_makers_allowance,
    )

    asyncio.run(_run_coinjoin(config, amount, destination, mixdepth, counterparties))


async def _run_coinjoin(
    config: TakerConfig,
    amount: int,
    destination: str,
    mixdepth: int,
    counterparties: int,
) -> None:
    """Run CoinJoin transaction."""
    # Use bitcoin_network for address generation
    bitcoin_network = config.bitcoin_network or config.network

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Wait for neutrino to sync
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
    )

    # Create taker
    taker = Taker(wallet, backend, config)

    try:
        await taker.start()

        logger.info(f"Starting CoinJoin: {amount} sats -> {destination}")
        txid = await taker.do_coinjoin(
            amount=amount,
            destination=destination,
            mixdepth=mixdepth,
            counterparty_count=counterparties,
        )

        if txid:
            logger.info(f"CoinJoin successful! txid: {txid}")
        else:
            logger.error("CoinJoin failed")
            raise typer.Exit(1)

    finally:
        await taker.stop()


@app.command()
def tumble(
    schedule_file: Path = typer.Argument(..., help="Path to schedule JSON file"),
    mnemonic: str = typer.Option(
        None, "--mnemonic", envvar="MNEMONIC", help="Wallet mnemonic phrase"
    ),
    network: str = typer.Option("mainnet", "--network", help="Bitcoin network"),
    backend_type: str = typer.Option(
        "full_node", "--backend", "-b", help="Backend type: full_node | neutrino"
    ),
    rpc_url: str = typer.Option(
        "http://127.0.0.1:8332",
        "--rpc-url",
        envvar="BITCOIN_RPC_URL",
        help="Bitcoin full node RPC URL",
    ),
    rpc_user: str = typer.Option(
        "", "--rpc-user", envvar="BITCOIN_RPC_USER", help="Bitcoin full node RPC user"
    ),
    rpc_password: str = typer.Option(
        "", "--rpc-password", envvar="BITCOIN_RPC_PASSWORD", help="Bitcoin full node RPC password"
    ),
    neutrino_url: str = typer.Option(
        "http://127.0.0.1:8334",
        "--neutrino-url",
        envvar="NEUTRINO_URL",
        help="Neutrino REST API URL",
    ),
    directory_servers: str = typer.Option(
        None,
        "--directory",
        "-D",
        envvar="DIRECTORY_SERVERS",
        help="Directory servers (comma-separated). Defaults to mainnet directory nodes.",
    ),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Run a tumbler schedule of CoinJoins."""
    setup_logging(log_level)

    if not mnemonic:
        logger.error("Mnemonic required. Set via --mnemonic or MNEMONIC env var")
        raise typer.Exit(1)

    if not schedule_file.exists():
        logger.error(f"Schedule file not found: {schedule_file}")
        raise typer.Exit(1)

    # Load schedule
    import json

    try:
        with open(schedule_file) as f:
            schedule_data = json.load(f)

        entries = [ScheduleEntry(**entry) for entry in schedule_data["entries"]]
        schedule = Schedule(entries=entries)
    except Exception as e:
        logger.error(f"Failed to load schedule: {e}")
        raise typer.Exit(1)

    # Parse network
    try:
        network_type = NetworkType(network)
    except ValueError:
        logger.error(f"Invalid network: {network}")
        raise typer.Exit(1)

    # Parse directory servers: use provided list or default for network
    if directory_servers:
        dir_servers = [s.strip() for s in directory_servers.split(",")]
    else:
        dir_servers = get_default_directory_nodes(network_type)

    # Build backend config based on type
    if backend_type == "neutrino":
        backend_config = {
            "neutrino_url": neutrino_url,
            "network": network,
        }
    else:
        backend_config = {
            "rpc_url": rpc_url,
            "rpc_user": rpc_user,
            "rpc_password": rpc_password,
        }

    # Build config
    config = TakerConfig(
        mnemonic=mnemonic,
        network=network_type,
        backend_type=backend_type,
        backend_config=backend_config,
        directory_servers=dir_servers,
    )

    asyncio.run(_run_tumble(config, schedule))


async def _run_tumble(config: TakerConfig, schedule: Schedule) -> None:
    """Run tumbler schedule."""
    # Use bitcoin_network for address generation
    bitcoin_network = config.bitcoin_network or config.network

    # Create backend based on config
    backend: NeutrinoBackend | BitcoinCoreBackend
    if config.backend_type == "neutrino":
        backend = NeutrinoBackend(
            neutrino_url=config.backend_config.get("neutrino_url", "http://127.0.0.1:8334"),
            network=bitcoin_network.value,
        )
        # Wait for neutrino to sync
        logger.info("Waiting for neutrino to sync...")
        synced = await backend.wait_for_sync(timeout=300.0)
        if not synced:
            logger.error("Neutrino sync timeout")
            raise typer.Exit(1)
    else:
        backend = BitcoinCoreBackend(
            rpc_url=config.backend_config["rpc_url"],
            rpc_user=config.backend_config["rpc_user"],
            rpc_password=config.backend_config["rpc_password"],
        )

    # Create wallet with bitcoin_network for address generation
    wallet = WalletService(
        mnemonic=config.mnemonic,
        backend=backend,
        network=bitcoin_network.value,
        mixdepth_count=config.mixdepth_count,
    )

    # Create taker
    taker = Taker(wallet, backend, config)

    try:
        await taker.start()

        logger.info(f"Starting tumble with {len(schedule.entries)} entries")
        success = await taker.run_schedule(schedule)

        if success:
            logger.info("Tumble complete!")
        else:
            logger.error("Tumble failed")
            raise typer.Exit(1)

    finally:
        await taker.stop()


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
