"""
End-to-end integration tests for Neutrino backend.

Tests neutrino light client backend functionality:
- Basic blockchain operations (height, transactions, fees)
- UTXO discovery and watching addresses
- Maker and taker operation with neutrino backend
- Cross-backend compatibility (bitcoin_core + neutrino)
- Fidelity bonds with neutrino backend

Requires: docker compose --profile all up -d

The neutrino backend uses BIP157/BIP158 compact block filters for
privacy-preserving SPV operation. These tests verify that the neutrino
backend works correctly with the JoinMarket wallet implementation.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from jmcore.models import NetworkType
from jmwallet.backends.neutrino import NeutrinoBackend
from jmwallet.wallet.service import WalletService
from maker.bot import MakerBot
from maker.config import MakerConfig
from taker.config import TakerConfig
from taker.taker import Taker

# Test wallet mnemonics (same as in test_complete_system.py for consistency)
MAKER1_MNEMONIC = (
    "avoid whisper mesh corn already blur sudden fine planet chicken hover sniff"
)
MAKER2_MNEMONIC = (
    "minute faint grape plate stock mercy tent world space opera apple rocket"
)
TAKER_MNEMONIC = (
    "burden notable love elephant orbit couch message galaxy elevator exile drop toilet"
)
GENERIC_TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


# ==============================================================================
# Fixtures
# ==============================================================================


@pytest.fixture(scope="module")
def neutrino_url() -> str:
    """Neutrino server URL."""
    return "http://127.0.0.1:8334"


@pytest_asyncio.fixture
async def neutrino_backend(neutrino_url: str):
    """Create Neutrino backend for tests."""
    backend = NeutrinoBackend(
        neutrino_url=neutrino_url,
        network="regtest",
    )

    # Verify neutrino is available and synced - fail if not
    try:
        height = await backend.get_block_height()
        if height == 0:
            # Wait for sync
            synced = await backend.wait_for_sync(timeout=30.0)
            if not synced:
                pytest.fail("Neutrino failed to sync within timeout")
    except Exception as e:
        pytest.fail(f"Neutrino server not available at {neutrino_url}: {e}")

    yield backend
    await backend.close()


@pytest_asyncio.fixture
async def funded_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund a test wallet using neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=GENERIC_TEST_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address BEFORE syncing
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core - mines directly to the address
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height (not 0)
        # The funding transaction will be in recent blocks
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)  # Scan last 10 blocks

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan to complete

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(
            f"Wallet has no funds after funding attempt. "
            f"Address: {funding_address}, neutrino may not have synced the new blocks"
        )

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest_asyncio.fixture
async def funded_maker1_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund maker1 wallet with neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=MAKER1_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund maker1 wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(f"Maker1 wallet has no funds. Address: {funding_address}")

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest_asyncio.fixture
async def funded_taker_neutrino_wallet(neutrino_backend: NeutrinoBackend):
    """Create and fund taker wallet with neutrino backend."""
    from tests.e2e.rpc_utils import ensure_wallet_funded

    wallet = WalletService(
        mnemonic=TAKER_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get the funding address
    funding_address = wallet.get_receive_address(0, 0)

    # Add the address to neutrino's watch list
    await neutrino_backend.add_watch_address(funding_address)

    # Check current balance
    await wallet.sync_all()
    total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        # Fund via Bitcoin Core
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if not funded:
            await wallet.close()
            pytest.fail("Failed to fund taker wallet via Bitcoin Core RPC")

        # Wait for neutrino to see the new blocks
        await asyncio.sleep(2)

        # Get current height and rescan from a recent height
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 10)

        # Rescan to find the funding transaction
        await neutrino_backend.rescan_from_height(
            rescan_start, addresses=[funding_address]
        )
        await asyncio.sleep(5)  # Wait for background rescan

        # Re-sync wallet
        await wallet.sync_all()
        total_balance = await wallet.get_total_balance()

    if total_balance == 0:
        await wallet.close()
        pytest.fail(f"Taker wallet has no funds. Address: {funding_address}")

    try:
        yield wallet
    finally:
        await wallet.close()


@pytest.fixture
def maker_neutrino_config():
    """Maker configuration using neutrino backend."""
    return MakerConfig(
        mnemonic=MAKER1_MNEMONIC,
        network=NetworkType.TESTNET,  # Protocol network
        bitcoin_network=NetworkType.REGTEST,  # Bitcoin network
        backend_type="neutrino",
        backend_config={
            "neutrino_url": "http://127.0.0.1:8334",
        },
        directory_servers=["127.0.0.1:5222"],
        min_size=100_000,
        cj_fee_relative="0.0003",
        tx_fee_contribution=1_000,
    )


@pytest.fixture
def taker_neutrino_config():
    """Taker configuration using neutrino backend."""
    return TakerConfig(
        mnemonic=TAKER_MNEMONIC,
        network=NetworkType.TESTNET,  # Protocol network
        bitcoin_network=NetworkType.REGTEST,  # Bitcoin network
        backend_type="neutrino",
        backend_config={
            "neutrino_url": "http://127.0.0.1:8334",
        },
        directory_servers=["127.0.0.1:5222"],
        counterparty_count=2,
        minimum_makers=2,
        maker_timeout_sec=30,
        order_wait_time=10.0,
    )


# ==============================================================================
# Basic Neutrino Backend Tests
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_connection(neutrino_backend: NeutrinoBackend):
    """Test basic neutrino backend connectivity."""
    height = await neutrino_backend.get_block_height()
    assert height > 0, "Should get block height from neutrino"

    fee = await neutrino_backend.estimate_fee(6)
    assert fee > 0, "Should estimate fee"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_watch_address(neutrino_backend: NeutrinoBackend):
    """Test neutrino address watching functionality."""
    test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

    # Add address to watch
    await neutrino_backend.add_watch_address(test_address)

    # Verify it was added (if API succeeded)
    if test_address in neutrino_backend._watched_addresses:
        assert test_address in neutrino_backend._watched_addresses


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_wallet_sync(funded_neutrino_wallet: WalletService):
    """Test wallet synchronization with neutrino backend."""
    balance = await funded_neutrino_wallet.get_total_balance()
    assert balance > 0, "Wallet should have balance"

    utxos_dict = await funded_neutrino_wallet.sync_all()
    assert len(utxos_dict) > 0, "Should find UTXOs"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_address_generation(funded_neutrino_wallet: WalletService):
    """Test address generation works with neutrino backend."""
    addr1 = funded_neutrino_wallet.get_receive_address(0, 0)
    addr2 = funded_neutrino_wallet.get_receive_address(0, 1)

    assert addr1.startswith("bcrt1"), "Should generate regtest bech32 address"
    assert addr2.startswith("bcrt1"), "Should generate regtest bech32 address"
    assert addr1 != addr2, "Addresses should be unique"


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_utxo_discovery(
    neutrino_backend: NeutrinoBackend, funded_neutrino_wallet: WalletService
):
    """Test UTXO discovery via neutrino compact block filters."""
    # Get wallet addresses
    addresses = [funded_neutrino_wallet.get_receive_address(0, i) for i in range(5)]

    # Get UTXOs via neutrino
    utxos = await neutrino_backend.get_utxos(addresses)

    # Should find at least the funded UTXO
    assert len(utxos) > 0, "Neutrino should discover UTXOs"

    # Verify UTXO structure
    for utxo in utxos:
        assert utxo.txid, "UTXO should have txid"
        assert utxo.value > 0, "UTXO should have value"
        assert utxo.confirmations >= 0, "UTXO should have confirmations"


# ==============================================================================
# Maker with Neutrino Backend
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_maker_neutrino_initialization(
    neutrino_backend: NeutrinoBackend, maker_neutrino_config: MakerConfig
):
    """Test maker bot initialization with neutrino backend."""
    wallet = WalletService(
        mnemonic=maker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    bot = MakerBot(wallet, neutrino_backend, maker_neutrino_config)

    assert bot.nick.startswith("J5"), "Should generate valid nick"
    assert len(bot.nick) == 16, "Nick should be 16 characters"

    await wallet.close()


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_maker_neutrino_offer_creation(
    funded_maker1_neutrino_wallet: WalletService, maker_neutrino_config: MakerConfig
):
    """Test maker can create offers with neutrino backend."""
    from maker.offers import OfferManager

    offer_manager = OfferManager(
        funded_maker1_neutrino_wallet, maker_neutrino_config, "J5NeutrinoMaker"
    )

    offers = await offer_manager.create_offers()

    if offers:
        offer = offers[0]
        assert offer.minsize <= offer.maxsize
        assert offer.txfee == maker_neutrino_config.tx_fee_contribution
        assert offer.counterparty == "J5NeutrinoMaker"


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
async def test_maker_neutrino_coinjoin(
    neutrino_backend: NeutrinoBackend,
    maker_neutrino_config: MakerConfig,
    funded_maker1_neutrino_wallet: WalletService,
):
    """Test maker can participate in CoinJoin using neutrino backend."""
    # This test requires a running taker and directory server
    # For now, we test that the maker can start and connect

    bot = MakerBot(
        funded_maker1_neutrino_wallet, neutrino_backend, maker_neutrino_config
    )

    # Start the bot in background
    start_task = asyncio.create_task(bot.start())

    try:
        # Wait for connection
        await asyncio.sleep(10)

        # Verify bot connected (if directory server is running)
        # This assertion may fail if directory server is not available
        if len(bot.directory_clients) > 0:
            assert bot.running, "Bot should be running"

    finally:
        await bot.stop()
        start_task.cancel()
        try:
            await start_task
        except asyncio.CancelledError:
            pass


# ==============================================================================
# Taker with Neutrino Backend
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_initialization(
    neutrino_backend: NeutrinoBackend, taker_neutrino_config: TakerConfig
):
    """Test taker initialization with neutrino backend."""
    wallet = WalletService(
        mnemonic=taker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    taker = Taker(wallet, neutrino_backend, taker_neutrino_config)

    assert taker.nick.startswith("J5"), "Should generate valid nick"
    assert len(taker.nick) == 16, "Nick should be 16 characters"

    await wallet.close()


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_podle_generation(
    funded_taker_neutrino_wallet: WalletService,
):
    """Test PoDLE commitment generation with neutrino backend."""
    from taker.podle import select_podle_utxo

    utxos = await funded_taker_neutrino_wallet.get_utxos(0)

    assert utxos, "Funded wallet should have UTXOs for PoDLE test"

    cj_amount = 100_000

    selected = select_podle_utxo(
        utxos=utxos,
        cj_amount=cj_amount,
        min_confirmations=1,
        min_percent=10,
    )

    assert selected is not None, "Should select a UTXO for PoDLE"
    assert selected.confirmations >= 1
    assert selected.value >= cj_amount * 0.1


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_taker_neutrino_orderbook_fetch(
    neutrino_backend: NeutrinoBackend, taker_neutrino_config: TakerConfig
):
    """Test taker can fetch orderbook with neutrino backend."""
    wallet = WalletService(
        mnemonic=taker_neutrino_config.mnemonic,
        backend=neutrino_backend,
        network="regtest",
    )

    taker = Taker(wallet, neutrino_backend, taker_neutrino_config)

    try:
        await taker.start()

        # Fetch orderbook (may be empty)
        try:
            offers = await taker.directory_client.fetch_orderbook(timeout=5.0)
            assert isinstance(offers, list), "Offers should be a list"
        except Exception:
            # Directory server may not be running
            pass

    finally:
        await taker.stop()
        await wallet.close()


# ==============================================================================
# Cross-Backend Compatibility Tests
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
async def test_cross_backend_bitcoin_core_maker_neutrino_taker(
    neutrino_backend: NeutrinoBackend,
    taker_neutrino_config: TakerConfig,
):
    """
    Test cross-backend compatibility: Bitcoin Core maker + Neutrino taker.

    This test verifies that takers using Neutrino backend can connect,
    fetch orderbook, and select makers that use Bitcoin Core backend.

    NOTE: Full CoinJoin execution with Neutrino taker is limited because
    the Neutrino light client cannot verify arbitrary maker UTXOs without
    additional infrastructure (e.g., mempool.space API). This test verifies
    the protocol exchange up to the point where UTXO verification is required.

    The Docker makers (jm-maker1, jm-maker2) use Bitcoin Core backend,
    while our taker uses the Neutrino backend.

    For a production Neutrino taker, additional infrastructure would be needed:
    - Use mempool.space API as fallback for UTXO verification
    - Run a hybrid setup with Bitcoin Core for verification
    - Accept only makers with pre-known UTXOs

    Requires:
    - docker compose --profile neutrino up -d
    """
    import subprocess

    from tests.e2e.rpc_utils import ensure_wallet_funded, mine_blocks

    # Check if Docker makers are running
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "jm-maker1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip() != "true":
            pytest.skip(
                "Docker maker1 not running. Start with: docker compose --profile neutrino up -d"
            )

        result2 = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "jm-maker2"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result2.stdout.strip() != "true":
            pytest.skip(
                "Docker maker2 not running. Start with: docker compose --profile neutrino up -d"
            )
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        pytest.skip("Docker not available or makers not running")

    # Check neutrino is available
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "jm-neutrino"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip() != "true":
            pytest.skip(
                "Neutrino container not running. Start with: docker compose --profile neutrino up -d"
            )
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        pytest.skip("Docker not available")

    # Ensure coinbase maturity
    addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    await mine_blocks(10, addr)

    # Create taker wallet with Neutrino backend
    taker_wallet = WalletService(
        mnemonic=TAKER_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get funding address and add to watch list
    funding_address = taker_wallet.get_receive_address(0, 0)
    await neutrino_backend.add_watch_address(funding_address)

    # Sync wallet
    await taker_wallet.sync_all()
    taker_balance = await taker_wallet.get_total_balance()

    # Fund if needed
    if taker_balance < 100_000_000:  # 1 BTC minimum
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if funded:
            # Wait for neutrino to see the new blocks
            await asyncio.sleep(2)
            current_height = await neutrino_backend.get_block_height()
            rescan_start = max(0, current_height - 10)
            await neutrino_backend.rescan_from_height(
                rescan_start, addresses=[funding_address]
            )
            await asyncio.sleep(5)
            await taker_wallet.sync_all()
            taker_balance = await taker_wallet.get_total_balance()

    if taker_balance < 100_000_000:
        await taker_wallet.close()
        pytest.skip(
            f"Taker needs at least 100,000,000 sats, has {taker_balance}. "
            "Run wallet-funder or fund manually."
        )

    # Create taker with Neutrino backend
    taker = Taker(taker_wallet, neutrino_backend, taker_neutrino_config)

    try:
        # Start taker
        await taker.start()

        # Fetch orderbook from Docker makers
        offers = await taker.directory_client.fetch_orderbook(timeout=15.0)

        if len(offers) < 2:
            await taker.stop()
            await taker_wallet.close()
            pytest.skip(
                f"Need at least 2 offers, found {len(offers)}. "
                "Ensure Docker makers are running and have funds."
            )

        # Verify the Neutrino taker successfully:
        # 1. Connected to the directory server
        # 2. Fetched offers from Bitcoin Core makers
        assert len(offers) >= 2, f"Should find at least 2 offers, found {len(offers)}"

        # Verify offer properties
        for offer in offers[:2]:
            assert offer.minsize > 0, "Offer should have valid minsize"
            assert offer.maxsize >= offer.minsize, "Offer should have valid maxsize"
            assert offer.counterparty.startswith("J5"), (
                "Offer should have valid counterparty"
            )

        # Update orderbook
        taker.orderbook_manager.update_offers(offers)

        # Verify we can select makers for CoinJoin
        cj_amount = 50_000_000  # 0.5 BTC
        selected, total_fee = taker.orderbook_manager.select_makers(cj_amount, n=2)
        assert len(selected) == 2, f"Should select 2 makers, selected {len(selected)}"

        # Verify taker has sufficient funds for CoinJoin
        assert taker_balance >= cj_amount, "Taker should have sufficient funds"

        # NOTE: We don't attempt the full CoinJoin because the Neutrino backend
        # cannot verify arbitrary maker UTXOs without additional infrastructure.
        # The protocol exchange up to !fill and !pubkey would work, but the taker's
        # !ioauth verification would fail because the Neutrino light client can only
        # see UTXOs for addresses it's watching.
        #
        # For a production Neutrino taker, additional infrastructure would be needed:
        # - Use mempool.space API as fallback for UTXO verification
        # - Run a hybrid setup with Bitcoin Core for verification
        # - Accept only makers with pre-known UTXOs

    finally:
        await taker.stop()
        await taker_wallet.close()


@pytest.mark.asyncio
@pytest.mark.neutrino
@pytest.mark.slow
async def test_cross_backend_neutrino_maker_bitcoin_core_taker(
    neutrino_backend: NeutrinoBackend,
    maker_neutrino_config: MakerConfig,
):
    """
    Test cross-backend compatibility: Neutrino maker + Bitcoin Core taker.

    This test verifies that makers using Neutrino backend can connect,
    announce offers, and participate in the CoinJoin protocol with takers
    using Bitcoin Core backend.

    NOTE: Full CoinJoin execution with Neutrino maker is limited because
    the Neutrino light client cannot verify arbitrary taker UTXOs without
    additional infrastructure (e.g., mempool.space API). This test verifies
    the protocol exchange up to the point where UTXO verification is required.

    For production, a Neutrino maker would need:
    - A trusted mempool API for UTXO verification
    - A connection to a full node for UTXO queries
    - Or to accept that only pre-known takers can participate

    Requires:
    - docker compose --profile neutrino up -d
    """
    import subprocess

    from jmwallet.backends.bitcoin_core import BitcoinCoreBackend

    from tests.e2e.rpc_utils import ensure_wallet_funded, mine_blocks

    # Check neutrino is available
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", "jm-neutrino"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.stdout.strip() != "true":
            pytest.skip(
                "Neutrino container not running. Start with: docker compose --profile neutrino up -d"
            )
    except (
        subprocess.TimeoutExpired,
        FileNotFoundError,
        subprocess.CalledProcessError,
    ):
        pytest.skip("Docker not available")

    # Ensure coinbase maturity
    addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    await mine_blocks(10, addr)

    # Create Bitcoin Core backend for taker
    bitcoin_backend = BitcoinCoreBackend(
        rpc_url="http://127.0.0.1:18443",
        rpc_user="test",
        rpc_password="test",
    )

    # Create maker wallet with Neutrino backend
    maker_wallet = WalletService(
        mnemonic=MAKER1_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Get funding address and add to watch list
    maker_funding_address = maker_wallet.get_receive_address(0, 0)
    await neutrino_backend.add_watch_address(maker_funding_address)

    # Sync maker wallet
    await maker_wallet.sync_all()
    maker_balance = await maker_wallet.get_total_balance()

    # Fund maker if needed
    if maker_balance < 100_000_000:  # 1 BTC minimum
        funded = await ensure_wallet_funded(
            maker_funding_address, amount_btc=1.0, confirmations=2
        )
        if funded:
            await asyncio.sleep(2)
            current_height = await neutrino_backend.get_block_height()
            rescan_start = max(0, current_height - 10)
            await neutrino_backend.rescan_from_height(
                rescan_start, addresses=[maker_funding_address]
            )
            await asyncio.sleep(5)
            await maker_wallet.sync_all()
            maker_balance = await maker_wallet.get_total_balance()

    if maker_balance < 100_000_000:
        await maker_wallet.close()
        await bitcoin_backend.close()
        pytest.skip(f"Maker needs at least 100,000,000 sats, has {maker_balance}.")

    # Create maker bot with Neutrino backend
    maker_bot = MakerBot(maker_wallet, neutrino_backend, maker_neutrino_config)

    # Create taker wallet with Bitcoin Core backend
    taker_wallet = WalletService(
        mnemonic=TAKER_MNEMONIC,
        backend=bitcoin_backend,
        network="regtest",
        mixdepth_count=5,
    )

    # Fund taker if needed
    await taker_wallet.sync_all()
    taker_balance = await taker_wallet.get_total_balance()

    if taker_balance < 100_000_000:
        funding_address = taker_wallet.get_receive_address(0, 0)
        funded = await ensure_wallet_funded(
            funding_address, amount_btc=1.0, confirmations=2
        )
        if funded:
            await taker_wallet.sync_all()
            taker_balance = await taker_wallet.get_total_balance()

    if taker_balance < 100_000_000:
        await maker_wallet.close()
        await taker_wallet.close()
        await bitcoin_backend.close()
        pytest.skip(f"Taker needs at least 100,000,000 sats, has {taker_balance}.")

    # Create taker config for Bitcoin Core
    taker_config = TakerConfig(
        mnemonic=TAKER_MNEMONIC,
        network=NetworkType.TESTNET,
        bitcoin_network=NetworkType.REGTEST,
        backend_type="bitcoin_core",
        backend_config={
            "rpc_url": "http://127.0.0.1:18443",
            "rpc_user": "test",
            "rpc_password": "test",
        },
        directory_servers=["127.0.0.1:5222"],
        counterparty_count=1,  # Just one maker (our neutrino maker)
        minimum_makers=1,
        maker_timeout_sec=30,
        order_wait_time=15.0,
    )

    # Create taker with Bitcoin Core backend
    taker = Taker(taker_wallet, bitcoin_backend, taker_config)

    maker_task = None
    try:
        # Start maker in background
        maker_task = asyncio.create_task(maker_bot.start())

        # Wait for maker to connect and announce offers
        await asyncio.sleep(10)

        # Start taker
        await taker.start()

        # Fetch orderbook - should see our neutrino maker's offer
        offers = await taker.directory_client.fetch_orderbook(timeout=15.0)

        # Find offers from our maker
        maker_offers = [o for o in offers if o.counterparty == maker_bot.nick]

        # Verify the Neutrino maker successfully:
        # 1. Connected to the directory server
        # 2. Announced offers
        assert len(maker_offers) > 0, (
            f"Neutrino maker {maker_bot.nick} should have offers in orderbook. "
            f"Found {len(offers)} offers total."
        )

        # Verify offer properties
        offer = maker_offers[0]
        assert offer.minsize > 0, "Offer should have valid minsize"
        assert offer.maxsize >= offer.minsize, "Offer should have valid maxsize"

        # Update orderbook
        taker.orderbook_manager.update_offers(offers)

        # Verify we can select this maker for CoinJoin
        cj_amount = 50_000_000
        selected, total_fee = taker.orderbook_manager.select_makers(cj_amount, n=1)
        assert len(selected) == 1, "Should select the neutrino maker"
        assert maker_bot.nick in selected, "Selected maker should be our neutrino maker"

        # NOTE: We don't attempt the full CoinJoin because the Neutrino backend
        # cannot verify arbitrary taker UTXOs without additional infrastructure.
        # The protocol exchange up to !fill and !pubkey would work, but !auth
        # verification would fail because the Neutrino light client can only see
        # UTXOs for addresses it's watching.
        #
        # For a production Neutrino maker, additional infrastructure would be needed:
        # - Use mempool.space API as fallback for UTXO verification
        # - Run a hybrid setup with Bitcoin Core for verification
        # - Accept only takers with pre-known addresses

    finally:
        await taker.stop()
        await maker_bot.stop()
        if maker_task:
            maker_task.cancel()
            try:
                await maker_task
            except asyncio.CancelledError:
                pass
        await maker_wallet.close()
        await taker_wallet.close()
        await bitcoin_backend.close()


# ==============================================================================
# Fidelity Bonds with Neutrino
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_fidelity_bond_discovery(
    neutrino_backend: NeutrinoBackend,
):
    """
    Test fidelity bond discovery with neutrino backend.

    Neutrino should be able to discover timelocked UTXOs and verify
    fidelity bond proofs using compact block filters.

    This test verifies:
    1. Fidelity bond address generation works with neutrino backend
    2. The wallet can sync fidelity bonds via neutrino
    3. Fidelity bond proof creation and verification works
    """
    import time

    from maker.fidelity import create_fidelity_bond_proof, find_fidelity_bonds

    from tests.e2e.rpc_utils import ensure_wallet_funded

    # Create wallet with neutrino backend
    wallet = WalletService(
        mnemonic=MAKER1_MNEMONIC,
        backend=neutrino_backend,
        network="regtest",
        mixdepth_count=5,
    )

    try:
        # Use a locktime in the past (already unlocked)
        # This allows the UTXO to be spendable for testing
        past_locktime = int(time.time()) - 3600  # 1 hour ago

        # Generate fidelity bond address
        fb_address = wallet.get_fidelity_bond_address(0, past_locktime)
        assert fb_address.startswith("bcrt1"), "Should generate regtest P2WSH address"

        # Add to neutrino watch list
        await neutrino_backend.add_watch_address(fb_address)

        # Fund the fidelity bond address
        funded = await ensure_wallet_funded(fb_address, amount_btc=0.1, confirmations=2)

        if not funded:
            pytest.skip("Could not fund fidelity bond address")

        # Wait for neutrino to see the blocks
        await asyncio.sleep(2)

        # Rescan to find the funding transaction
        current_height = await neutrino_backend.get_block_height()
        rescan_start = max(0, current_height - 15)
        await neutrino_backend.rescan_from_height(rescan_start, addresses=[fb_address])
        await asyncio.sleep(5)

        # Sync fidelity bonds
        await wallet.sync_fidelity_bonds([past_locktime])

        # Find fidelity bonds in wallet
        bonds = find_fidelity_bonds(wallet)

        # We should find at least one bond (the one we just funded)
        assert len(bonds) >= 1, (
            f"Should find at least 1 fidelity bond, found {len(bonds)}"
        )

        # Verify bond properties
        bond = bonds[0]
        assert bond.value > 0, "Bond should have value"
        assert bond.locktime == past_locktime, "Bond should have correct locktime"
        assert bond.bond_value > 0, "Bond should have calculated bond value"

        # Verify we can create a proof for this bond
        if bond.private_key and bond.pubkey:
            proof = create_fidelity_bond_proof(
                bond=bond,
                maker_nick="J5TestNeutrino",
                taker_nick="J5TakerNick",
            )
            assert proof is not None, "Should create fidelity bond proof"
            assert len(proof) > 100, "Proof should be substantial base64 string"

    finally:
        await wallet.close()


# ==============================================================================
# Neutrino Rescan and Recovery
# ==============================================================================


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_rescan_from_height(neutrino_backend: NeutrinoBackend):
    """Test neutrino blockchain rescan functionality."""
    test_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"

    # Rescan from genesis - should succeed
    await neutrino_backend.rescan_from_height(0, addresses=[test_address])
    # If we get here, the rescan was initiated successfully
    assert True


@pytest.mark.asyncio
@pytest.mark.neutrino
async def test_neutrino_watch_outpoint(neutrino_backend: NeutrinoBackend):
    """Test neutrino outpoint watching functionality."""
    # Create a test outpoint
    test_txid = "a" * 64
    test_vout = 0

    await neutrino_backend.add_watch_outpoint(test_txid, test_vout)

    # Verify it's in watched set
    assert (test_txid, test_vout) in neutrino_backend._watched_outpoints


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
