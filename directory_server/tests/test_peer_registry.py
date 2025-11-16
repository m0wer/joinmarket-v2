"""
Tests for peer registry.
"""

import pytest
from jmcore.models import NetworkType, PeerInfo, PeerStatus

from directory_server.peer_registry import PeerRegistry


@pytest.fixture
def registry():
    return PeerRegistry(max_peers=10)


@pytest.fixture
def sample_peer():
    return PeerInfo(
        nick="test_peer",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion",
        port=5222,
        network=NetworkType.MAINNET,
    )


def test_register_peer(registry, sample_peer):
    registry.register(sample_peer)

    assert registry.count() == 1
    retrieved = registry.get_by_nick("test_peer")
    assert retrieved is not None
    assert retrieved.nick == "test_peer"


def test_register_duplicate_nick(registry, sample_peer):
    registry.register(sample_peer)

    peer2 = PeerInfo(
        nick="test_peer",
        onion_address="abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvw2.onion",
        port=5222,
    )
    registry.register(peer2)

    assert registry.count() == 2


def test_max_peers_limit(registry):
    for i in range(10):
        peer = PeerInfo(nick=f"peer{i}", onion_address=f"{'a' * 56}.onion", port=5222 + i)
        registry.register(peer)

    assert registry.count() == 10

    with pytest.raises(ValueError, match="Maximum peers reached"):
        extra_peer = PeerInfo(nick="extra", onion_address=f"{'b' * 56}.onion", port=6000)
        registry.register(extra_peer)


def test_unregister_peer(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    registry.unregister(location)

    assert registry.count() == 0
    assert registry.get_by_nick("test_peer") is None


def test_get_by_location(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    retrieved = registry.get_by_location(location)
    assert retrieved is not None
    assert retrieved.nick == "test_peer"


def test_update_status(registry, sample_peer):
    registry.register(sample_peer)
    location = sample_peer.location_string()

    registry.update_status(location, PeerStatus.HANDSHAKED)

    peer = registry.get_by_location(location)
    assert peer.status == PeerStatus.HANDSHAKED


def test_get_all_connected(registry):
    for i in range(3):
        peer = PeerInfo(
            nick=f"peer{i}",
            onion_address=f"{'a' * 56}.onion",
            port=5220 + i,
            network=NetworkType.MAINNET,
        )
        registry.register(peer)
        registry.update_status(peer.location_string(), PeerStatus.HANDSHAKED)

    connected = registry.get_all_connected(NetworkType.MAINNET)
    assert len(connected) == 3


def test_get_all_connected_filters_network(registry):
    mainnet_peer = PeerInfo(
        nick="mainnet", onion_address=f"{'a' * 56}.onion", port=5222, network=NetworkType.MAINNET
    )
    testnet_peer = PeerInfo(
        nick="testnet", onion_address=f"{'b' * 56}.onion", port=5222, network=NetworkType.TESTNET
    )

    registry.register(mainnet_peer)
    registry.register(testnet_peer)
    registry.update_status(mainnet_peer.location_string(), PeerStatus.HANDSHAKED)
    registry.update_status(testnet_peer.location_string(), PeerStatus.HANDSHAKED)

    mainnet_peers = registry.get_all_connected(NetworkType.MAINNET)
    assert len(mainnet_peers) == 1
    assert mainnet_peers[0].nick == "mainnet"


def test_get_peerlist_for_network(registry):
    peer = PeerInfo(
        nick="peer1", onion_address=f"{'a' * 56}.onion", port=5222, network=NetworkType.MAINNET
    )
    registry.register(peer)
    registry.update_status(peer.location_string(), PeerStatus.HANDSHAKED)

    peerlist = registry.get_peerlist_for_network(NetworkType.MAINNET)
    assert len(peerlist) == 1
    assert peerlist[0] == ("peer1", peer.location_string())


def test_clear(registry, sample_peer):
    registry.register(sample_peer)
    registry.clear()

    assert registry.count() == 0
    assert registry.get_by_nick("test_peer") is None


def test_get_passive_peers(registry):
    passive_peer1 = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    passive_peer2 = PeerInfo(
        nick="taker2",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    active_peer = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    registry.register(passive_peer1)
    registry.register(passive_peer2)
    registry.register(active_peer)

    passive_peers = registry.get_passive_peers()
    assert len(passive_peers) == 2
    assert all(p.onion_address == "NOT-SERVING-ONION" for p in passive_peers)
    assert "taker1" in [p.nick for p in passive_peers]
    assert "taker2" in [p.nick for p in passive_peers]


def test_get_active_peers(registry):
    passive_peer = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    active_peer1 = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    active_peer2 = PeerInfo(
        nick="maker2",
        onion_address=f"{'b' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    registry.register(passive_peer)
    registry.register(active_peer1)
    registry.register(active_peer2)

    active_peers = registry.get_active_peers()
    assert len(active_peers) == 2
    assert all(p.onion_address != "NOT-SERVING-ONION" for p in active_peers)
    assert "maker1" in [p.nick for p in active_peers]
    assert "maker2" in [p.nick for p in active_peers]


def test_get_passive_peers_filters_network(registry):
    mainnet_passive = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    testnet_passive = PeerInfo(
        nick="taker2",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.TESTNET,
        status=PeerStatus.HANDSHAKED,
    )

    registry.register(mainnet_passive)
    registry.register(testnet_passive)

    mainnet_peers = registry.get_passive_peers(NetworkType.MAINNET)
    assert len(mainnet_peers) == 1
    assert mainnet_peers[0].nick == "taker1"


def test_get_active_peers_filters_network(registry):
    mainnet_active = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    testnet_active = PeerInfo(
        nick="maker2",
        onion_address=f"{'b' * 56}.onion",
        port=5222,
        network=NetworkType.TESTNET,
        status=PeerStatus.HANDSHAKED,
    )

    registry.register(mainnet_active)
    registry.register(testnet_active)

    mainnet_peers = registry.get_active_peers(NetworkType.MAINNET)
    assert len(mainnet_peers) == 1
    assert mainnet_peers[0].nick == "maker1"


def test_get_stats_includes_passive_and_active(registry):
    passive_peer = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )
    active_peer = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
    )

    registry.register(passive_peer)
    registry.register(active_peer)

    stats = registry.get_stats()
    assert stats["total_peers"] == 2
    assert stats["connected_peers"] == 2
    assert stats["passive_peers"] == 1
    assert stats["active_peers"] == 1


def test_passive_peers_exclude_directories(registry):
    passive_peer = PeerInfo(
        nick="taker1",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
        is_directory=False,
    )
    directory_peer = PeerInfo(
        nick="directory",
        onion_address="NOT-SERVING-ONION",
        port=-1,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
        is_directory=True,
    )

    registry.register(passive_peer)
    registry.register(directory_peer)

    passive_peers = registry.get_passive_peers()
    assert len(passive_peers) == 1
    assert passive_peers[0].nick == "taker1"


def test_active_peers_exclude_directories(registry):
    active_peer = PeerInfo(
        nick="maker1",
        onion_address=f"{'a' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
        is_directory=False,
    )
    directory_peer = PeerInfo(
        nick="directory",
        onion_address=f"{'b' * 56}.onion",
        port=5222,
        network=NetworkType.MAINNET,
        status=PeerStatus.HANDSHAKED,
        is_directory=True,
    )

    registry.register(active_peer)
    registry.register(directory_peer)

    active_peers = registry.get_active_peers()
    assert len(active_peers) == 1
    assert active_peers[0].nick == "maker1"
