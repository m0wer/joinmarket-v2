"""
Pytest configuration and fixtures for maker tests.
"""

import pytest
from coincurve import PrivateKey


@pytest.fixture
def test_mnemonic() -> str:
    """Test mnemonic (BIP39 test vector)"""
    return (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )


@pytest.fixture
def test_network() -> str:
    """Test network"""
    return "regtest"


@pytest.fixture
def test_private_key() -> PrivateKey:
    """Generate a test ECDSA private key for fidelity bond tests."""
    return PrivateKey()


@pytest.fixture
def test_pubkey(test_private_key: PrivateKey) -> bytes:
    """Get compressed public key from test private key."""
    return test_private_key.public_key.format(compressed=True)
