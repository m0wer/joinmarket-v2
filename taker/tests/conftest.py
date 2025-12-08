"""
Test configuration for taker tests.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_mnemonic() -> str:
    """Test mnemonic (not for production use!)."""
    return (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )
