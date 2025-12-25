"""
Tests for maker configuration validation.
"""

import pytest
from jmcore.models import OfferType
from pydantic import ValidationError

from maker.config import MakerConfig

# Test mnemonic (BIP39 test vector)
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)


def test_valid_config() -> None:
    """Test that valid configuration is accepted."""
    config = MakerConfig(
        mnemonic=TEST_MNEMONIC,
        cj_fee_relative="0.001",
        offer_type=OfferType.SW0_RELATIVE,
    )
    assert config.cj_fee_relative == "0.001"


def test_zero_cj_fee_relative_fails() -> None:
    """Test that zero cj_fee_relative fails for relative offer types."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be > 0"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="0",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_negative_cj_fee_relative_fails() -> None:
    """Test that negative cj_fee_relative fails for relative offer types."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be > 0"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="-0.001",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_invalid_cj_fee_relative_string_fails() -> None:
    """Test that invalid string for cj_fee_relative fails."""
    with pytest.raises(ValidationError, match="cj_fee_relative must be a valid number"):
        MakerConfig(
            mnemonic=TEST_MNEMONIC,
            cj_fee_relative="not_a_number",
            offer_type=OfferType.SW0_RELATIVE,
        )


def test_zero_cj_fee_relative_ok_for_absolute_offers() -> None:
    """Test that zero cj_fee_relative is OK for absolute offer types."""
    config = MakerConfig(
        mnemonic=TEST_MNEMONIC,
        cj_fee_relative="0",
        offer_type=OfferType.SW0_ABSOLUTE,
        cj_fee_absolute=500,
    )
    assert config.cj_fee_relative == "0"
    assert config.offer_type == OfferType.SW0_ABSOLUTE
