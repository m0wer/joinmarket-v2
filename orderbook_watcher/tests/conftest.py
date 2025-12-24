"""
Test fixtures and configuration.
"""

from typing import Any

import pytest


@pytest.fixture
def sample_offer_data() -> dict[str, Any]:
    return {
        "counterparty": "J5test",
        "oid": 0,
        "ordertype": "sw0reloffer",
        "minsize": 100000,
        "maxsize": 10000000,
        "txfee": 1000,
        "cjfee": "0.0002",
        "fidelity_bond_value": 5000000,
    }


@pytest.fixture
def sample_bond_data() -> dict[str, Any]:
    return {
        "counterparty": "J5test",
        "utxo": {
            "txid": "a" * 64,
            "vout": 0,
        },
        "bond_value": 5000000,
        "locktime": 1700000000,
        "amount": 10000000,
        "script": "abc123",
        "utxo_confirmations": 100,
        "utxo_confirmation_timestamp": 1600000000,
        "cert_expiry": 850000,
    }
