"""
Legacy compatibility wrapper for DirectoryClient.

This module re-exports jmcore.DirectoryClient for backward compatibility.
All new code should import directly from jmcore.directory_client.
"""

from jmcore.directory_client import (
    DirectoryClient,
    DirectoryClientError,
    parse_fidelity_bond_proof,
)

__all__ = ["DirectoryClient", "DirectoryClientError", "parse_fidelity_bond_proof"]
