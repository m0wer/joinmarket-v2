"""
Cryptographic primitives for JoinMarket.
"""

from __future__ import annotations

import binascii
import hashlib
import secrets

from coincurve import PrivateKey, PublicKey
from coincurve import verify_signature as coincurve_verify

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
NICK_HASH_LENGTH = 10
NICK_MAX_ENCODED = 14


class CryptoError(Exception):
    pass


def base58_encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")

    result = ""
    while num > 0:
        num, remainder = divmod(num, 58)
        result = BASE58_ALPHABET[remainder] + result

    for byte in data:
        if byte == 0:
            result = BASE58_ALPHABET[0] + result
        else:
            break

    return result


def generate_jm_nick(version: int = 5) -> str:
    privkey_bytes = secrets.token_bytes(32)
    private_key = PrivateKey(privkey_bytes)
    pubkey_bytes = private_key.public_key.format(compressed=False)

    pubkey_hex = binascii.hexlify(pubkey_bytes)
    nick_pkh_raw = hashlib.sha256(pubkey_hex).digest()[:NICK_HASH_LENGTH]
    nick_pkh = base58_encode(nick_pkh_raw)

    nick_pkh += "O" * (NICK_MAX_ENCODED - len(nick_pkh))

    return f"J{version}{nick_pkh}"


class KeyPair:
    def __init__(self, private_key: PrivateKey | None = None):
        if private_key is None:
            private_key = PrivateKey()
        self._private_key = private_key
        self._public_key = private_key.public_key

    @property
    def private_key(self) -> PrivateKey:
        return self._private_key

    @property
    def public_key(self) -> PublicKey:
        return self._public_key

    def sign(self, message: bytes) -> bytes:
        """Sign a message with SHA256 hashing."""
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            return self._public_key.verify(signature, message)
        except Exception:
            return False

    def public_key_bytes(self) -> bytes:
        return self._public_key.format(compressed=True)

    def public_key_hex(self) -> str:
        return self.public_key_bytes().hex()


def verify_signature(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        return coincurve_verify(signature, message, public_key_bytes)
    except Exception:
        return False
