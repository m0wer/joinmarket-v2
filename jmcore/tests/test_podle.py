"""
Tests for jmcore.podle module.

Tests both PoDLE generation (taker side) and verification (maker side).
"""

import hashlib

import pytest

from jmcore.podle import (
    G_COMPRESSED,
    PRECOMPUTED_NUMS,
    SECP256K1_N,
    SECP256K1_P,
    PoDLECommitment,
    PoDLEError,
    deserialize_revelation,
    generate_podle,
    get_nums_point,
    parse_podle_revelation,
    point_add,
    point_mult,
    point_to_bytes,
    scalar_mult_g,
    serialize_revelation,
    verify_podle,
)


class TestConstants:
    """Tests for PoDLE constants."""

    def test_secp256k1_n(self) -> None:
        """Test curve order is correct."""
        assert (
            int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            == SECP256K1_N
        )

    def test_secp256k1_p(self) -> None:
        """Test field prime is correct."""
        assert SECP256K1_P == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def test_g_compressed(self) -> None:
        """Test generator point is compressed."""
        assert len(G_COMPRESSED) == 33
        assert G_COMPRESSED[0] in (0x02, 0x03)

    def test_precomputed_nums_count(self) -> None:
        """Test we have 10 NUMS points."""
        assert len(PRECOMPUTED_NUMS) == 10

    def test_precomputed_nums_format(self) -> None:
        """Test NUMS points are valid compressed pubkeys."""
        for idx, point_bytes in PRECOMPUTED_NUMS.items():
            assert len(point_bytes) == 33, f"NUMS point {idx} wrong length"
            assert point_bytes[0] in (0x02, 0x03), f"NUMS point {idx} wrong prefix"


class TestGetNumsPoint:
    """Tests for get_nums_point function."""

    def test_valid_index(self) -> None:
        """Test getting valid NUMS points."""
        for i in range(10):
            point = get_nums_point(i)
            assert point is not None
            compressed = point_to_bytes(point)
            assert compressed == PRECOMPUTED_NUMS[i]

    def test_invalid_index_negative(self) -> None:
        """Test negative index raises error."""
        with pytest.raises(PoDLEError, match="not supported"):
            get_nums_point(-1)

    def test_invalid_index_too_high(self) -> None:
        """Test index > 9 raises error."""
        with pytest.raises(PoDLEError, match="not supported"):
            get_nums_point(10)


class TestECOperations:
    """Tests for elliptic curve operations."""

    def test_scalar_mult_g(self) -> None:
        """Test scalar multiplication with generator."""
        # Private key 1 should give generator point
        result = scalar_mult_g(1)
        compressed = point_to_bytes(result)
        assert compressed == G_COMPRESSED

    def test_scalar_mult_g_modulo(self) -> None:
        """Test scalar is taken modulo N."""
        # Scalar = N should give same as scalar = 0 (but 0 is invalid)
        # Scalar = N + 1 should give same as scalar = 1
        result = scalar_mult_g(SECP256K1_N + 1)
        compressed = point_to_bytes(result)
        assert compressed == G_COMPRESSED

    def test_point_add(self) -> None:
        """Test point addition."""
        g = scalar_mult_g(1)
        g2 = scalar_mult_g(2)

        # G + G should equal 2*G
        result = point_add(g, g)
        assert point_to_bytes(result) == point_to_bytes(g2)

    def test_point_mult(self) -> None:
        """Test point scalar multiplication."""
        j0 = get_nums_point(0)

        # 2 * J0
        result = point_mult(2, j0)
        # This should be a valid point
        compressed = point_to_bytes(result)
        assert len(compressed) == 33

    def test_point_to_bytes(self) -> None:
        """Test point serialization."""
        g = scalar_mult_g(1)
        compressed = point_to_bytes(g)
        assert len(compressed) == 33
        assert compressed[0] in (0x02, 0x03)


class TestGeneratePoDLE:
    """Tests for PoDLE generation."""

    def test_generate_valid(self) -> None:
        """Test generating a valid PoDLE commitment."""
        # Use a known private key
        private_key = bytes([1] * 32)
        utxo_str = "a" * 64 + ":0"

        commitment = generate_podle(private_key, utxo_str, index=0)

        assert isinstance(commitment, PoDLECommitment)
        assert len(commitment.commitment) == 32
        assert len(commitment.p) == 33
        assert len(commitment.p2) == 33
        assert len(commitment.sig) == 32
        assert len(commitment.e) == 32
        assert commitment.utxo == utxo_str
        assert commitment.index == 0

    def test_commitment_is_hash_of_p2(self) -> None:
        """Test commitment = H(P2)."""
        private_key = bytes([2] * 32)
        utxo_str = "b" * 64 + ":1"

        commitment = generate_podle(private_key, utxo_str)

        expected_commitment = hashlib.sha256(commitment.p2).digest()
        assert commitment.commitment == expected_commitment

    def test_different_indices_give_different_p2(self) -> None:
        """Test different NUMS indices give different P2."""
        private_key = bytes([3] * 32)
        utxo_str = "c" * 64 + ":2"

        c0 = generate_podle(private_key, utxo_str, index=0)
        c1 = generate_podle(private_key, utxo_str, index=1)

        assert c0.p == c1.p  # Same P (derived from same private key)
        assert c0.p2 != c1.p2  # Different P2 (different J point)

    def test_invalid_private_key_length(self) -> None:
        """Test invalid private key length."""
        with pytest.raises(PoDLEError, match="Invalid private key length"):
            generate_podle(b"short", "a" * 64 + ":0")

    def test_invalid_nums_index(self) -> None:
        """Test invalid NUMS index."""
        with pytest.raises(PoDLEError, match="Invalid NUMS index"):
            generate_podle(bytes([1] * 32), "a" * 64 + ":0", index=99)

    def test_zero_private_key(self) -> None:
        """Test zero private key is rejected."""
        with pytest.raises(PoDLEError, match="Invalid private key value"):
            generate_podle(bytes(32), "a" * 64 + ":0")


class TestVerifyPoDLE:
    """Tests for PoDLE verification."""

    def test_verify_valid_proof(self) -> None:
        """Test verification of valid proof."""
        private_key = bytes([5] * 32)
        utxo_str = "d" * 64 + ":3"

        commitment = generate_podle(private_key, utxo_str, index=0)

        is_valid, error = verify_podle(
            p=commitment.p,
            p2=commitment.p2,
            sig=commitment.sig,
            e=commitment.e,
            commitment=commitment.commitment,
            index_range=range(10),
        )

        assert is_valid, f"Verification should succeed: {error}"
        assert error == ""

    def test_verify_fails_wrong_commitment(self) -> None:
        """Test verification fails with wrong commitment."""
        private_key = bytes([6] * 32)
        utxo_str = "e" * 64 + ":4"

        commitment = generate_podle(private_key, utxo_str)

        is_valid, error = verify_podle(
            p=commitment.p,
            p2=commitment.p2,
            sig=commitment.sig,
            e=commitment.e,
            commitment=bytes(32),  # Wrong commitment
            index_range=range(10),
        )

        assert not is_valid
        assert "Commitment does not match" in error

    def test_verify_fails_wrong_signature(self) -> None:
        """Test verification fails with wrong signature."""
        private_key = bytes([7] * 32)
        utxo_str = "f" * 64 + ":5"

        commitment = generate_podle(private_key, utxo_str)

        is_valid, error = verify_podle(
            p=commitment.p,
            p2=commitment.p2,
            sig=bytes(32),  # Wrong signature
            e=commitment.e,
            commitment=commitment.commitment,
            index_range=range(10),
        )

        assert not is_valid

    def test_verify_fails_invalid_lengths(self) -> None:
        """Test verification fails with invalid input lengths."""
        is_valid, error = verify_podle(
            p=b"short",
            p2=bytes(33),
            sig=bytes(32),
            e=bytes(32),
            commitment=bytes(32),
        )
        assert not is_valid
        assert "Invalid P length" in error


class TestRevelationParsing:
    """Tests for revelation parsing and serialization."""

    def test_parse_valid_revelation(self) -> None:
        """Test parsing a valid revelation dict."""
        revelation = {
            "P": "02" + "aa" * 32,
            "P2": "03" + "bb" * 32,
            "sig": "cc" * 32,
            "e": "dd" * 32,
            "utxo": "ee" * 32 + ":0",
        }

        parsed = parse_podle_revelation(revelation)

        assert parsed is not None
        assert len(parsed["P"]) == 33
        assert len(parsed["P2"]) == 33
        assert len(parsed["sig"]) == 32
        assert len(parsed["e"]) == 32
        assert parsed["txid"] == "ee" * 32
        assert parsed["vout"] == 0

    def test_parse_missing_field(self) -> None:
        """Test parsing fails with missing field."""
        revelation = {
            "P": "02" + "aa" * 32,
            # Missing P2
            "sig": "cc" * 32,
            "e": "dd" * 32,
            "utxo": "ee" * 32 + ":0",
        }

        parsed = parse_podle_revelation(revelation)
        assert parsed is None

    def test_parse_invalid_utxo_format(self) -> None:
        """Test parsing fails with invalid UTXO format."""
        revelation = {
            "P": "02" + "aa" * 32,
            "P2": "03" + "bb" * 32,
            "sig": "cc" * 32,
            "e": "dd" * 32,
            "utxo": "invalid_utxo",  # Missing :vout
        }

        parsed = parse_podle_revelation(revelation)
        assert parsed is None

    def test_deserialize_valid_revelation(self) -> None:
        """Test deserializing wire format."""
        wire_format = "|".join(
            [
                "02" + "aa" * 32,  # P
                "03" + "bb" * 32,  # P2
                "cc" * 32,  # sig
                "dd" * 32,  # e
                "ee" * 32 + ":0",  # utxo
            ]
        )

        parsed = deserialize_revelation(wire_format)

        assert parsed is not None
        assert parsed["P"] == "02" + "aa" * 32
        assert parsed["utxo"] == "ee" * 32 + ":0"

    def test_deserialize_wrong_parts(self) -> None:
        """Test deserialization fails with wrong number of parts."""
        wire_format = "part1|part2|part3"  # Only 3 parts
        parsed = deserialize_revelation(wire_format)
        assert parsed is None


class TestPoDLECommitment:
    """Tests for PoDLECommitment dataclass."""

    def test_to_revelation(self) -> None:
        """Test converting commitment to revelation dict."""
        commitment = PoDLECommitment(
            commitment=bytes(32),
            p=b"\x02" + bytes(32),
            p2=b"\x03" + bytes(32),
            sig=bytes(32),
            e=bytes(32),
            utxo="txid:0",
            index=0,
        )

        revelation = commitment.to_revelation()

        assert "P" in revelation
        assert "P2" in revelation
        assert "sig" in revelation
        assert "e" in revelation
        assert "utxo" in revelation
        assert revelation["utxo"] == "txid:0"

    def test_to_commitment_str(self) -> None:
        """Test getting commitment as hex string."""
        commitment = PoDLECommitment(
            commitment=bytes.fromhex("aa" * 32),
            p=b"\x02" + bytes(32),
            p2=b"\x03" + bytes(32),
            sig=bytes(32),
            e=bytes(32),
            utxo="txid:0",
            index=0,
        )

        hex_str = commitment.to_commitment_str()
        assert hex_str == "aa" * 32


class TestSerializeRevelation:
    """Tests for revelation serialization."""

    def test_serialize_revelation(self) -> None:
        """Test serializing commitment to wire format."""
        commitment = PoDLECommitment(
            commitment=bytes(32),
            p=bytes.fromhex("02" + "aa" * 32),
            p2=bytes.fromhex("03" + "bb" * 32),
            sig=bytes.fromhex("cc" * 32),
            e=bytes.fromhex("dd" * 32),
            utxo="ee" * 32 + ":0",
            index=0,
        )

        wire = serialize_revelation(commitment)

        parts = wire.split("|")
        assert len(parts) == 5
        assert parts[0] == "02" + "aa" * 32
        assert parts[4] == "ee" * 32 + ":0"

    def test_roundtrip(self) -> None:
        """Test serialization roundtrip."""
        private_key = bytes([8] * 32)
        utxo_str = "g" * 64 + ":6"

        original = generate_podle(private_key, utxo_str)
        wire = serialize_revelation(original)
        parsed = deserialize_revelation(wire)

        assert parsed is not None
        assert parsed["P"] == original.p.hex()
        assert parsed["P2"] == original.p2.hex()
        assert parsed["sig"] == original.sig.hex()
        assert parsed["e"] == original.e.hex()
        assert parsed["utxo"] == original.utxo


class TestFullFlow:
    """Integration tests for full PoDLE flow."""

    def test_generate_and_verify(self) -> None:
        """Test full flow: generate commitment, serialize, parse, verify."""
        # Taker generates PoDLE
        private_key = bytes([9] * 32)
        utxo_str = "h" * 64 + ":7"

        commitment = generate_podle(private_key, utxo_str, index=0)

        # Taker sends commitment to maker
        commitment_hex = commitment.to_commitment_str()
        assert len(commitment_hex) == 64

        # Maker accepts, taker sends revelation
        wire = serialize_revelation(commitment)

        # Maker parses and verifies
        parsed_wire = deserialize_revelation(wire)
        assert parsed_wire is not None

        parsed_revelation = parse_podle_revelation(parsed_wire)
        assert parsed_revelation is not None

        is_valid, error = verify_podle(
            p=parsed_revelation["P"],
            p2=parsed_revelation["P2"],
            sig=parsed_revelation["sig"],
            e=parsed_revelation["e"],
            commitment=commitment.commitment,
            index_range=range(10),
        )

        assert is_valid, f"Full flow verification failed: {error}"

    def test_all_nums_indices(self) -> None:
        """Test PoDLE works with all NUMS indices."""
        private_key = bytes([10] * 32)
        utxo_str = "i" * 64 + ":8"

        for idx in range(10):
            commitment = generate_podle(private_key, utxo_str, index=idx)

            is_valid, error = verify_podle(
                p=commitment.p,
                p2=commitment.p2,
                sig=commitment.sig,
                e=commitment.e,
                commitment=commitment.commitment,
                index_range=range(10),
            )

            assert is_valid, f"Index {idx} verification failed: {error}"
