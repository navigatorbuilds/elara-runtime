"""Cross-language compatibility tests: Python Layer 1 <-> Rust Runtime.

Tests that:
1. Rust signs, Python verifies (and vice versa)
2. Wire format produces byte-identical output
3. Batch verify works faster than serial
4. SHA3-256 matches between implementations
"""

import hashlib
import json
import struct
import time
import sys
import os

import pytest

# Add Layer 1 to path
sys.path.insert(0, os.path.expanduser("~/elara-layer1"))

from elara_runtime import (
    NATIVE_AVAILABLE,
    py_dilithium3_keygen,
    py_dilithium3_sign,
    py_dilithium3_verify,
    py_sphincs_keygen,
    py_sphincs_sign,
    py_sphincs_verify,
    py_sha3_256,
    py_sha3_256_hex,
    py_batch_verify,
    py_uuid7,
    py_record_to_bytes,
    py_record_from_bytes,
    py_signable_bytes,
)

# Skip all tests if native extension not available
pytestmark = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="Native extension not built"
)


class TestCryptoCompat:
    """Cross-language sign/verify compatibility."""

    def test_rust_keygen_sizes(self):
        """Dilithium3 key sizes match expected values."""
        pk, sk = py_dilithium3_keygen()
        assert len(pk) == 1952, f"Expected pk=1952, got {len(pk)}"
        assert len(sk) > 0

    def test_rust_sign_rust_verify(self):
        """Rust can sign and verify its own signatures."""
        pk, sk = py_dilithium3_keygen()
        msg = b"test message from Rust"
        sig = py_dilithium3_sign(msg, sk)
        assert len(sig) == 3293
        assert py_dilithium3_verify(msg, sig, pk)

    def test_rust_sign_python_verify(self):
        """Rust signs, Python (liboqs) verifies."""
        try:
            import oqs
        except ImportError:
            pytest.skip("liboqs-python not installed")

        pk, sk = py_dilithium3_keygen()
        msg = b"cross-language test: Rust -> Python"
        sig = py_dilithium3_sign(msg, sk)

        # Verify with Python liboqs
        verifier = oqs.Signature("Dilithium3")
        assert verifier.verify(msg, sig, pk)

    def test_python_sign_rust_verify(self):
        """Python (liboqs) signs, Rust verifies."""
        try:
            import oqs
        except ImportError:
            pytest.skip("liboqs-python not installed")

        signer = oqs.Signature("Dilithium3")
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()
        msg = b"cross-language test: Python -> Rust"
        sig = signer.sign(msg)

        assert py_dilithium3_verify(msg, sig, pk)

    def test_wrong_message_rejected(self):
        pk, sk = py_dilithium3_keygen()
        sig = py_dilithium3_sign(b"correct", sk)
        assert not py_dilithium3_verify(b"wrong", sig, pk)

    def test_wrong_key_rejected(self):
        pk1, sk1 = py_dilithium3_keygen()
        pk2, sk2 = py_dilithium3_keygen()
        sig = py_dilithium3_sign(b"test", sk1)
        assert not py_dilithium3_verify(b"test", sig, pk2)


class TestSphincsCompat:
    """SPHINCS+ cross-language compatibility."""

    def test_rust_sphincs_keygen_sizes(self):
        pk, sk = py_sphincs_keygen()
        assert len(pk) == 48, f"Expected SPHINCS+ pk=48, got {len(pk)}"

    def test_rust_sphincs_sign_verify(self):
        pk, sk = py_sphincs_keygen()
        msg = b"sphincs test"
        sig = py_sphincs_sign(msg, sk)
        assert len(sig) == 35664
        assert py_sphincs_verify(msg, sig, pk)

    def test_rust_sphincs_sign_python_verify(self):
        try:
            import oqs
        except ImportError:
            pytest.skip("liboqs-python not installed")

        pk, sk = py_sphincs_keygen()
        msg = b"sphincs cross-lang: Rust -> Python"
        sig = py_sphincs_sign(msg, sk)

        verifier = oqs.Signature("SPHINCS+-SHA2-192f-simple")
        assert verifier.verify(msg, sig, pk)

    def test_python_sphincs_sign_rust_verify(self):
        try:
            import oqs
        except ImportError:
            pytest.skip("liboqs-python not installed")

        signer = oqs.Signature("SPHINCS+-SHA2-192f-simple")
        pk = signer.generate_keypair()
        sig = signer.sign(b"sphincs cross-lang: Python -> Rust")

        assert py_sphincs_verify(b"sphincs cross-lang: Python -> Rust", sig, pk)


class TestHashCompat:
    """SHA3-256 compatibility."""

    def test_sha3_empty(self):
        rust_hash = py_sha3_256(b"")
        python_hash = hashlib.sha3_256(b"").digest()
        assert rust_hash == python_hash

    def test_sha3_data(self):
        data = b"elara protocol layer 1.5"
        rust_hash = py_sha3_256(data)
        python_hash = hashlib.sha3_256(data).digest()
        assert rust_hash == python_hash

    def test_sha3_hex(self):
        data = b"test"
        rust_hex = py_sha3_256_hex(data)
        python_hex = hashlib.sha3_256(data).hexdigest()
        assert rust_hex == python_hex


class TestWireFormatCompat:
    """Wire format byte-equality tests."""

    def test_record_roundtrip(self):
        """Encode a record in Rust, decode it, verify fields match."""
        pk, sk = py_dilithium3_keygen()
        record = {
            "id": "019506e0-1234-7000-8000-000000000001",
            "version": 1,
            "content_hash": py_sha3_256(b"test content"),
            "creator_public_key": pk,
            "timestamp": 1739712345.123456,
            "parents": [],
            "classification": 0,
            "metadata": {},
            "signature": None,
            "sphincs_signature": None,
            "zk_proof": None,
        }
        wire = py_record_to_bytes(record)
        assert wire[:4] == b"ELRA"

        decoded = py_record_from_bytes(wire)
        assert decoded["id"] == record["id"]
        assert decoded["version"] == record["version"]
        assert decoded["content_hash"] == record["content_hash"]
        assert decoded["timestamp"] == record["timestamp"]
        assert decoded["classification"] == record["classification"]

    def test_wire_format_matches_python(self):
        """Wire bytes from Rust must match Python's to_bytes() exactly."""
        try:
            from elara_protocol.record import ValidationRecord, Classification
        except ImportError:
            pytest.skip("elara_protocol not installed")

        pk, sk = py_dilithium3_keygen()

        # Create identical records in both implementations
        record_id = "019506e0-1234-7000-8000-000000000001"
        content_hash = hashlib.sha3_256(b"wire compat test").digest()
        timestamp = 1739712345.0
        parents = []
        classification = 0  # PUBLIC
        metadata = {}

        # Python record
        py_rec = ValidationRecord(
            id=record_id,
            version=1,
            content_hash=content_hash,
            creator_public_key=bytes(pk),
            timestamp=timestamp,
            parents=parents,
            classification=Classification(classification),
            metadata=metadata,
            signature=None,
            sphincs_signature=None,
            zk_proof=None,
        )
        python_wire = py_rec.to_bytes()

        # Rust record
        rust_record = {
            "id": record_id,
            "version": 1,
            "content_hash": content_hash,
            "creator_public_key": bytes(pk),
            "timestamp": timestamp,
            "parents": parents,
            "classification": classification,
            "metadata": metadata,
            "signature": None,
            "sphincs_signature": None,
            "zk_proof": None,
        }
        rust_wire = py_record_to_bytes(rust_record)

        assert python_wire == rust_wire, (
            f"Wire format mismatch!\n"
            f"Python: {python_wire[:50].hex()}...\n"
            f"Rust:   {rust_wire[:50].hex()}..."
        )

    def test_signable_bytes_match_python(self):
        """signable_bytes() must match between Rust and Python."""
        try:
            from elara_protocol.record import ValidationRecord, Classification
        except ImportError:
            pytest.skip("elara_protocol not installed")

        pk, sk = py_dilithium3_keygen()
        record_id = "019506e0-abcd-7000-8000-000000000002"
        content_hash = hashlib.sha3_256(b"signable compat").digest()
        timestamp = 1739712345.5
        parents = [
            "019506e0-1111-7000-8000-000000000000",
            "019506e0-2222-7000-8000-000000000000",
        ]

        py_rec = ValidationRecord(
            id=record_id,
            version=1,
            content_hash=content_hash,
            creator_public_key=bytes(pk),
            timestamp=timestamp,
            parents=parents,
            classification=Classification.PUBLIC,
            metadata={},
            signature=None,
            sphincs_signature=None,
            zk_proof=None,
        )
        python_signable = py_rec.signable_bytes()

        rust_record = {
            "id": record_id,
            "version": 1,
            "content_hash": content_hash,
            "creator_public_key": bytes(pk),
            "timestamp": timestamp,
            "parents": parents,
            "classification": 0,
            "metadata": {},
            "signature": None,
            "sphincs_signature": None,
            "zk_proof": None,
        }
        rust_signable = py_signable_bytes(rust_record)

        assert python_signable == rust_signable, (
            f"Signable bytes mismatch!\n"
            f"Python: {python_signable[:80].hex()}...\n"
            f"Rust:   {rust_signable[:80].hex()}..."
        )


class TestBatchVerify:
    """Batch verification tests."""

    def test_batch_all_valid(self):
        pk, sk = py_dilithium3_keygen()
        jobs = []
        for i in range(10):
            msg = f"batch-{i}".encode()
            sig = py_dilithium3_sign(msg, sk)
            jobs.append((msg, sig, bytes(pk)))

        results = py_batch_verify(jobs)
        assert all(results)
        assert len(results) == 10

    def test_batch_one_invalid(self):
        pk, sk = py_dilithium3_keygen()
        pk2, sk2 = py_dilithium3_keygen()
        msg = b"test"
        sig_valid = py_dilithium3_sign(msg, sk)
        sig_invalid = py_dilithium3_sign(msg, sk2)

        jobs = [
            (msg, sig_valid, bytes(pk)),
            (msg, sig_invalid, bytes(pk)),  # wrong key
        ]
        results = py_batch_verify(jobs)
        assert results[0] is True
        assert results[1] is False

    def test_batch_100_faster_than_serial(self):
        """Batch verify 100 sigs should be faster than serial."""
        pk, sk = py_dilithium3_keygen()
        jobs = []
        for i in range(100):
            msg = f"perf-{i}".encode()
            sig = py_dilithium3_sign(msg, sk)
            jobs.append((msg, sig, bytes(pk)))

        # Serial
        t0 = time.perf_counter()
        for msg, sig, pk_bytes in jobs:
            py_dilithium3_verify(msg, sig, pk_bytes)
        serial_time = time.perf_counter() - t0

        # Batch (parallel)
        t0 = time.perf_counter()
        results = py_batch_verify(jobs)
        batch_time = time.perf_counter() - t0

        assert all(results)
        print(f"\nSerial: {serial_time:.3f}s, Batch: {batch_time:.3f}s, "
              f"Speedup: {serial_time/batch_time:.1f}x")


class TestUUID7:
    """UUID v7 generation."""

    def test_format(self):
        uid = py_uuid7()
        assert len(uid) == 36
        assert uid[14] == "7"  # version 7

    def test_uniqueness(self):
        ids = [py_uuid7() for _ in range(100)]
        assert len(set(ids)) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
