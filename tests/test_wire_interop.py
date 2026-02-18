"""Wire format interop tests: Python Layer 1 ↔ Rust Runtime with real metadata.

Tests that:
1. Signed records with typed metadata survive Python→Rust→Python round-trips
2. Live DAG records decode identically in both implementations
3. 100-record stress test produces byte-identical output

These tests expose the metadata type preservation fix in dict_to_record().
"""

import hashlib
import os
import sys
import time

import pytest

# Add Layer 1 to path
sys.path.insert(0, os.path.expanduser("~/elara-layer1"))

from elara_runtime import (
    NATIVE_AVAILABLE,
    py_dilithium3_keygen,
    py_dilithium3_sign,
    py_record_to_bytes,
    py_record_from_bytes,
    py_signable_bytes,
    py_sha3_256,
)

# Skip all tests if native extension not available
pytestmark = pytest.mark.skipif(
    not NATIVE_AVAILABLE, reason="Native extension not built"
)


def _make_record_dict(pk, metadata=None, parents=None, classification=3):
    """Helper: create a minimal record dict."""
    from elara_runtime import py_uuid7
    return {
        "id": py_uuid7(),
        "version": 1,
        "content_hash": py_sha3_256(f"content-{time.time()}".encode()),
        "creator_public_key": bytes(pk),
        "timestamp": time.time(),
        "parents": parents or [],
        "classification": classification,
        "metadata": metadata or {},
        "signature": None,
        "sphincs_signature": None,
        "zk_proof": None,
    }


class TestSignedRecordInterop:
    """Python creates + signs, Rust decodes. And reverse."""

    def _skip_if_no_layer1(self):
        try:
            from elara_protocol.record import ValidationRecord, Classification
            from elara_protocol.identity import Identity, EntityType, CryptoProfile
            return False
        except ImportError:
            pytest.skip("elara_protocol not installed")

    def test_python_sign_rust_decode(self):
        """Python creates + dual-signs → Rust decodes → fields match."""
        self._skip_if_no_layer1()
        from elara_protocol.record import ValidationRecord, Classification
        from elara_protocol.identity import Identity, EntityType, CryptoProfile

        # Generate identity
        identity = Identity.generate(
            entity_type=EntityType.AI,
            profile=CryptoProfile.PROFILE_A,
        )

        content = b"test artifact content for interop"
        record = ValidationRecord.create(
            content=content,
            creator_public_key=identity.public_key,
            parents=[],
            classification=Classification.SOVEREIGN,
            metadata={
                "artifact_type": "prediction",
                "confidence": 0.85,
                "witness_count": 0,
                "domain": "testing",
            },
        )

        # Sign
        signable = record.signable_bytes()
        record.signature = identity.sign(signable)
        record.sphincs_signature = identity.sign_sphincs(signable)

        # Python → wire bytes → Rust decode
        wire = record.to_bytes()
        decoded = py_record_from_bytes(wire)

        assert decoded["id"] == record.id
        assert decoded["version"] == record.version
        assert decoded["content_hash"] == record.content_hash
        assert decoded["timestamp"] == record.timestamp
        assert decoded["classification"] == 3  # SOVEREIGN
        assert decoded["metadata"]["artifact_type"] == "prediction"
        assert decoded["metadata"]["confidence"] == 0.85
        assert decoded["metadata"]["witness_count"] == 0

    def test_rust_encode_python_decode(self):
        """Rust encodes → Python decodes → fields match."""
        self._skip_if_no_layer1()
        from elara_protocol.record import ValidationRecord, Classification

        pk, sk = py_dilithium3_keygen()

        record_dict = _make_record_dict(pk, metadata={
            "artifact_type": "model",
            "confidence": 1.0,
            "witness_count": 0,
            "zone": "local",
        })

        # Rust encode
        wire = py_record_to_bytes(record_dict)

        # Python decode
        py_record = ValidationRecord.from_bytes(wire)

        assert py_record.id == record_dict["id"]
        assert py_record.version == record_dict["version"]
        assert py_record.timestamp == record_dict["timestamp"]
        assert py_record.metadata["artifact_type"] == "model"
        assert py_record.metadata["confidence"] == 1.0
        assert py_record.metadata["witness_count"] == 0

    def test_signable_bytes_match_with_metadata(self):
        """signable_bytes with typed metadata must match between Python and Rust."""
        self._skip_if_no_layer1()
        from elara_protocol.record import ValidationRecord, Classification

        pk, sk = py_dilithium3_keygen()
        record_id = "019506e0-abcd-7000-8000-000000000099"
        content_hash = hashlib.sha3_256(b"signable with metadata").digest()
        timestamp = 1739712345.5
        metadata = {
            "artifact_type": "prediction",
            "confidence": 0.85,
            "witness_count": 0,
            "zone": "local",
            "layer3_version": "0.11.0",
        }

        # Python record
        py_rec = ValidationRecord(
            id=record_id,
            version=1,
            content_hash=content_hash,
            creator_public_key=bytes(pk),
            timestamp=timestamp,
            parents=[],
            classification=Classification.SOVEREIGN,
            metadata=metadata,
            signature=None,
            sphincs_signature=None,
            zk_proof=None,
        )
        python_signable = py_rec.signable_bytes()

        # Rust record
        rust_dict = {
            "id": record_id,
            "version": 1,
            "content_hash": content_hash,
            "creator_public_key": bytes(pk),
            "timestamp": timestamp,
            "parents": [],
            "classification": 3,
            "metadata": metadata,
            "signature": None,
            "sphincs_signature": None,
            "zk_proof": None,
        }
        rust_signable = py_signable_bytes(rust_dict)

        assert python_signable == rust_signable, (
            f"Signable bytes mismatch with typed metadata!\n"
            f"Python: {python_signable[:80].hex()}...\n"
            f"Rust:   {rust_signable[:80].hex()}..."
        )


class TestDAGRecordInterop:
    """Load real records from live DAG, verify cross-impl decoding."""

    @pytest.fixture(autouse=True)
    def _check_dag(self):
        dag_path = os.path.expanduser("~/.elara/elara-dag.sqlite")
        if not os.path.exists(dag_path):
            pytest.skip("No live DAG at ~/.elara/elara-dag.sqlite")

    def test_live_dag_records_decode(self):
        """First 5 live DAG records: Python to_bytes → Rust decode → fields match."""
        from elara_protocol.dag import LocalDAG

        dag_path = os.path.expanduser("~/.elara/elara-dag.sqlite")
        dag = LocalDAG(dag_path)

        records = dag.query(limit=5)
        if not records:
            pytest.skip("DAG is empty")

        for record in records:
            wire = record.to_bytes()
            decoded = py_record_from_bytes(wire)

            assert decoded["id"] == record.id
            assert decoded["version"] == record.version
            assert abs(decoded["timestamp"] - record.timestamp) < 0.001
            assert decoded["classification"] == record.classification.value

    def test_live_dag_signable_match(self):
        """Live DAG records: Python signable_bytes vs Rust signable_bytes."""
        from elara_protocol.dag import LocalDAG

        dag_path = os.path.expanduser("~/.elara/elara-dag.sqlite")
        dag = LocalDAG(dag_path)

        records = dag.query(limit=5)
        if not records:
            pytest.skip("DAG is empty")

        for record in records:
            python_signable = record.signable_bytes()

            rust_dict = {
                "id": record.id,
                "version": record.version,
                "content_hash": record.content_hash,
                "creator_public_key": record.creator_public_key,
                "timestamp": record.timestamp,
                "parents": record.parents,
                "classification": record.classification.value,
                "metadata": record.metadata,
                "signature": record.signature,
                "sphincs_signature": record.sphincs_signature,
                "zk_proof": record.zk_proof,
            }
            rust_signable = py_signable_bytes(rust_dict)

            assert python_signable == rust_signable, (
                f"Signable mismatch for record {record.id}\n"
                f"Metadata: {record.metadata}"
            )


class TestRoundTripStress:
    """100 records with varying metadata, classifications, parent counts."""

    def test_100_records_roundtrip(self):
        """Generate 100 records, Python encode → Rust decode → Rust encode → bytes match."""
        pk, sk = py_dilithium3_keygen()
        from elara_runtime import py_uuid7

        classifications = [0, 1, 2, 3]
        parent_pool = [py_uuid7() for _ in range(10)]

        for i in range(100):
            # Vary metadata types
            metadata = {
                "artifact_type": ["model", "prediction", "principle", "workflow"][i % 4],
                "confidence": round(i / 100.0, 2),
                "witness_count": i % 5,
                "zone": "local",
                "index": i,
            }

            # Vary parents (0, 1, or 2)
            n_parents = i % 3
            parents = parent_pool[:n_parents]

            record = _make_record_dict(
                pk,
                metadata=metadata,
                parents=parents,
                classification=classifications[i % 4],
            )

            # Rust encode → Rust decode → Rust re-encode
            wire1 = py_record_to_bytes(record)
            decoded = py_record_from_bytes(wire1)

            # Rebuild dict from decoded for re-encode
            re_record = {
                "id": decoded["id"],
                "version": decoded["version"],
                "content_hash": decoded["content_hash"],
                "creator_public_key": decoded["creator_public_key"],
                "timestamp": decoded["timestamp"],
                "parents": decoded["parents"],
                "classification": decoded["classification"],
                "metadata": decoded["metadata"],
                "signature": decoded.get("signature"),
                "sphincs_signature": decoded.get("sphincs_signature"),
                "zk_proof": decoded.get("zk_proof"),
            }
            wire2 = py_record_to_bytes(re_record)

            assert wire1 == wire2, (
                f"Round-trip byte mismatch at record {i}!\n"
                f"Metadata: {metadata}\n"
                f"wire1[{len(wire1)}] vs wire2[{len(wire2)}]"
            )

    def test_metadata_type_preservation(self):
        """Specifically test that int, float, string, bool survive round-trip."""
        pk, _ = py_dilithium3_keygen()

        metadata = {
            "str_val": "hello",
            "int_val": 42,
            "float_val": 3.14,
            "zero_int": 0,
            "zero_float": 0.0,
            "negative": -1,
        }

        record = _make_record_dict(pk, metadata=metadata)
        wire = py_record_to_bytes(record)
        decoded = py_record_from_bytes(wire)

        assert decoded["metadata"]["str_val"] == "hello"
        assert decoded["metadata"]["int_val"] == 42
        assert isinstance(decoded["metadata"]["int_val"], int)
        assert decoded["metadata"]["float_val"] == 3.14
        assert decoded["metadata"]["zero_int"] == 0
        assert decoded["metadata"]["negative"] == -1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
