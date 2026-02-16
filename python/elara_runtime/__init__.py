"""Elara Runtime — Rust-powered fast lane for the Elara Protocol.

Provides accelerated crypto, wire format, and DAG operations.
Falls back to pure-Python Layer 1 if the native extension is unavailable.
"""

__version__ = "0.1.0"

try:
    from elara_runtime._native import (
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

    NATIVE_AVAILABLE = True

except ImportError:
    NATIVE_AVAILABLE = False

    def _not_available(*args, **kwargs):
        raise RuntimeError(
            "elara_runtime native extension not available. "
            "Install with: cd elara-runtime && maturin develop --release"
        )

    py_dilithium3_keygen = _not_available
    py_dilithium3_sign = _not_available
    py_dilithium3_verify = _not_available
    py_sphincs_keygen = _not_available
    py_sphincs_sign = _not_available
    py_sphincs_verify = _not_available
    py_sha3_256 = _not_available
    py_sha3_256_hex = _not_available
    py_batch_verify = _not_available
    py_uuid7 = _not_available
    py_record_to_bytes = _not_available
    py_record_from_bytes = _not_available
    py_signable_bytes = _not_available


# Public API
__all__ = [
    "NATIVE_AVAILABLE",
    "py_dilithium3_keygen",
    "py_dilithium3_sign",
    "py_dilithium3_verify",
    "py_sphincs_keygen",
    "py_sphincs_sign",
    "py_sphincs_verify",
    "py_sha3_256",
    "py_sha3_256_hex",
    "py_batch_verify",
    "py_uuid7",
    "py_record_to_bytes",
    "py_record_from_bytes",
    "py_signable_bytes",
]
