# Elara Runtime

**Layer 1.5 — Rust DAM Virtual Machine with PyO3 bindings.**

The Elara Runtime implements the [Elara Protocol](https://github.com/navigatorbuilds/elara-protocol)'s Directed Acyclic Mesh concepts in Rust — post-quantum cryptography, binary wire format, 5-tuple dimensional addressing, tiled storage, in-memory DAG index, and all 9 DAM operations. Callable from Python as an optional fast path via PyO3. Byte-identical wire format with [Layer 1](https://github.com/navigatorbuilds/elara-layer1).

## What it does

- **Post-quantum crypto** — Dilithium3 + SPHINCS+-SHA2-192f via `oqs` crate (same liboqs as Layer 1)
- **Wire format** — ELRA binary encode/decode, byte-identical to Python implementation
- **5-tuple addressing** — `(time, concurrency, zone, classification, ai)` → filesystem paths
- **Tiled storage** — Append-only records.bin/index.bin/edges.bin per dimensional tile
- **In-memory DAG** — HashMap-based graph with BFS traversal, tips, roots, ancestors
- **9 DAM operations** — INSERT, QUERY, WITNESS, MERGE, CLASSIFY, ANALYZE, HASH, SIGN, VERIFY
- **Parallel batch** — Sign/verify batches via rayon
- **Python bindings** — 13 PyO3-exported functions, drop-in fast path

## Cross-Language Compatibility

Rust signs → Python verifies. Python signs → Rust verifies. Both directions confirmed for Dilithium3 and SPHINCS+. Wire format produces byte-identical output from both implementations.

## Installation

**Requirements:** Rust 1.70+, Python 3.10+, maturin

```bash
git clone https://github.com/navigatorbuilds/elara-runtime.git
cd elara-runtime

# Build Rust library + Python wheel
python -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop --release

# Run tests
cargo test                              # 72 Rust tests
python -m pytest tests/test_compat.py   # 21 cross-language tests
```

## Architecture

```
src/
├── crypto/
│   ├── pqc.rs       # Dilithium3 + SPHINCS+ keygen/sign/verify
│   ├── hash.rs      # SHA3-256
│   └── batch.rs     # Parallel batch sign/verify (rayon)
├── wire.rs          # ELRA binary wire format encode/decode
├── record.rs        # ValidationRecord struct, signable_bytes()
├── identity.rs      # PQC identity management
├── addressing.rs    # 5-tuple dimensional addressing
├── storage/
│   ├── tiled.rs     # Dimensional tile storage (filesystem)
│   ├── mmap_index.rs # Memory-mapped tile indexes
│   └── sqlite.rs    # SQLite backend (reads Layer 1 databases)
├── dag.rs           # In-memory DAG index
├── operations.rs    # DamVm with 9 DAM operations
└── lib.rs           # PyO3 module (13 exported functions)

tests/
└── test_compat.py   # Cross-language sign/verify + wire format tests

benches/
├── bench_crypto.rs  # PQC + hashing benchmarks
├── bench_wire.rs    # Wire format benchmarks
└── bench_dag.rs     # DAG traversal benchmarks
```

**72 Rust tests + 21 Python cross-language tests, all passing.**

## Benchmarks

Measured on Xeon E5 / 64GB RDIMM (Dell 5810). Run with `cargo bench`.

### Cryptography

| Operation | Time |
|-----------|------|
| Dilithium3 keygen | 57 µs |
| Dilithium3 sign | 159 µs |
| Dilithium3 verify | 55 µs |
| SPHINCS+ keygen | 1.3 ms |
| SPHINCS+ sign | 28 ms |
| SPHINCS+ verify | 1.6 ms |
| SHA3-256 (4 KB) | 16 µs |
| Batch verify 100 sigs | 1.7 ms |

### Wire Format

| Operation | Time |
|-----------|------|
| to_bytes (serialize) | 292 ns |
| from_bytes (deserialize) | 780 ns |
| signable_bytes | 445 ns |

### DAG (10,000 nodes)

| Operation | Time |
|-----------|------|
| Insert 10K records | 16 ms |
| Find tips | 567 µs |
| Find ancestors (depth 50) | 2.6 ms |

## Python Usage

```python
from elara_runtime import (
    dilithium3_keygen, dilithium3_sign, dilithium3_verify,
    sphincs_keygen, sphincs_sign, sphincs_verify,
    sha3_256, sha3_256_hex,
    batch_verify, uuid7,
    record_to_bytes, record_from_bytes, signable_bytes,
    NATIVE_AVAILABLE
)

# Check if native Rust backend loaded
print(f"Native: {NATIVE_AVAILABLE}")

# Generate keys
pk, sk = dilithium3_keygen()

# Sign and verify
sig = dilithium3_sign(b"hello world", sk)
assert dilithium3_verify(b"hello world", sig, pk)

# Hash
digest = sha3_256_hex(b"content")
```

## Related Projects

| Project | Description |
|---------|-------------|
| [Elara Protocol](https://github.com/navigatorbuilds/elara-protocol) | Whitepapers and specifications |
| [Elara Layer 1](https://github.com/navigatorbuilds/elara-layer1) | Layer 1 — Python local validation (50 tests) |
| [Elara Core](https://github.com/navigatorbuilds/elara-core) | Layer 3 — AI cognitive architecture (MCP server) |

## License

MIT OR Apache-2.0

## Author

**Nenad Vasic** — Solo developer, Montenegro
- Email: nenadvasic@protonmail.com
- GitHub: [@navigatorbuilds](https://github.com/navigatorbuilds)
- Site: [navigatorbuilds.com](https://navigatorbuilds.com)

---

*The same math for the teenager in Kenya and the colonist on Mars.*
