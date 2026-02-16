//! SHA3-256 hashing.

use sha3::{Digest, Sha3_256};

/// Compute SHA3-256 hash of data, returns 32 bytes.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA3-256 hash and return hex string.
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        assert_eq!(hash.len(), 32);
        // Known SHA3-256 of empty string
        assert_eq!(
            sha3_256_hex(b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_256_deterministic() {
        let data = b"elara protocol";
        assert_eq!(sha3_256(data), sha3_256(data));
    }

    #[test]
    fn test_sha3_256_different_inputs() {
        assert_ne!(sha3_256(b"hello"), sha3_256(b"world"));
    }
}
