//! Post-quantum cryptography: Dilithium3 + SPHINCS+-SHA2-192f via liboqs.
//!
//! Uses the `oqs` crate (vendored liboqs) for byte-level compatibility
//! with the Python Layer 1 implementation which uses `liboqs-python`.

use oqs::sig::{Algorithm, Sig};

use crate::errors::{ElaraError, Result};

// Algorithm constants matching Python's liboqs names:
//   Python: oqs.Signature("Dilithium3")
//   Rust:   Algorithm::Dilithium3
const DILITHIUM3: Algorithm = Algorithm::Dilithium3;

//   Python: oqs.Signature("SPHINCS+-SHA2-192f-simple")
//   Rust:   Algorithm::SphincsSha2192fSimple
const SPHINCS_SHA2_192F: Algorithm = Algorithm::SphincsSha2192fSimple;

/// A Dilithium3 keypair (public key + secret key).
pub struct DilithiumKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// A SPHINCS+ keypair.
pub struct SphincsKeypair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// Generate a Dilithium3 keypair.
pub fn dilithium3_keygen() -> Result<DilithiumKeypair> {
    let sig = Sig::new(DILITHIUM3).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let (pk, sk) = sig
        .keypair()
        .map_err(|e| ElaraError::Crypto(format!("keygen: {e}")))?;
    Ok(DilithiumKeypair {
        public_key: pk.into_vec(),
        secret_key: sk.into_vec(),
    })
}

/// Sign a message with Dilithium3.
pub fn dilithium3_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sig = Sig::new(DILITHIUM3).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let sk_ref = sig
        .secret_key_from_bytes(secret_key)
        .ok_or_else(|| ElaraError::Crypto("invalid secret key length".into()))?;
    let signature = sig
        .sign(message, sk_ref)
        .map_err(|e| ElaraError::Crypto(format!("sign: {e}")))?;
    Ok(signature.into_vec())
}

/// Verify a Dilithium3 signature.
pub fn dilithium3_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let sig = Sig::new(DILITHIUM3).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let pk_ref = sig
        .public_key_from_bytes(public_key)
        .ok_or_else(|| ElaraError::Crypto("invalid public key length".into()))?;
    let sig_ref = sig
        .signature_from_bytes(signature)
        .ok_or_else(|| ElaraError::Crypto("invalid signature length".into()))?;
    match sig.verify(message, sig_ref, pk_ref) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a SPHINCS+-SHA2-192f-simple keypair.
pub fn sphincs_keygen() -> Result<SphincsKeypair> {
    let sig =
        Sig::new(SPHINCS_SHA2_192F).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let (pk, sk) = sig
        .keypair()
        .map_err(|e| ElaraError::Crypto(format!("keygen: {e}")))?;
    Ok(SphincsKeypair {
        public_key: pk.into_vec(),
        secret_key: sk.into_vec(),
    })
}

/// Sign a message with SPHINCS+-SHA2-192f-simple.
pub fn sphincs_sign(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    let sig =
        Sig::new(SPHINCS_SHA2_192F).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let sk_ref = sig
        .secret_key_from_bytes(secret_key)
        .ok_or_else(|| ElaraError::Crypto("invalid SPHINCS+ secret key length".into()))?;
    let signature = sig
        .sign(message, sk_ref)
        .map_err(|e| ElaraError::Crypto(format!("sign: {e}")))?;
    Ok(signature.into_vec())
}

/// Verify a SPHINCS+-SHA2-192f-simple signature.
pub fn sphincs_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    let sig =
        Sig::new(SPHINCS_SHA2_192F).map_err(|e| ElaraError::Crypto(format!("init: {e}")))?;
    let pk_ref = sig
        .public_key_from_bytes(public_key)
        .ok_or_else(|| ElaraError::Crypto("invalid SPHINCS+ public key length".into()))?;
    let sig_ref = sig
        .signature_from_bytes(signature)
        .ok_or_else(|| ElaraError::Crypto("invalid SPHINCS+ signature length".into()))?;
    match sig.verify(message, sig_ref, pk_ref) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dilithium3_keygen() {
        let kp = dilithium3_keygen().unwrap();
        assert_eq!(kp.public_key.len(), 1952); // Dilithium3 pk size
        assert!(!kp.secret_key.is_empty());
    }

    #[test]
    fn test_dilithium3_sign_verify() {
        let kp = dilithium3_keygen().unwrap();
        let msg = b"elara protocol test message";
        let sig = dilithium3_sign(msg, &kp.secret_key).unwrap();
        assert_eq!(sig.len(), 3293); // Dilithium3 sig size
        assert!(dilithium3_verify(msg, &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_dilithium3_wrong_message() {
        let kp = dilithium3_keygen().unwrap();
        let sig = dilithium3_sign(b"correct", &kp.secret_key).unwrap();
        assert!(!dilithium3_verify(b"wrong", &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_dilithium3_wrong_key() {
        let kp1 = dilithium3_keygen().unwrap();
        let kp2 = dilithium3_keygen().unwrap();
        let msg = b"test";
        let sig = dilithium3_sign(msg, &kp1.secret_key).unwrap();
        assert!(!dilithium3_verify(msg, &sig, &kp2.public_key).unwrap());
    }

    #[test]
    fn test_sphincs_keygen() {
        let kp = sphincs_keygen().unwrap();
        assert_eq!(kp.public_key.len(), 48); // SPHINCS+-SHA2-192f pk size
        assert!(!kp.secret_key.is_empty());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let kp = sphincs_keygen().unwrap();
        let msg = b"sphincs test message";
        let sig = sphincs_sign(msg, &kp.secret_key).unwrap();
        assert_eq!(sig.len(), 35664); // SPHINCS+-SHA2-192f sig size
        assert!(sphincs_verify(msg, &sig, &kp.public_key).unwrap());
    }

    #[test]
    fn test_sphincs_wrong_message() {
        let kp = sphincs_keygen().unwrap();
        let sig = sphincs_sign(b"correct", &kp.secret_key).unwrap();
        assert!(!sphincs_verify(b"wrong", &sig, &kp.public_key).unwrap());
    }
}
