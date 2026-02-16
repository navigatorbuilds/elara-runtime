//! Cryptographic identity management — Dilithium3 + SPHINCS+ keypairs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256_hex;
use crate::crypto::pqc::{
    dilithium3_keygen, dilithium3_sign, dilithium3_verify, sphincs_keygen, sphincs_sign,
    sphincs_verify,
};
use crate::errors::{ElaraError, Result};

/// Entity types from Protocol Whitepaper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    #[serde(rename = "HUMAN")]
    Human,
    #[serde(rename = "AI")]
    Ai,
    #[serde(rename = "DEVICE")]
    Device,
    #[serde(rename = "ORGANIZATION")]
    Organization,
    #[serde(rename = "COMPOSITE")]
    Composite,
}

/// Cryptographic profiles from Protocol Whitepaper, Section 4.6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CryptoProfile {
    /// Full PQC: Dilithium3 + SPHINCS+
    #[serde(rename = "A")]
    ProfileA,
    /// Compact PQC: Dilithium3 only, no dual sig
    #[serde(rename = "B")]
    ProfileB,
    /// Gateway-delegated (not implemented in Layer 1)
    #[serde(rename = "C")]
    ProfileC,
}

/// An Elara Protocol identity — a self-sovereign cryptographic keypair.
#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key: Vec<u8>,
    pub identity_hash: String,
    pub entity_type: EntityType,
    pub created: f64,
    pub algorithm: String,
    pub profile: CryptoProfile,
    secret_key: Option<Vec<u8>>,
    sphincs_public_key: Option<Vec<u8>>,
    sphincs_secret_key: Option<Vec<u8>>,
}

impl Identity {
    /// Generate a new identity with fresh keypairs.
    /// Profile A generates both Dilithium3 and SPHINCS+ keypairs.
    pub fn generate(entity_type: EntityType, profile: CryptoProfile) -> Result<Self> {
        let dil_kp = dilithium3_keygen()?;

        let (sphincs_pk, sphincs_sk) = if profile == CryptoProfile::ProfileA {
            let sp_kp = sphincs_keygen()?;
            (Some(sp_kp.public_key), Some(sp_kp.secret_key))
        } else {
            (None, None)
        };

        let identity_hash = sha3_256_hex(&dil_kp.public_key);
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        Ok(Self {
            public_key: dil_kp.public_key,
            identity_hash,
            entity_type,
            created,
            algorithm: "dilithium3".to_string(),
            profile,
            secret_key: Some(dil_kp.secret_key),
            sphincs_public_key: sphincs_pk,
            sphincs_secret_key: sphincs_sk,
        })
    }

    /// Sign a message with Dilithium3.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = self
            .secret_key
            .as_ref()
            .ok_or_else(|| ElaraError::Crypto("no secret key (public identity)".into()))?;
        dilithium3_sign(message, sk)
    }

    /// Sign a message with SPHINCS+ (Profile A only).
    pub fn sign_sphincs(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sk = self
            .sphincs_secret_key
            .as_ref()
            .ok_or_else(|| ElaraError::Crypto("no SPHINCS+ key (Profile A only)".into()))?;
        sphincs_sign(message, sk)
    }

    /// Verify a Dilithium3 signature against a public key.
    pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        dilithium3_verify(message, signature, public_key)
    }

    /// Verify a SPHINCS+ signature.
    pub fn verify_sphincs(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        sphincs_verify(message, signature, public_key)
    }

    pub fn has_secret_key(&self) -> bool {
        self.secret_key.is_some()
    }

    pub fn sphincs_public_key(&self) -> Option<&[u8]> {
        self.sphincs_public_key.as_deref()
    }

    /// Return a copy without secret keys (safe to share).
    pub fn public_identity(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            identity_hash: self.identity_hash.clone(),
            entity_type: self.entity_type.clone(),
            created: self.created,
            algorithm: self.algorithm.clone(),
            profile: self.profile.clone(),
            secret_key: None,
            sphincs_public_key: self.sphincs_public_key.clone(),
            sphincs_secret_key: None,
        }
    }

    /// Save identity to JSON (compatible with Python's Identity.save()).
    pub fn to_json(&self) -> BTreeMap<String, serde_json::Value> {
        let mut data = BTreeMap::new();
        data.insert(
            "public_key".into(),
            serde_json::Value::String(hex::encode(&self.public_key)),
        );
        data.insert(
            "identity_hash".into(),
            serde_json::Value::String(self.identity_hash.clone()),
        );
        data.insert(
            "entity_type".into(),
            serde_json::json!(match &self.entity_type {
                EntityType::Human => "HUMAN",
                EntityType::Ai => "AI",
                EntityType::Device => "DEVICE",
                EntityType::Organization => "ORGANIZATION",
                EntityType::Composite => "COMPOSITE",
            }),
        );
        data.insert("created".into(), serde_json::json!(self.created));
        data.insert(
            "algorithm".into(),
            serde_json::Value::String(self.algorithm.clone()),
        );
        data.insert(
            "profile".into(),
            serde_json::json!(match &self.profile {
                CryptoProfile::ProfileA => "A",
                CryptoProfile::ProfileB => "B",
                CryptoProfile::ProfileC => "C",
            }),
        );
        if let Some(sk) = &self.secret_key {
            data.insert(
                "secret_key".into(),
                serde_json::Value::String(hex::encode(sk)),
            );
        }
        if let Some(spk) = &self.sphincs_public_key {
            data.insert(
                "sphincs_public_key".into(),
                serde_json::Value::String(hex::encode(spk)),
            );
        }
        if let Some(ssk) = &self.sphincs_secret_key {
            data.insert(
                "sphincs_secret_key".into(),
                serde_json::Value::String(hex::encode(ssk)),
            );
        }
        data
    }

    /// Load identity from JSON (compatible with Python's Identity.load()).
    pub fn from_json(data: &BTreeMap<String, serde_json::Value>) -> Result<Self> {
        let get_str = |key: &str| -> Result<String> {
            data.get(key)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| ElaraError::Crypto(format!("missing field: {key}")))
        };

        let public_key =
            hex::decode(get_str("public_key")?).map_err(|e| ElaraError::Crypto(e.to_string()))?;
        let identity_hash = get_str("identity_hash")?;
        let entity_type = match get_str("entity_type")?.as_str() {
            "HUMAN" => EntityType::Human,
            "AI" => EntityType::Ai,
            "DEVICE" => EntityType::Device,
            "ORGANIZATION" => EntityType::Organization,
            "COMPOSITE" => EntityType::Composite,
            other => {
                return Err(ElaraError::Crypto(format!(
                    "unknown entity type: {other}"
                )))
            }
        };
        let created = data
            .get("created")
            .and_then(|v| v.as_f64())
            .ok_or_else(|| ElaraError::Crypto("missing created".into()))?;
        let algorithm = get_str("algorithm")?;
        let profile = match get_str("profile")?.as_str() {
            "A" => CryptoProfile::ProfileA,
            "B" => CryptoProfile::ProfileB,
            "C" => CryptoProfile::ProfileC,
            other => {
                return Err(ElaraError::Crypto(format!(
                    "unknown profile: {other}"
                )))
            }
        };

        let secret_key = data
            .get("secret_key")
            .and_then(|v| v.as_str())
            .map(|s| hex::decode(s))
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        let sphincs_public_key = data
            .get("sphincs_public_key")
            .and_then(|v| v.as_str())
            .map(|s| hex::decode(s))
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        let sphincs_secret_key = data
            .get("sphincs_secret_key")
            .and_then(|v| v.as_str())
            .map(|s| hex::decode(s))
            .transpose()
            .map_err(|e| ElaraError::Crypto(e.to_string()))?;

        Ok(Self {
            public_key,
            identity_hash,
            entity_type,
            created,
            algorithm,
            profile,
            secret_key,
            sphincs_public_key,
            sphincs_secret_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_profile_a() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        assert_eq!(id.public_key.len(), 1952);
        assert!(id.has_secret_key());
        assert!(id.sphincs_public_key().is_some());
        assert_eq!(id.sphincs_public_key().unwrap().len(), 48);
    }

    #[test]
    fn test_generate_profile_b() {
        let id = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB).unwrap();
        assert_eq!(id.public_key.len(), 1952);
        assert!(id.has_secret_key());
        assert!(id.sphincs_public_key().is_none());
    }

    #[test]
    fn test_sign_verify() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let msg = b"test message";
        let sig = id.sign(msg).unwrap();
        assert!(Identity::verify(msg, &sig, &id.public_key).unwrap());
    }

    #[test]
    fn test_sphincs_sign_verify() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let msg = b"test message";
        let sig = id.sign_sphincs(msg).unwrap();
        let pk = id.sphincs_public_key().unwrap();
        assert!(Identity::verify_sphincs(msg, &sig, pk).unwrap());
    }

    #[test]
    fn test_public_identity_cannot_sign() {
        let id = Identity::generate(EntityType::Human, CryptoProfile::ProfileA).unwrap();
        let pub_id = id.public_identity();
        assert!(!pub_id.has_secret_key());
        assert!(pub_id.sign(b"test").is_err());
    }

    #[test]
    fn test_json_roundtrip() {
        let id = Identity::generate(EntityType::Device, CryptoProfile::ProfileA).unwrap();
        let json = id.to_json();
        let restored = Identity::from_json(&json).unwrap();
        assert_eq!(restored.public_key, id.public_key);
        assert_eq!(restored.identity_hash, id.identity_hash);
        assert!(restored.has_secret_key());
    }

    #[test]
    fn test_identity_uniqueness() {
        let id1 = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        let id2 = Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.identity_hash, id2.identity_hash);
    }
}
