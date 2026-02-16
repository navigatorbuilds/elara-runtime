//! ValidationRecord — the atomic unit of the Elara Protocol.
//!
//! Byte-identical serialization with the Python Layer 1 implementation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::uuid7::uuid7;
use crate::wire::*;

/// Classification levels from Protocol Whitepaper, Section 5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Classification {
    Public = 0,
    Private = 1,
    Restricted = 2,
    Sovereign = 3,
}

impl Classification {
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Public),
            1 => Ok(Self::Private),
            2 => Ok(Self::Restricted),
            3 => Ok(Self::Sovereign),
            _ => Err(ElaraError::Wire(format!(
                "invalid classification: {val}"
            ))),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Private => "PRIVATE",
            Self::Restricted => "RESTRICTED",
            Self::Sovereign => "SOVEREIGN",
        }
    }
}

/// A single validation record on the DAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub id: String,
    pub version: u16,
    pub content_hash: Vec<u8>,
    pub creator_public_key: Vec<u8>,
    pub timestamp: f64,
    pub parents: Vec<String>,
    pub classification: Classification,
    /// BTreeMap ensures sorted keys, matching Python's `sort_keys=True`.
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub signature: Option<Vec<u8>>,
    pub sphincs_signature: Option<Vec<u8>>,
    pub zk_proof: Option<Vec<u8>>,
}

impl ValidationRecord {
    /// Create an unsigned record from content bytes.
    pub fn create(
        content: &[u8],
        creator_public_key: Vec<u8>,
        parents: Vec<String>,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Self {
        let content_hash = sha3_256(content).to_vec();
        Self {
            id: uuid7(),
            version: WIRE_VERSION,
            content_hash,
            creator_public_key,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            parents,
            classification,
            metadata: metadata.unwrap_or_default(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
        }
    }

    /// Create an unsigned record from a pre-computed hash.
    pub fn create_from_hash(
        content_hash: Vec<u8>,
        creator_public_key: Vec<u8>,
        parents: Vec<String>,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Result<Self> {
        if content_hash.len() != 32 {
            return Err(ElaraError::Wire(format!(
                "content hash must be 32 bytes, got {}",
                content_hash.len()
            )));
        }
        Ok(Self {
            id: uuid7(),
            version: WIRE_VERSION,
            content_hash,
            creator_public_key,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            parents,
            classification,
            metadata: metadata.unwrap_or_default(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
        })
    }

    /// Canonical byte representation for signing (everything except signatures).
    /// Must produce identical output to Python's `signable_bytes()`.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // id as UTF-8
        buf.extend_from_slice(self.id.as_bytes());

        // version as u16 BE
        buf.extend_from_slice(&self.version.to_be_bytes());

        // content_hash (32 bytes)
        buf.extend_from_slice(&self.content_hash);

        // creator_public_key (raw bytes)
        buf.extend_from_slice(&self.creator_public_key);

        // timestamp as f64 BE (matches Python's struct.pack("!d", ...))
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // num_parents as u16 BE
        buf.extend_from_slice(&(self.parents.len() as u16).to_be_bytes());

        // Sorted parent IDs (Python sorts them for determinism)
        let mut sorted_parents = self.parents.clone();
        sorted_parents.sort();
        for pid in &sorted_parents {
            buf.extend_from_slice(pid.as_bytes());
        }

        // classification as u8
        buf.push(self.classification as u8);

        // Metadata: sorted compact JSON matching Python's
        // json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        // BTreeMap + serde_json::to_string produces this exact format.
        let meta_json = serde_json::to_string(&self.metadata).unwrap();
        let meta_bytes = meta_json.as_bytes();
        buf.extend_from_slice(&(meta_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(meta_bytes);

        // ZK proof
        match &self.zk_proof {
            Some(zk) => {
                buf.extend_from_slice(&(zk.len() as u32).to_be_bytes());
                buf.extend_from_slice(zk);
            }
            None => {
                buf.extend_from_slice(&0u32.to_be_bytes());
            }
        }

        buf
    }

    /// Serialize to binary wire format (byte-identical to Python's to_bytes()).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4096);

        // Header: ELRA + version(2) + type(1) + reserved(1)
        encode_header(&mut buf);

        // Record ID (UUID v7, 36 chars UTF-8)
        encode_u8_prefixed(&mut buf, self.id.as_bytes());

        // Content hash (fixed 32 bytes, no length prefix)
        buf.extend_from_slice(&self.content_hash);

        // Creator public key (u16 length prefix)
        encode_u16_prefixed(&mut buf, &self.creator_public_key);

        // Timestamp (f64 BE)
        encode_timestamp(&mut buf, self.timestamp);

        // Parents
        buf.extend_from_slice(&(self.parents.len() as u16).to_be_bytes());
        for pid in &self.parents {
            encode_u8_prefixed(&mut buf, pid.as_bytes());
        }

        // Classification
        buf.push(self.classification as u8);

        // Metadata (sorted compact JSON, u32 length prefix)
        let meta_json = serde_json::to_string(&self.metadata).unwrap();
        encode_u32_prefixed(&mut buf, meta_json.as_bytes());

        // ZK proof
        encode_optional_u32(&mut buf, self.zk_proof.as_deref());

        // Signature
        encode_optional_u16(&mut buf, self.signature.as_deref());

        // SPHINCS+ signature
        encode_optional_u16(&mut buf, self.sphincs_signature.as_deref());

        buf
    }

    /// Deserialize from binary wire format (byte-compatible with Python's from_bytes()).
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut reader = WireReader::new(data);

        // Header
        let (version, _rec_type) = reader.read_header()?;

        // Record ID
        let id_bytes = reader.read_u8_prefixed()?;
        let id = std::str::from_utf8(id_bytes)
            .map_err(|e| ElaraError::Wire(format!("invalid UTF-8 in record ID: {e}")))?
            .to_string();

        // Content hash (32 bytes)
        let content_hash = reader.read_bytes(32)?.to_vec();

        // Creator public key
        let creator_public_key = reader.read_u16_prefixed()?.to_vec();

        // Timestamp
        let timestamp = reader.read_f64()?;

        // Parents
        let num_parents = reader.read_u16()? as usize;
        let mut parents = Vec::with_capacity(num_parents);
        for _ in 0..num_parents {
            let pid_bytes = reader.read_u8_prefixed()?;
            let pid = std::str::from_utf8(pid_bytes)
                .map_err(|e| ElaraError::Wire(format!("invalid UTF-8 in parent ID: {e}")))?
                .to_string();
            parents.push(pid);
        }

        // Classification
        let class_val = reader.read_u8()?;
        let classification = Classification::from_u8(class_val)?;

        // Metadata
        let meta_bytes = reader.read_u32_prefixed()?;
        let metadata: BTreeMap<String, serde_json::Value> = if meta_bytes.is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_slice(meta_bytes)?
        };

        // ZK proof
        let zk_proof = reader.read_optional_u32()?;

        // Signature
        let signature = reader.read_optional_u16()?;

        // SPHINCS+ signature (may be absent at end of data)
        let sphincs_signature = if reader.remaining() > 0 {
            reader.read_optional_u16()?
        } else {
            None
        };

        Ok(Self {
            id,
            version,
            content_hash,
            creator_public_key,
            timestamp,
            parents,
            classification,
            metadata,
            signature,
            sphincs_signature,
            zk_proof,
        })
    }

    /// SHA3-256 hash of the complete signed record wire bytes.
    pub fn record_hash(&self) -> [u8; 32] {
        sha3_256(&self.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk() -> Vec<u8> {
        vec![0xAA; 1952]
    }

    #[test]
    fn test_create_record() {
        let rec = ValidationRecord::create(
            b"test content",
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        );
        assert_eq!(rec.version, WIRE_VERSION);
        assert_eq!(rec.content_hash.len(), 32);
        assert_eq!(rec.classification, Classification::Public);
        assert!(rec.signature.is_none());
    }

    #[test]
    fn test_create_from_hash() {
        let hash = sha3_256(b"test");
        let rec = ValidationRecord::create_from_hash(
            hash.to_vec(),
            dummy_pk(),
            vec![],
            Classification::Private,
            None,
        )
        .unwrap();
        assert_eq!(rec.content_hash, hash);
    }

    #[test]
    fn test_create_from_hash_wrong_length() {
        assert!(ValidationRecord::create_from_hash(
            vec![0; 16],
            dummy_pk(),
            vec![],
            Classification::Public,
            None,
        )
        .is_err());
    }

    #[test]
    fn test_wire_roundtrip() {
        let mut metadata = BTreeMap::new();
        metadata.insert("key".into(), serde_json::Value::String("value".into()));

        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.123456,
            parents: vec!["019506e0-1234-7000-8000-000000000000".to_string()],
            classification: Classification::Public,
            metadata,
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
        };

        let wire = rec.to_bytes();
        assert_eq!(&wire[0..4], b"ELRA");

        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.content_hash, rec.content_hash);
        assert_eq!(decoded.creator_public_key, rec.creator_public_key);
        assert_eq!(decoded.timestamp, rec.timestamp);
        assert_eq!(decoded.parents, rec.parents);
        assert_eq!(decoded.classification, rec.classification);
        assert_eq!(decoded.metadata, rec.metadata);
        assert_eq!(decoded.signature, rec.signature);
        assert_eq!(decoded.sphincs_signature, rec.sphincs_signature);
    }

    #[test]
    fn test_signable_bytes_deterministic() {
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![
                "019506e0-1234-7000-8000-000000000003".to_string(),
                "019506e0-1234-7000-8000-000000000002".to_string(),
            ],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
        };
        // signable_bytes() sorts parents, so calling twice should be identical
        assert_eq!(rec.signable_bytes(), rec.signable_bytes());
    }

    #[test]
    fn test_signable_bytes_parent_order_independent() {
        let base = || ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
        };

        let mut rec1 = base();
        rec1.parents = vec!["aaa".to_string(), "bbb".to_string()];

        let mut rec2 = base();
        rec2.parents = vec!["bbb".to_string(), "aaa".to_string()];

        assert_eq!(rec1.signable_bytes(), rec2.signable_bytes());
    }

    #[test]
    fn test_record_hash_changes() {
        let rec1 = ValidationRecord::create(b"content1", dummy_pk(), vec![], Classification::Public, None);
        let rec2 = ValidationRecord::create(b"content2", dummy_pk(), vec![], Classification::Public, None);
        assert_ne!(rec1.record_hash(), rec2.record_hash());
    }

    #[test]
    fn test_classification_roundtrip() {
        for val in 0..4u8 {
            let c = Classification::from_u8(val).unwrap();
            assert_eq!(c as u8, val);
        }
        assert!(Classification::from_u8(4).is_err());
    }

    #[test]
    fn test_wire_with_sphincs_sig() {
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: WIRE_VERSION,
            content_hash: sha3_256(b"content").to_vec(),
            creator_public_key: dummy_pk(),
            timestamp: 1739712345.0,
            parents: vec![],
            classification: Classification::Public,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xCC; 3293]),
            sphincs_signature: Some(vec![0xDD; 35664]),
            zk_proof: None,
        };

        let wire = rec.to_bytes();
        let decoded = ValidationRecord::from_bytes(&wire).unwrap();
        assert_eq!(decoded.signature.as_ref().unwrap().len(), 3293);
        assert_eq!(decoded.sphincs_signature.as_ref().unwrap().len(), 35664);
    }
}
