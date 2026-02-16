//! 9 DAM operations — the instruction set of the DVM.

use std::collections::BTreeMap;

use crate::crypto::hash::sha3_256;
use crate::crypto::pqc::dilithium3_verify;
use crate::dag::DagIndex;
use crate::errors::{ElaraError, Result};
use crate::identity::Identity;
use crate::record::{Classification, ValidationRecord};
use crate::storage::Storage;

/// DAM operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamOp {
    Insert,
    Query,
    Witness,
    Merge,
    Classify,
    Analyze,
    Hash,
    Sign,
    Verify,
}

/// Configuration for the DVM.
#[derive(Debug, Clone)]
pub struct DvmConfig {
    pub verify_on_insert: bool,
    pub max_ancestors_depth: usize,
}

impl Default for DvmConfig {
    fn default() -> Self {
        Self {
            verify_on_insert: true,
            max_ancestors_depth: 100,
        }
    }
}

/// The DAM Virtual Machine — executes operations on a storage backend with an in-memory DAG index.
pub struct DamVm<S: Storage> {
    pub storage: S,
    pub dag: DagIndex,
    pub config: DvmConfig,
}

impl<S: Storage> DamVm<S> {
    pub fn new(storage: S, config: DvmConfig) -> Self {
        Self {
            storage,
            dag: DagIndex::new(),
            config,
        }
    }

    /// INSERT — Add a signed record to the DAG.
    pub fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
        // Verify signature if configured
        if self.config.verify_on_insert {
            if let Some(sig) = &record.signature {
                let signable = record.signable_bytes();
                if !dilithium3_verify(&signable, sig, &record.creator_public_key)? {
                    return Err(ElaraError::InvalidSignature);
                }
            } else {
                return Err(ElaraError::InvalidSignature);
            }
        }

        // Insert into DAG index
        self.dag.insert(
            record.id.clone(),
            record.parents.clone(),
            record.timestamp,
        )?;

        // Insert into storage
        self.storage.insert(record)
    }

    /// QUERY — Retrieve records matching criteria.
    pub fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        self.storage
            .query(classification, creator_key, since, until, limit)
    }

    /// WITNESS — Create a new record witnessing (referencing) current tip records.
    pub fn witness(
        &mut self,
        content: &[u8],
        identity: &Identity,
        classification: Classification,
        metadata: Option<BTreeMap<String, serde_json::Value>>,
    ) -> Result<String> {
        let tips = self.dag.tips();
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            tips,
            classification,
            metadata,
        );

        // Sign
        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable)?);

        self.insert(&record)
    }

    /// MERGE — Create a merge record referencing multiple parents.
    pub fn merge(
        &mut self,
        parent_ids: Vec<String>,
        content: &[u8],
        identity: &Identity,
        classification: Classification,
    ) -> Result<String> {
        let mut record = ValidationRecord::create(
            content,
            identity.public_key.clone(),
            parent_ids,
            classification,
            None,
        );

        let signable = record.signable_bytes();
        record.signature = Some(identity.sign(&signable)?);

        self.insert(&record)
    }

    /// CLASSIFY — Get the classification of a record.
    pub fn classify(&self, record_id: &str) -> Result<Classification> {
        let record = self.storage.get(record_id)?;
        Ok(record.classification)
    }

    /// ANALYZE — Get DAG statistics around a record.
    pub fn analyze(&self, record_id: &str) -> Result<AnalysisResult> {
        if !self.dag.contains(record_id) {
            return Err(ElaraError::RecordNotFound(record_id.to_string()));
        }

        let ancestors = self
            .dag
            .ancestors(record_id, self.config.max_ancestors_depth);
        let descendants = self
            .dag
            .descendants(record_id, self.config.max_ancestors_depth);
        let parents = self.dag.parents(record_id);
        let children = self.dag.children(record_id);

        Ok(AnalysisResult {
            record_id: record_id.to_string(),
            ancestor_count: ancestors.len(),
            descendant_count: descendants.len(),
            parent_count: parents.len(),
            child_count: children.len(),
            is_tip: children.is_empty(),
            is_root: parents.is_empty(),
        })
    }

    /// HASH — Compute SHA3-256 of content.
    pub fn hash(&self, content: &[u8]) -> [u8; 32] {
        sha3_256(content)
    }

    /// SIGN — Sign a message with an identity.
    pub fn sign(&self, message: &[u8], identity: &Identity) -> Result<Vec<u8>> {
        identity.sign(message)
    }

    /// VERIFY — Verify a Dilithium3 signature.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool> {
        dilithium3_verify(message, signature, public_key)
    }

    /// Get current tips.
    pub fn tips(&self) -> Vec<String> {
        self.dag.tips()
    }

    /// Get roots.
    pub fn roots(&self) -> Vec<String> {
        self.dag.roots()
    }

    /// Total record count.
    pub fn len(&self) -> usize {
        self.dag.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dag.is_empty()
    }

    /// Get a record by ID.
    pub fn get(&self, record_id: &str) -> Result<ValidationRecord> {
        self.storage.get(record_id)
    }
}

/// Result of the ANALYZE operation.
#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub record_id: String,
    pub ancestor_count: usize,
    pub descendant_count: usize,
    pub parent_count: usize,
    pub child_count: usize,
    pub is_tip: bool,
    pub is_root: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{CryptoProfile, EntityType};
    use crate::storage::sqlite::SqliteStorage;

    fn setup_vm() -> (DamVm<SqliteStorage>, Identity) {
        let storage = SqliteStorage::in_memory().unwrap();
        let config = DvmConfig::default();
        let vm = DamVm::new(storage, config);
        let identity =
            Identity::generate(EntityType::Human, CryptoProfile::ProfileB).unwrap();
        (vm, identity)
    }

    fn signed_record(
        identity: &Identity,
        parents: Vec<String>,
    ) -> ValidationRecord {
        let mut rec = ValidationRecord::create(
            b"test content",
            identity.public_key.clone(),
            parents,
            Classification::Public,
            None,
        );
        let signable = rec.signable_bytes();
        rec.signature = Some(identity.sign(&signable).unwrap());
        rec
    }

    #[test]
    fn test_insert_and_get() {
        let (mut vm, id) = setup_vm();
        let rec = signed_record(&id, vec![]);
        let rec_id = rec.id.clone();
        vm.insert(&rec).unwrap();

        let retrieved = vm.get(&rec_id).unwrap();
        assert_eq!(retrieved.id, rec_id);
    }

    #[test]
    fn test_insert_unsigned_rejected() {
        let (mut vm, id) = setup_vm();
        let rec = ValidationRecord::create(
            b"unsigned",
            id.public_key.clone(),
            vec![],
            Classification::Public,
            None,
        );
        assert!(vm.insert(&rec).is_err());
    }

    #[test]
    fn test_witness() {
        let (mut vm, id) = setup_vm();
        // Insert genesis
        let hash1 = vm.witness(b"genesis", &id, Classification::Public, None).unwrap();
        assert!(!hash1.is_empty());

        // Witness references tips
        let hash2 = vm.witness(b"second", &id, Classification::Public, None).unwrap();
        assert_ne!(hash1, hash2);
        assert_eq!(vm.len(), 2);
    }

    #[test]
    fn test_merge() {
        let (mut vm, id) = setup_vm();
        let r1 = signed_record(&id, vec![]);
        let r1_id = r1.id.clone();
        vm.insert(&r1).unwrap();

        let r2 = signed_record(&id, vec![]);
        let r2_id = r2.id.clone();
        vm.insert(&r2).unwrap();

        vm.merge(
            vec![r1_id, r2_id],
            b"merged",
            &id,
            Classification::Public,
        )
        .unwrap();
        assert_eq!(vm.len(), 3);
        assert_eq!(vm.tips().len(), 1);
    }

    #[test]
    fn test_analyze() {
        let (mut vm, id) = setup_vm();
        let r1 = signed_record(&id, vec![]);
        let r1_id = r1.id.clone();
        vm.insert(&r1).unwrap();

        let r2 = signed_record(&id, vec![r1_id.clone()]);
        let r2_id = r2.id.clone();
        vm.insert(&r2).unwrap();

        let analysis = vm.analyze(&r2_id).unwrap();
        assert_eq!(analysis.ancestor_count, 1);
        assert_eq!(analysis.parent_count, 1);
        assert!(analysis.is_tip);
        assert!(!analysis.is_root);

        let root_analysis = vm.analyze(&r1_id).unwrap();
        assert!(root_analysis.is_root);
    }

    #[test]
    fn test_hash_op() {
        let (vm, _) = setup_vm();
        let h1 = vm.hash(b"hello");
        let h2 = vm.hash(b"hello");
        assert_eq!(h1, h2);
        assert_ne!(vm.hash(b"hello"), vm.hash(b"world"));
    }

    #[test]
    fn test_sign_verify_ops() {
        let (vm, id) = setup_vm();
        let msg = b"test message";
        let sig = vm.sign(msg, &id).unwrap();
        assert!(vm.verify(msg, &sig, &id.public_key).unwrap());
        assert!(!vm.verify(b"wrong", &sig, &id.public_key).unwrap());
    }

    #[test]
    fn test_classify() {
        let (mut vm, id) = setup_vm();
        vm.witness(b"private data", &id, Classification::Private, None)
            .unwrap();
        let tips = vm.tips();
        let class = vm.classify(&tips[0]).unwrap();
        assert_eq!(class, Classification::Private);
    }
}
