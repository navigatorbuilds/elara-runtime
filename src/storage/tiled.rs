//! Tiled filesystem storage with dimensional addressing.
//!
//! Layout:
//! ```text
//! {base_dir}/tiles/{year}/{month}/{day}/c{class}/z{zone}/s{shard}/
//!   records.bin   — append-only wire-format records
//!   index.bin     — [id_hash(8) | offset(8) | length(4)] entries
//!   edges.bin     — [child_hash(8) | parent_hash(8)] entries
//! ```

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::addressing::Address;
use crate::crypto::hash::sha3_256;
use crate::errors::{ElaraError, Result};
use crate::record::{Classification, ValidationRecord};
use crate::storage::Storage;

/// Index entry: maps record ID hash to offset/length in records.bin.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    id_hash: [u8; 8],  // First 8 bytes of SHA3-256(record_id)
    offset: u64,        // Byte offset in records.bin
    length: u32,        // Length of wire-format record
}

impl IndexEntry {
    const SIZE: usize = 8 + 8 + 4; // 20 bytes

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.id_hash);
        buf[8..16].copy_from_slice(&self.offset.to_le_bytes());
        buf[16..20].copy_from_slice(&self.length.to_le_bytes());
        buf
    }

    #[allow(dead_code)]
    fn from_bytes(data: &[u8; Self::SIZE]) -> Self {
        let mut id_hash = [0u8; 8];
        id_hash.copy_from_slice(&data[0..8]);
        let offset = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let length = u32::from_le_bytes(data[16..20].try_into().unwrap());
        Self {
            id_hash,
            offset,
            length,
        }
    }
}

/// Edge entry: parent-child relationship.
#[derive(Debug, Clone, Copy)]
struct EdgeEntry {
    child_hash: [u8; 8],
    parent_hash: [u8; 8],
}

impl EdgeEntry {
    const SIZE: usize = 16;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..8].copy_from_slice(&self.child_hash);
        buf[8..16].copy_from_slice(&self.parent_hash);
        buf
    }
}

fn id_hash_prefix(id: &str) -> [u8; 8] {
    let full = sha3_256(id.as_bytes());
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&full[0..8]);
    prefix
}

/// Tiled filesystem storage backend.
pub struct TiledStorage {
    base_dir: PathBuf,
    /// In-memory index: record_id -> (tile_path, offset, length)
    id_index: HashMap<String, (PathBuf, u64, u32)>,
    /// In-memory hash index: record_hash_hex -> record_id
    hash_index: HashMap<String, String>,
    /// In-memory edge index: parent_id -> Vec<child_id>
    children_index: HashMap<String, Vec<String>>,
    /// In-memory edge index: child_id -> Vec<parent_id>
    parents_index: HashMap<String, Vec<String>>,
    /// All known record IDs
    all_ids: HashSet<String>,
}

impl TiledStorage {
    /// Open or create a tiled storage at the given base directory.
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(base_dir.join("tiles"))?;
        Ok(Self {
            base_dir,
            id_index: HashMap::new(),
            hash_index: HashMap::new(),
            children_index: HashMap::new(),
            parents_index: HashMap::new(),
            all_ids: HashSet::new(),
        })
    }

    fn tile_dir(&self, addr: &Address) -> PathBuf {
        self.base_dir.join("tiles").join(addr.to_path())
    }

    fn ensure_tile_dir(&self, addr: &Address) -> Result<PathBuf> {
        let dir = self.tile_dir(addr);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

impl Storage for TiledStorage {
    fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
        if self.all_ids.contains(&record.id) {
            return Err(ElaraError::DuplicateRecord(record.id.clone()));
        }

        // Check parents exist
        for pid in &record.parents {
            if !self.all_ids.contains(pid) {
                return Err(ElaraError::MissingParent(pid.clone()));
            }
        }

        let addr = Address::from_record(record);
        let tile_dir = self.ensure_tile_dir(&addr)?;

        // Serialize to wire format
        let wire_bytes = record.to_bytes();
        let rec_hash = sha3_256(&wire_bytes);
        let rec_hash_hex = hex::encode(rec_hash);

        // Append to records.bin
        let records_path = tile_dir.join("records.bin");
        let offset = if records_path.exists() {
            fs::metadata(&records_path)?.len()
        } else {
            0
        };
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&records_path)?;
        file.write_all(&wire_bytes)?;

        // Append to index.bin
        let index_entry = IndexEntry {
            id_hash: id_hash_prefix(&record.id),
            offset,
            length: wire_bytes.len() as u32,
        };
        let index_path = tile_dir.join("index.bin");
        let mut index_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&index_path)?;
        index_file.write_all(&index_entry.to_bytes())?;

        // Append edges
        if !record.parents.is_empty() {
            let edges_path = tile_dir.join("edges.bin");
            let mut edges_file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&edges_path)?;
            for pid in &record.parents {
                let edge = EdgeEntry {
                    child_hash: id_hash_prefix(&record.id),
                    parent_hash: id_hash_prefix(pid),
                };
                edges_file.write_all(&edge.to_bytes())?;
            }
        }

        // Update in-memory indexes
        self.id_index.insert(
            record.id.clone(),
            (tile_dir, offset, wire_bytes.len() as u32),
        );
        self.hash_index
            .insert(rec_hash_hex.clone(), record.id.clone());
        self.all_ids.insert(record.id.clone());

        for pid in &record.parents {
            self.children_index
                .entry(pid.clone())
                .or_default()
                .push(record.id.clone());
            self.parents_index
                .entry(record.id.clone())
                .or_default()
                .push(pid.clone());
        }

        Ok(rec_hash_hex)
    }

    fn get(&self, record_id: &str) -> Result<ValidationRecord> {
        let (tile_dir, offset, length) = self
            .id_index
            .get(record_id)
            .ok_or_else(|| ElaraError::RecordNotFound(record_id.to_string()))?;

        let records_path = tile_dir.join("records.bin");
        let data = fs::read(&records_path)?;
        let wire_bytes = &data[*offset as usize..(*offset as usize + *length as usize)];
        ValidationRecord::from_bytes(wire_bytes)
    }

    fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord> {
        let record_id = self
            .hash_index
            .get(hash)
            .ok_or_else(|| ElaraError::RecordNotFound(format!("hash:{hash}")))?;
        self.get(record_id)
    }

    fn exists(&self, record_id: &str) -> Result<bool> {
        Ok(self.all_ids.contains(record_id))
    }

    fn tips(&self) -> Result<Vec<String>> {
        Ok(self
            .all_ids
            .iter()
            .filter(|id| {
                self.children_index
                    .get(*id)
                    .map_or(true, |c| c.is_empty())
            })
            .cloned()
            .collect())
    }

    fn roots(&self) -> Result<Vec<String>> {
        Ok(self
            .all_ids
            .iter()
            .filter(|id| {
                self.parents_index
                    .get(*id)
                    .map_or(true, |p| p.is_empty())
            })
            .cloned()
            .collect())
    }

    fn parents(&self, record_id: &str) -> Result<Vec<String>> {
        Ok(self
            .parents_index
            .get(record_id)
            .cloned()
            .unwrap_or_default())
    }

    fn children(&self, record_id: &str) -> Result<Vec<String>> {
        Ok(self
            .children_index
            .get(record_id)
            .cloned()
            .unwrap_or_default())
    }

    fn count(&self) -> Result<usize> {
        Ok(self.all_ids.len())
    }

    fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        let mut results = Vec::new();
        for id in &self.all_ids {
            if results.len() >= limit {
                break;
            }
            let record = self.get(id)?;
            if let Some(c) = classification {
                if record.classification != c {
                    continue;
                }
            }
            if let Some(ck) = creator_key {
                if record.creator_public_key != ck {
                    continue;
                }
            }
            if let Some(s) = since {
                if record.timestamp < s {
                    continue;
                }
            }
            if let Some(u) = until {
                if record.timestamp > u {
                    continue;
                }
            }
            results.push(record);
        }
        results.sort_by(|a, b| b.timestamp.partial_cmp(&a.timestamp).unwrap());
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_record(
        id: &str,
        parents: Vec<String>,
        class: Classification,
    ) -> ValidationRecord {
        ValidationRecord {
            id: id.to_string(),
            version: 1,
            content_hash: sha3_256(id.as_bytes()).to_vec(),
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1739712345.0,
            parents,
            classification: class,
            metadata: BTreeMap::new(),
            signature: Some(vec![0xBB; 3293]),
            sphincs_signature: None,
            zk_proof: None,
        }
    }

    #[test]
    fn test_tiled_insert_get() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TiledStorage::new(dir.path()).unwrap();
        let rec = make_record("rec-001", vec![], Classification::Public);
        let hash = store.insert(&rec).unwrap();
        assert!(!hash.is_empty());

        let retrieved = store.get("rec-001").unwrap();
        assert_eq!(retrieved.id, "rec-001");
    }

    #[test]
    fn test_tiled_tips_roots() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TiledStorage::new(dir.path()).unwrap();
        let r1 = make_record("r1", vec![], Classification::Public);
        store.insert(&r1).unwrap();
        let r2 = make_record("r2", vec!["r1".into()], Classification::Public);
        store.insert(&r2).unwrap();

        let roots = store.roots().unwrap();
        assert!(roots.contains(&"r1".to_string()));
        let tips = store.tips().unwrap();
        assert!(tips.contains(&"r2".to_string()));
    }

    #[test]
    fn test_tiled_duplicate_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TiledStorage::new(dir.path()).unwrap();
        let rec = make_record("dup-001", vec![], Classification::Public);
        store.insert(&rec).unwrap();
        assert!(store.insert(&rec).is_err());
    }

    #[test]
    fn test_tiled_missing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TiledStorage::new(dir.path()).unwrap();
        let rec = make_record("orphan", vec!["nonexistent".into()], Classification::Public);
        assert!(store.insert(&rec).is_err());
    }

    #[test]
    fn test_tiled_directory_structure() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = TiledStorage::new(dir.path()).unwrap();
        let rec = make_record("dir-test", vec![], Classification::Public);
        store.insert(&rec).unwrap();

        // Check tiles directory was created
        assert!(dir.path().join("tiles").exists());
    }
}
