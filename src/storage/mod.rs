//! Storage backends: tiled filesystem, memory-mapped index, SQLite compatibility.

pub mod mmap_index;
pub mod sqlite;
pub mod tiled;

use crate::errors::Result;
use crate::record::{Classification, ValidationRecord};

/// Storage trait — abstract backend for record persistence.
pub trait Storage {
    /// Insert a record into storage.
    fn insert(&mut self, record: &ValidationRecord) -> Result<String>;

    /// Retrieve a record by UUID.
    fn get(&self, record_id: &str) -> Result<ValidationRecord>;

    /// Retrieve a record by its SHA3-256 hash (hex).
    fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord>;

    /// Check if a record exists.
    fn exists(&self, record_id: &str) -> Result<bool>;

    /// Return tip record IDs (no children).
    fn tips(&self) -> Result<Vec<String>>;

    /// Return root record IDs (no parents).
    fn roots(&self) -> Result<Vec<String>>;

    /// Return parent IDs of a record.
    fn parents(&self, record_id: &str) -> Result<Vec<String>>;

    /// Return child IDs of a record.
    fn children(&self, record_id: &str) -> Result<Vec<String>>;

    /// Total record count.
    fn count(&self) -> Result<usize>;

    /// Query with optional filters.
    fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>>;
}
