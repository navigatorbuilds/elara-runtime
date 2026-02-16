//! SQLite storage backend — reads existing Layer 1 DAG databases.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::errors::{ElaraError, Result};
use crate::record::{Classification, ValidationRecord};
use crate::storage::Storage;

/// SQLite-backed storage, compatible with Python Layer 1's LocalDAG format.
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    /// Open an existing Layer 1 SQLite database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Ok(Self { conn })
    }

    /// Create a new SQLite database with the Layer 1 schema.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref())?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA synchronous=NORMAL;

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                content_hash BLOB NOT NULL,
                creator_public_key BLOB NOT NULL,
                timestamp REAL NOT NULL,
                classification INTEGER NOT NULL,
                metadata TEXT NOT NULL,
                signature BLOB,
                sphincs_signature BLOB,
                zk_proof BLOB,
                record_hash BLOB NOT NULL,
                wire_bytes BLOB NOT NULL,
                inserted_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS edges (
                child_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                PRIMARY KEY (child_id, parent_id),
                FOREIGN KEY (child_id) REFERENCES records(id),
                FOREIGN KEY (parent_id) REFERENCES records(id)
            );

            CREATE INDEX IF NOT EXISTS idx_records_timestamp ON records(timestamp);
            CREATE INDEX IF NOT EXISTS idx_records_classification ON records(classification);
            CREATE INDEX IF NOT EXISTS idx_records_creator ON records(creator_public_key);
            CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);

            INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1');
            ",
        )?;
        Ok(Self { conn })
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "
            PRAGMA foreign_keys=ON;

            CREATE TABLE meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE records (
                id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                content_hash BLOB NOT NULL,
                creator_public_key BLOB NOT NULL,
                timestamp REAL NOT NULL,
                classification INTEGER NOT NULL,
                metadata TEXT NOT NULL,
                signature BLOB,
                sphincs_signature BLOB,
                zk_proof BLOB,
                record_hash BLOB NOT NULL,
                wire_bytes BLOB NOT NULL,
                inserted_at REAL NOT NULL
            );

            CREATE TABLE edges (
                child_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                PRIMARY KEY (child_id, parent_id),
                FOREIGN KEY (child_id) REFERENCES records(id),
                FOREIGN KEY (parent_id) REFERENCES records(id)
            );

            INSERT INTO meta (key, value) VALUES ('schema_version', '1');
            ",
        )?;
        Ok(Self { conn })
    }
}

impl Storage for SqliteStorage {
    fn insert(&mut self, record: &ValidationRecord) -> Result<String> {
        // Check duplicate
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id = ?1)",
            params![record.id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(ElaraError::DuplicateRecord(record.id.clone()));
        }

        // Check parents exist
        for pid in &record.parents {
            let parent_exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM records WHERE id = ?1)",
                params![pid],
                |row| row.get(0),
            )?;
            if !parent_exists {
                return Err(ElaraError::MissingParent(pid.clone()));
            }
        }

        let wire_bytes = record.to_bytes();
        let rec_hash = crate::crypto::hash::sha3_256(&wire_bytes);
        let rec_hash_hex = hex::encode(rec_hash);
        let meta_json = serde_json::to_string(&record.metadata)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        self.conn.execute(
            "INSERT INTO records (id, version, content_hash, creator_public_key, timestamp,
                classification, metadata, signature, sphincs_signature, zk_proof,
                record_hash, wire_bytes, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                record.id,
                record.version,
                record.content_hash,
                record.creator_public_key,
                record.timestamp,
                record.classification as u8,
                meta_json,
                record.signature,
                record.sphincs_signature,
                record.zk_proof,
                rec_hash.to_vec(),
                wire_bytes,
                now,
            ],
        )?;

        for pid in &record.parents {
            self.conn.execute(
                "INSERT INTO edges (child_id, parent_id) VALUES (?1, ?2)",
                params![record.id, pid],
            )?;
        }

        Ok(rec_hash_hex)
    }

    fn get(&self, record_id: &str) -> Result<ValidationRecord> {
        let wire_bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT wire_bytes FROM records WHERE id = ?1",
                params![record_id],
                |row| row.get(0),
            )
            .map_err(|_| ElaraError::RecordNotFound(record_id.to_string()))?;
        ValidationRecord::from_bytes(&wire_bytes)
    }

    fn get_by_hash(&self, hash: &str) -> Result<ValidationRecord> {
        let hash_bytes = hex::decode(hash).map_err(|e| ElaraError::Storage(e.to_string()))?;
        let wire_bytes: Vec<u8> = self
            .conn
            .query_row(
                "SELECT wire_bytes FROM records WHERE record_hash = ?1",
                params![hash_bytes],
                |row| row.get(0),
            )
            .map_err(|_| ElaraError::RecordNotFound(format!("hash:{hash}")))?;
        ValidationRecord::from_bytes(&wire_bytes)
    }

    fn exists(&self, record_id: &str) -> Result<bool> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id = ?1)",
            params![record_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    fn tips(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id FROM records r
             WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.parent_id = r.id)
             ORDER BY r.timestamp DESC",
        )?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    fn roots(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id FROM records r
             WHERE NOT EXISTS (SELECT 1 FROM edges e WHERE e.child_id = r.id)
             ORDER BY r.timestamp ASC",
        )?;
        let ids: Vec<String> = stmt
            .query_map([], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    fn parents(&self, record_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT parent_id FROM edges WHERE child_id = ?1")?;
        let ids: Vec<String> = stmt
            .query_map(params![record_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    fn children(&self, record_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT child_id FROM edges WHERE parent_id = ?1")?;
        let ids: Vec<String> = stmt
            .query_map(params![record_id], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(ids)
    }

    fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    fn query(
        &self,
        classification: Option<Classification>,
        creator_key: Option<&[u8]>,
        since: Option<f64>,
        until: Option<f64>,
        limit: usize,
    ) -> Result<Vec<ValidationRecord>> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(c) = classification {
            conditions.push("classification = ?");
            param_values.push(Box::new(c as u8));
        }
        if let Some(ck) = creator_key {
            conditions.push("creator_public_key = ?");
            param_values.push(Box::new(ck.to_vec()));
        }
        if let Some(s) = since {
            conditions.push("timestamp >= ?");
            param_values.push(Box::new(s));
        }
        if let Some(u) = until {
            conditions.push("timestamp <= ?");
            param_values.push(Box::new(u));
        }

        let where_clause = if conditions.is_empty() {
            "1=1".to_string()
        } else {
            conditions.join(" AND ")
        };

        let sql = format!(
            "SELECT wire_bytes FROM records WHERE {where_clause} ORDER BY timestamp DESC LIMIT ?"
        );
        param_values.push(Box::new(limit as i64));

        let params: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let records: Vec<ValidationRecord> = stmt
            .query_map(params.as_slice(), |row| {
                let wire_bytes: Vec<u8> = row.get(0)?;
                Ok(wire_bytes)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|wb| ValidationRecord::from_bytes(&wb).ok())
            .collect();
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::crypto::hash::sha3_256;

    fn make_record(id: &str, parents: Vec<String>, class: Classification) -> ValidationRecord {
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
    fn test_sqlite_insert_get() {
        let mut db = SqliteStorage::in_memory().unwrap();
        let rec = make_record("sqlite-001", vec![], Classification::Public);
        let hash = db.insert(&rec).unwrap();
        assert!(!hash.is_empty());

        let retrieved = db.get("sqlite-001").unwrap();
        assert_eq!(retrieved.id, "sqlite-001");
    }

    #[test]
    fn test_sqlite_tips_roots() {
        let mut db = SqliteStorage::in_memory().unwrap();
        let r1 = make_record("r1", vec![], Classification::Public);
        db.insert(&r1).unwrap();
        let r2 = make_record("r2", vec!["r1".into()], Classification::Public);
        db.insert(&r2).unwrap();

        let roots = db.roots().unwrap();
        assert_eq!(roots, vec!["r1"]);
        let tips = db.tips().unwrap();
        assert_eq!(tips, vec!["r2"]);
    }

    #[test]
    fn test_sqlite_duplicate() {
        let mut db = SqliteStorage::in_memory().unwrap();
        let rec = make_record("dup", vec![], Classification::Public);
        db.insert(&rec).unwrap();
        assert!(db.insert(&rec).is_err());
    }

    #[test]
    fn test_sqlite_query() {
        let mut db = SqliteStorage::in_memory().unwrap();
        let r1 = make_record("q1", vec![], Classification::Public);
        db.insert(&r1).unwrap();
        let r2 = make_record("q2", vec![], Classification::Private);
        db.insert(&r2).unwrap();

        let public = db.query(Some(Classification::Public), None, None, None, 100).unwrap();
        assert_eq!(public.len(), 1);
        assert_eq!(public[0].id, "q1");
    }

    #[test]
    fn test_sqlite_count() {
        let mut db = SqliteStorage::in_memory().unwrap();
        assert_eq!(db.count().unwrap(), 0);
        let rec = make_record("cnt", vec![], Classification::Public);
        db.insert(&rec).unwrap();
        assert_eq!(db.count().unwrap(), 1);
    }
}
