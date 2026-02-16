//! Memory-mapped index files for fast tile lookups.

use std::fs;
use std::path::Path;

use memmap2::Mmap;

use crate::errors::{ElaraError, Result};

/// Entry size: id_hash(8) + offset(8) + length(4) = 20 bytes.
const ENTRY_SIZE: usize = 20;

/// A memory-mapped read-only index over a tile's index.bin file.
pub struct MmapIndex {
    mmap: Mmap,
    entry_count: usize,
}

impl MmapIndex {
    /// Open a memory-mapped index from a file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = fs::File::open(path.as_ref())?;
        let metadata = file.metadata()?;
        let len = metadata.len() as usize;

        if len % ENTRY_SIZE != 0 {
            return Err(ElaraError::Storage(format!(
                "index file size {} not aligned to entry size {}",
                len, ENTRY_SIZE
            )));
        }

        let mmap = unsafe { Mmap::map(&file)? };
        let entry_count = len / ENTRY_SIZE;

        Ok(Self { mmap, entry_count })
    }

    /// Number of entries in the index.
    pub fn len(&self) -> usize {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Get entry at index: returns (id_hash_prefix, offset, length).
    pub fn get(&self, idx: usize) -> Option<([u8; 8], u64, u32)> {
        if idx >= self.entry_count {
            return None;
        }
        let start = idx * ENTRY_SIZE;
        let entry = &self.mmap[start..start + ENTRY_SIZE];

        let mut id_hash = [0u8; 8];
        id_hash.copy_from_slice(&entry[0..8]);
        let offset = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let length = u32::from_le_bytes(entry[16..20].try_into().unwrap());

        Some((id_hash, offset, length))
    }

    /// Linear scan for an entry matching an id_hash prefix.
    /// Returns (offset, length) if found.
    pub fn find_by_id_hash(&self, target: &[u8; 8]) -> Option<(u64, u32)> {
        for i in 0..self.entry_count {
            if let Some((hash, offset, length)) = self.get(i) {
                if hash == *target {
                    return Some((offset, length));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_mmap_index_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.bin");

        // Write 3 entries
        let mut file = fs::File::create(&path).unwrap();
        for i in 0u64..3 {
            let mut entry = [0u8; ENTRY_SIZE];
            entry[0] = i as u8; // id_hash prefix
            entry[8..16].copy_from_slice(&(i * 100).to_le_bytes()); // offset
            entry[16..20].copy_from_slice(&((i as u32 + 1) * 50).to_le_bytes()); // length
            file.write_all(&entry).unwrap();
        }
        drop(file);

        let idx = MmapIndex::open(&path).unwrap();
        assert_eq!(idx.len(), 3);

        let (hash, offset, length) = idx.get(0).unwrap();
        assert_eq!(hash[0], 0);
        assert_eq!(offset, 0);
        assert_eq!(length, 50);

        let (hash, offset, length) = idx.get(2).unwrap();
        assert_eq!(hash[0], 2);
        assert_eq!(offset, 200);
        assert_eq!(length, 150);
    }

    #[test]
    fn test_mmap_find_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.bin");

        let mut file = fs::File::create(&path).unwrap();
        let mut target_hash = [0u8; 8];
        target_hash[0] = 0x42;
        let mut entry = [0u8; ENTRY_SIZE];
        entry[0..8].copy_from_slice(&target_hash);
        entry[8..16].copy_from_slice(&500u64.to_le_bytes());
        entry[16..20].copy_from_slice(&100u32.to_le_bytes());
        file.write_all(&entry).unwrap();
        drop(file);

        let idx = MmapIndex::open(&path).unwrap();
        let (offset, length) = idx.find_by_id_hash(&target_hash).unwrap();
        assert_eq!(offset, 500);
        assert_eq!(length, 100);
    }
}
