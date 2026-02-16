//! 5-tuple dimensional addressing: (time, concurrency, zone, classification, ai).
//!
//! Maps records to filesystem paths for tiled storage.

use crate::errors::{ElaraError, Result};
use crate::record::{Classification, ValidationRecord};

/// 5-tuple address in the DAM dimensional space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// D1: Time — date components from record timestamp.
    pub year: u16,
    pub month: u8,
    pub day: u8,

    /// D2: Concurrency shard — hash-based distribution.
    pub shard: u16,

    /// D3: Zone — locality identifier (0 = local).
    pub zone: u16,

    /// D4: Classification level.
    pub classification: Classification,

    /// D5: AI confidence tier (reserved for future use).
    pub ai_tier: u8,
}

impl Address {
    /// Derive an address from a validation record.
    pub fn from_record(record: &ValidationRecord) -> Self {
        // D1: Time from timestamp
        let secs = record.timestamp as i64;
        let (year, month, day) = unix_to_ymd(secs);

        // D2: Shard from first 2 bytes of content_hash
        let shard = if record.content_hash.len() >= 2 {
            u16::from_be_bytes([record.content_hash[0], record.content_hash[1]]) % 256
        } else {
            0
        };

        // D3: Zone (local = 0)
        let zone = 0;

        // D4: Classification
        let classification = record.classification;

        // D5: AI tier (0 = unclassified)
        let ai_tier = 0;

        Self {
            year,
            month,
            day,
            shard,
            zone,
            classification,
            ai_tier,
        }
    }

    /// Convert to filesystem path components.
    /// Layout: `{year}/{month:02}/{day:02}/c{classification}/z{zone:04}/s{shard:04}/`
    pub fn to_path(&self) -> String {
        format!(
            "{}/{:02}/{:02}/c{}/z{:04}/s{:04}",
            self.year,
            self.month,
            self.day,
            self.classification as u8,
            self.zone,
            self.shard,
        )
    }

    /// Parse an address from filesystem path components.
    pub fn from_path(path: &str) -> Result<Self> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 6 {
            return Err(ElaraError::Address(format!(
                "path too short: {path}"
            )));
        }
        let year: u16 = parts[0]
            .parse()
            .map_err(|_| ElaraError::Address(format!("invalid year: {}", parts[0])))?;
        let month: u8 = parts[1]
            .parse()
            .map_err(|_| ElaraError::Address(format!("invalid month: {}", parts[1])))?;
        let day: u8 = parts[2]
            .parse()
            .map_err(|_| ElaraError::Address(format!("invalid day: {}", parts[2])))?;

        let classification = parts[3]
            .strip_prefix('c')
            .and_then(|s| s.parse::<u8>().ok())
            .map(Classification::from_u8)
            .ok_or_else(|| ElaraError::Address(format!("invalid classification: {}", parts[3])))??;

        let zone: u16 = parts[4]
            .strip_prefix('z')
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ElaraError::Address(format!("invalid zone: {}", parts[4])))?;

        let shard: u16 = parts[5]
            .strip_prefix('s')
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ElaraError::Address(format!("invalid shard: {}", parts[5])))?;

        Ok(Self {
            year,
            month,
            day,
            shard,
            zone,
            classification,
            ai_tier: 0,
        })
    }
}

/// Convert unix timestamp (seconds) to (year, month, day).
fn unix_to_ymd(secs: i64) -> (u16, u8, u8) {
    // Simple conversion using chrono-free approach
    // Days since epoch
    let days = (secs / 86400) as i32;
    let mut y = 1970i32;
    let mut remaining = days;

    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        y += 1;
    }

    let leap = is_leap(y);
    let month_days = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0usize;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining < md {
            m = i;
            break;
        }
        remaining -= md;
    }

    (y as u16, (m + 1) as u8, (remaining + 1) as u8)
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::sha3_256;

    #[test]
    fn test_unix_to_ymd() {
        // 2026-02-16 = 56 years + ...
        // Let's test a known date: 2024-01-01 00:00:00 UTC = 1704067200
        let (y, m, d) = unix_to_ymd(1704067200);
        assert_eq!((y, m, d), (2024, 1, 1));
    }

    #[test]
    fn test_unix_to_ymd_epoch() {
        let (y, m, d) = unix_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_address_from_record() {
        let rec = ValidationRecord {
            id: "019506e0-1234-7000-8000-000000000001".to_string(),
            version: 1,
            content_hash: sha3_256(b"test").to_vec(),
            creator_public_key: vec![0xAA; 1952],
            timestamp: 1739712345.0, // ~2025-02-16
            parents: vec![],
            classification: Classification::Public,
            metadata: Default::default(),
            signature: None,
            sphincs_signature: None,
            zk_proof: None,
        };
        let addr = Address::from_record(&rec);
        assert_eq!(addr.classification, Classification::Public);
        assert!(addr.year >= 2025);
    }

    #[test]
    fn test_address_path_roundtrip() {
        let addr = Address {
            year: 2026,
            month: 2,
            day: 16,
            shard: 42,
            zone: 0,
            classification: Classification::Public,
            ai_tier: 0,
        };
        let path = addr.to_path();
        assert_eq!(path, "2026/02/16/c0/z0000/s0042");

        let parsed = Address::from_path(&path).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_address_classifications() {
        for class in [
            Classification::Public,
            Classification::Private,
            Classification::Restricted,
            Classification::Sovereign,
        ] {
            let addr = Address {
                year: 2026,
                month: 1,
                day: 1,
                shard: 0,
                zone: 0,
                classification: class,
                ai_tier: 0,
            };
            let path = addr.to_path();
            let parsed = Address::from_path(&path).unwrap();
            assert_eq!(parsed.classification, class);
        }
    }
}
