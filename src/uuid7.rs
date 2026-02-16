//! UUID v7 generation — time-ordered, random.

use uuid::Uuid;

/// Generate a new UUID v7 string.
pub fn uuid7() -> String {
    Uuid::now_v7().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid7_format() {
        let id = uuid7();
        // Standard UUID format: 8-4-4-4-12
        assert_eq!(id.len(), 36);
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        // Version 7: char at position 14 should be '7'
        assert_eq!(&id[14..15], "7");
    }

    #[test]
    fn test_uuid7_uniqueness() {
        let ids: Vec<String> = (0..100).map(|_| uuid7()).collect();
        let mut deduped = ids.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len());
    }

    #[test]
    fn test_uuid7_ordering() {
        // UUIDs generated sequentially should be lexicographically ordered
        let id1 = uuid7();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = uuid7();
        assert!(id1 < id2, "UUID v7 should be time-ordered: {} < {}", id1, id2);
    }
}
