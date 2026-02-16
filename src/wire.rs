//! ELRA binary wire format — byte-identical to the Python Layer 1 implementation.
//!
//! Wire format layout:
//! ```text
//! [ELRA][version:2][type:1][reserved:1]  — 8-byte header
//! [id_len:1][id:N]                       — UUID v7
//! [content_hash:32]                      — SHA3-256
//! [pk_len:2][public_key:N]               — Dilithium3 public key
//! [timestamp:8]                          — IEEE 754 double, big-endian
//! [num_parents:2][parent_ids...]         — DAG edges (each: [len:1][id:N])
//! [classification:1]                     — 0=PUBLIC, 1=PRIVATE, 2=RESTRICTED, 3=SOVEREIGN
//! [meta_len:4][metadata:N]              — sorted compact JSON
//! [zk_len:4][zk_proof:N]               — ZK proof (future)
//! [sig_len:2][signature:N]              — Dilithium3 signature
//! [sphincs_len:2][sphincs_sig:N]        — SPHINCS+ signature
//! ```

use crate::errors::{ElaraError, Result};

pub const MAGIC: &[u8; 4] = b"ELRA";
pub const WIRE_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 8; // 4 (magic) + 2 (version) + 1 (type) + 1 (reserved)

/// Encode a record header.
pub fn encode_header(buf: &mut Vec<u8>) {
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    buf.push(0x01); // record_type
    buf.push(0x00); // reserved
}

/// Encode a length-prefixed byte field with u8 length prefix.
pub fn encode_u8_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

/// Encode a length-prefixed byte field with u16 (big-endian) length prefix.
pub fn encode_u16_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode a length-prefixed byte field with u32 (big-endian) length prefix.
pub fn encode_u32_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Encode an f64 timestamp as big-endian IEEE 754.
pub fn encode_timestamp(buf: &mut Vec<u8>, ts: f64) {
    buf.extend_from_slice(&ts.to_be_bytes());
}

/// Encode optional bytes with u16 prefix (0 length if None).
pub fn encode_optional_u16(buf: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) => encode_u16_prefixed(buf, d),
        None => buf.extend_from_slice(&0u16.to_be_bytes()),
    }
}

/// Encode optional bytes with u32 prefix (0 length if None).
pub fn encode_optional_u32(buf: &mut Vec<u8>, data: Option<&[u8]>) {
    match data {
        Some(d) => encode_u32_prefixed(buf, d),
        None => buf.extend_from_slice(&0u32.to_be_bytes()),
    }
}

/// A cursor for reading wire-format bytes.
pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(ElaraError::Wire(format!(
                "unexpected EOF at offset {}, need {} bytes",
                self.pos, n
            )));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_f64(&mut self) -> Result<f64> {
        let bytes = self.read_bytes(8)?;
        Ok(f64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a field with u8 length prefix.
    pub fn read_u8_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u8()? as usize;
        self.read_bytes(len)
    }

    /// Read a field with u16 length prefix.
    pub fn read_u16_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    /// Read a field with u32 length prefix.
    pub fn read_u32_prefixed(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_bytes(len)
    }

    /// Read optional bytes with u16 length prefix (returns None if length is 0).
    pub fn read_optional_u16(&mut self) -> Result<Option<Vec<u8>>> {
        let len = self.read_u16()? as usize;
        if len == 0 {
            Ok(None)
        } else {
            let data = self.read_bytes(len)?;
            Ok(Some(data.to_vec()))
        }
    }

    /// Read optional bytes with u32 length prefix.
    pub fn read_optional_u32(&mut self) -> Result<Option<Vec<u8>>> {
        let len = self.read_u32()? as usize;
        if len == 0 {
            Ok(None)
        } else {
            let data = self.read_bytes(len)?;
            Ok(Some(data.to_vec()))
        }
    }

    /// Validate the wire header, returning (version, record_type).
    pub fn read_header(&mut self) -> Result<(u16, u8)> {
        let magic = self.read_bytes(4)?;
        if magic != MAGIC {
            return Err(ElaraError::Wire(format!("invalid magic: {:?}", magic)));
        }
        let version = self.read_u16()?;
        if version != WIRE_VERSION {
            return Err(ElaraError::Wire(format!(
                "unsupported wire version: {version}"
            )));
        }
        let rec_type = self.read_u8()?;
        let _reserved = self.read_u8()?;
        Ok((version, rec_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let mut buf = Vec::new();
        encode_header(&mut buf);
        assert_eq!(buf.len(), HEADER_SIZE);
        assert_eq!(&buf[0..4], MAGIC);

        let mut reader = WireReader::new(&buf);
        let (version, rec_type) = reader.read_header().unwrap();
        assert_eq!(version, WIRE_VERSION);
        assert_eq!(rec_type, 0x01);
    }

    #[test]
    fn test_u8_prefixed() {
        let mut buf = Vec::new();
        encode_u8_prefixed(&mut buf, b"hello");
        assert_eq!(buf.len(), 6); // 1 + 5

        let mut reader = WireReader::new(&buf);
        let data = reader.read_u8_prefixed().unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn test_u16_prefixed() {
        let mut buf = Vec::new();
        let key = vec![0xAB; 1952]; // Dilithium3 pk size
        encode_u16_prefixed(&mut buf, &key);
        assert_eq!(buf.len(), 1954); // 2 + 1952

        let mut reader = WireReader::new(&buf);
        let data = reader.read_u16_prefixed().unwrap();
        assert_eq!(data.len(), 1952);
    }

    #[test]
    fn test_timestamp_encode_decode() {
        let mut buf = Vec::new();
        let ts = 1739712345.123456;
        encode_timestamp(&mut buf, ts);
        assert_eq!(buf.len(), 8);

        let mut reader = WireReader::new(&buf);
        let decoded = reader.read_f64().unwrap();
        assert_eq!(decoded, ts);
    }

    #[test]
    fn test_invalid_magic() {
        let buf = b"NOPE\x00\x01\x01\x00";
        let mut reader = WireReader::new(buf);
        assert!(reader.read_header().is_err());
    }
}
