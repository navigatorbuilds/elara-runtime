//! Elara Runtime — Layer 1.5 DAM Virtual Machine.
//!
//! Rust implementation of the Elara Protocol with PyO3 bindings.
//! Provides a fast lane for crypto, wire format, and DAG operations
//! while maintaining byte-level compatibility with the Python Layer 1.

pub mod addressing;
pub mod crypto;
pub mod dag;
pub mod errors;
pub mod identity;
pub mod operations;
pub mod record;
pub mod storage;
pub mod uuid7;
pub mod wire;

use std::collections::BTreeMap;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

// ─── PyO3 Bindings ────────────────────────────────────────────────────────

/// Generate a Dilithium3 keypair. Returns (public_key, secret_key) as bytes.
#[pyfunction]
fn py_dilithium3_keygen(py: Python) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let kp = crypto::pqc::dilithium3_keygen()?;
    Ok((
        PyBytes::new(py, &kp.public_key).into(),
        PyBytes::new(py, &kp.secret_key).into(),
    ))
}

/// Sign a message with Dilithium3. Returns signature bytes.
#[pyfunction]
fn py_dilithium3_sign<'py>(
    py: Python<'py>,
    message: &[u8],
    secret_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    let sig = crypto::pqc::dilithium3_sign(message, secret_key)?;
    Ok(PyBytes::new(py, &sig).into())
}

/// Verify a Dilithium3 signature. Returns bool.
#[pyfunction]
fn py_dilithium3_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    Ok(crypto::pqc::dilithium3_verify(message, signature, public_key)?)
}

/// Generate a SPHINCS+ keypair. Returns (public_key, secret_key) as bytes.
#[pyfunction]
fn py_sphincs_keygen(py: Python) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let kp = crypto::pqc::sphincs_keygen()?;
    Ok((
        PyBytes::new(py, &kp.public_key).into(),
        PyBytes::new(py, &kp.secret_key).into(),
    ))
}

/// Sign a message with SPHINCS+. Returns signature bytes.
#[pyfunction]
fn py_sphincs_sign<'py>(
    py: Python<'py>,
    message: &[u8],
    secret_key: &[u8],
) -> PyResult<Py<PyBytes>> {
    let sig = crypto::pqc::sphincs_sign(message, secret_key)?;
    Ok(PyBytes::new(py, &sig).into())
}

/// Verify a SPHINCS+ signature. Returns bool.
#[pyfunction]
fn py_sphincs_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> PyResult<bool> {
    Ok(crypto::pqc::sphincs_verify(message, signature, public_key)?)
}

/// Compute SHA3-256 hash. Returns 32-byte hash.
#[pyfunction]
fn py_sha3_256<'py>(py: Python<'py>, data: &[u8]) -> Py<PyBytes> {
    let hash = crypto::hash::sha3_256(data);
    PyBytes::new(py, &hash).into()
}

/// Compute SHA3-256 hash. Returns hex string.
#[pyfunction]
fn py_sha3_256_hex(data: &[u8]) -> String {
    crypto::hash::sha3_256_hex(data)
}

/// Batch verify Dilithium3 signatures. Returns list of bools.
#[pyfunction]
fn py_batch_verify(jobs: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>) -> Vec<bool> {
    let verify_jobs: Vec<crypto::batch::VerifyJob> = jobs
        .iter()
        .map(|(msg, sig, pk)| crypto::batch::VerifyJob {
            message: msg,
            signature: sig,
            public_key: pk,
        })
        .collect();
    crypto::batch::batch_verify(&verify_jobs)
}

/// Generate a UUID v7 string.
#[pyfunction]
fn py_uuid7() -> String {
    uuid7::uuid7()
}

/// Encode a ValidationRecord to wire format bytes.
/// Takes a dict with record fields, returns bytes.
#[pyfunction]
fn py_record_to_bytes<'py>(py: Python<'py>, record_dict: &Bound<'py, PyDict>) -> PyResult<Py<PyBytes>> {
    let rec = dict_to_record(record_dict)?;
    let wire = rec.to_bytes();
    Ok(PyBytes::new(py, &wire).into())
}

/// Decode wire format bytes to a record dict.
#[pyfunction]
fn py_record_from_bytes<'py>(py: Python<'py>, data: &[u8]) -> PyResult<PyObject> {
    let rec = record::ValidationRecord::from_bytes(data)?;
    record_to_dict(py, &rec)
}

/// Compute signable bytes for a record dict.
#[pyfunction]
fn py_signable_bytes<'py>(py: Python<'py>, record_dict: &Bound<'py, PyDict>) -> PyResult<Py<PyBytes>> {
    let rec = dict_to_record(record_dict)?;
    let signable = rec.signable_bytes();
    Ok(PyBytes::new(py, &signable).into())
}

// ─── Helper conversions ───────────────────────────────────────────────────

/// Convert a Python value to serde_json::Value, preserving types.
fn python_to_json_value(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        return Ok(serde_json::Value::Null);
    }
    // Try bool BEFORE int — Python bool is a subclass of int
    if let Ok(b) = obj.extract::<bool>() {
        return Ok(serde_json::Value::Bool(b));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(serde_json::json!(i));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(serde_json::json!(f));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }
    // Fallback: stringify
    let s: String = obj.str()?.to_string();
    Ok(serde_json::Value::String(s))
}

fn dict_to_record(dict: &Bound<'_, PyDict>) -> PyResult<record::ValidationRecord> {
    let id: String = dict
        .get_item("id")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("id"))?
        .extract()?;

    let version: u16 = dict
        .get_item("version")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("version"))?
        .extract()?;

    let content_hash: Vec<u8> = dict
        .get_item("content_hash")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("content_hash"))?
        .extract()?;

    let creator_public_key: Vec<u8> = dict
        .get_item("creator_public_key")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("creator_public_key"))?
        .extract()?;

    let timestamp: f64 = dict
        .get_item("timestamp")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("timestamp"))?
        .extract()?;

    let parents: Vec<String> = dict
        .get_item("parents")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("parents"))?
        .extract()?;

    let classification_val: u8 = dict
        .get_item("classification")?
        .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err("classification"))?
        .extract()?;
    let classification = record::Classification::from_u8(classification_val)?;

    // Metadata: convert Python dict to BTreeMap<String, serde_json::Value>
    // Preserves types: int→Number, float→Number, bool→Bool, None→Null, str→String
    let metadata: BTreeMap<String, serde_json::Value> =
        if let Some(meta_obj) = dict.get_item("metadata")? {
            if let Ok(meta_dict) = meta_obj.downcast::<PyDict>() {
                let mut map = BTreeMap::new();
                for (k, v) in meta_dict.iter() {
                    let key: String = k.extract()?;
                    let val = python_to_json_value(&v)?;
                    map.insert(key, val);
                }
                map
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

    let signature: Option<Vec<u8>> = dict
        .get_item("signature")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()?;

    let sphincs_signature: Option<Vec<u8>> = dict
        .get_item("sphincs_signature")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()?;

    let zk_proof: Option<Vec<u8>> = dict
        .get_item("zk_proof")?
        .and_then(|v| if v.is_none() { None } else { Some(v) })
        .map(|v| v.extract())
        .transpose()?;

    Ok(record::ValidationRecord {
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

fn record_to_dict(py: Python, rec: &record::ValidationRecord) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("id", &rec.id)?;
    dict.set_item("version", rec.version)?;
    dict.set_item("content_hash", PyBytes::new(py, &rec.content_hash))?;
    dict.set_item(
        "creator_public_key",
        PyBytes::new(py, &rec.creator_public_key),
    )?;
    dict.set_item("timestamp", rec.timestamp)?;
    dict.set_item("parents", &rec.parents)?;
    dict.set_item("classification", rec.classification as u8)?;

    let meta_dict = PyDict::new(py);
    for (k, v) in &rec.metadata {
        match v {
            serde_json::Value::Null => meta_dict.set_item(k, py.None())?,
            serde_json::Value::Bool(b) => meta_dict.set_item(k, *b)?,
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    meta_dict.set_item(k, i)?;
                } else if let Some(f) = n.as_f64() {
                    meta_dict.set_item(k, f)?;
                } else {
                    meta_dict.set_item(k, n.to_string())?;
                }
            }
            serde_json::Value::String(s) => meta_dict.set_item(k, s)?,
            other => meta_dict.set_item(k, other.to_string())?,
        }
    }
    dict.set_item("metadata", meta_dict)?;

    match &rec.signature {
        Some(s) => dict.set_item("signature", PyBytes::new(py, s))?,
        None => dict.set_item("signature", py.None())?,
    }
    match &rec.sphincs_signature {
        Some(s) => dict.set_item("sphincs_signature", PyBytes::new(py, s))?,
        None => dict.set_item("sphincs_signature", py.None())?,
    }
    match &rec.zk_proof {
        Some(z) => dict.set_item("zk_proof", PyBytes::new(py, z))?,
        None => dict.set_item("zk_proof", py.None())?,
    }

    Ok(dict.into())
}

/// Elara Runtime — Rust-powered fast lane for the Elara Protocol.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Crypto
    m.add_function(wrap_pyfunction!(py_dilithium3_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(py_dilithium3_sign, m)?)?;
    m.add_function(wrap_pyfunction!(py_dilithium3_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_sphincs_keygen, m)?)?;
    m.add_function(wrap_pyfunction!(py_sphincs_sign, m)?)?;
    m.add_function(wrap_pyfunction!(py_sphincs_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_sha3_256, m)?)?;
    m.add_function(wrap_pyfunction!(py_sha3_256_hex, m)?)?;
    m.add_function(wrap_pyfunction!(py_batch_verify, m)?)?;

    // UUID
    m.add_function(wrap_pyfunction!(py_uuid7, m)?)?;

    // Wire format
    m.add_function(wrap_pyfunction!(py_record_to_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(py_record_from_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(py_signable_bytes, m)?)?;

    Ok(())
}
