//! Error types for the Elara Runtime.

use pyo3::exceptions::PyValueError;
use pyo3::PyErr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ElaraError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Wire format error: {0}")]
    Wire(String),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("Duplicate record: {0}")]
    DuplicateRecord(String),

    #[error("Missing parent: {0}")]
    MissingParent(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Address error: {0}")]
    Address(String),

    #[error("DAG error: {0}")]
    Dag(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, ElaraError>;

impl From<ElaraError> for PyErr {
    fn from(err: ElaraError) -> PyErr {
        PyValueError::new_err(err.to_string())
    }
}
