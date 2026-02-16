//! Parallel batch sign/verify via rayon.

use rayon::prelude::*;

use crate::crypto::pqc::{dilithium3_sign, dilithium3_verify};
use crate::errors::Result;

/// A verification job: (message, signature, public_key).
pub struct VerifyJob<'a> {
    pub message: &'a [u8],
    pub signature: &'a [u8],
    pub public_key: &'a [u8],
}

/// Verify multiple Dilithium3 signatures in parallel.
/// Returns a Vec of bools, one per job.
pub fn batch_verify(jobs: &[VerifyJob]) -> Vec<bool> {
    jobs.par_iter()
        .map(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
        .collect()
}

/// Verify multiple signatures in parallel, returning true only if ALL pass.
pub fn batch_verify_all(jobs: &[VerifyJob]) -> bool {
    jobs.par_iter()
        .all(|job| dilithium3_verify(job.message, job.signature, job.public_key).unwrap_or(false))
}

/// A signing job: (message, secret_key).
pub struct SignJob<'a> {
    pub message: &'a [u8],
    pub secret_key: &'a [u8],
}

/// Sign multiple messages in parallel with Dilithium3.
/// Returns Vec<Result<Vec<u8>>>.
pub fn batch_sign(jobs: &[SignJob]) -> Vec<Result<Vec<u8>>> {
    jobs.par_iter()
        .map(|job| dilithium3_sign(job.message, job.secret_key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pqc::dilithium3_keygen;

    #[test]
    fn test_batch_verify_all_valid() {
        let kp = dilithium3_keygen().unwrap();
        let messages: Vec<Vec<u8>> = (0..10).map(|i| format!("msg-{i}").into_bytes()).collect();
        let sigs: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| dilithium3_sign(m, &kp.secret_key).unwrap())
            .collect();

        let jobs: Vec<VerifyJob> = messages
            .iter()
            .zip(sigs.iter())
            .map(|(m, s)| VerifyJob {
                message: m,
                signature: s,
                public_key: &kp.public_key,
            })
            .collect();

        let results = batch_verify(&jobs);
        assert!(results.iter().all(|&r| r));
        assert!(batch_verify_all(&jobs));
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let kp = dilithium3_keygen().unwrap();
        let kp2 = dilithium3_keygen().unwrap();
        let msg = b"test message";
        let sig_valid = dilithium3_sign(msg, &kp.secret_key).unwrap();
        let sig_invalid = dilithium3_sign(msg, &kp2.secret_key).unwrap();

        let jobs = vec![
            VerifyJob {
                message: msg,
                signature: &sig_valid,
                public_key: &kp.public_key,
            },
            VerifyJob {
                message: msg,
                signature: &sig_invalid,
                public_key: &kp.public_key, // wrong key for this sig
            },
        ];

        let results = batch_verify(&jobs);
        assert!(results[0]);
        assert!(!results[1]);
        assert!(!batch_verify_all(&jobs));
    }

    #[test]
    fn test_batch_sign() {
        let kp = dilithium3_keygen().unwrap();
        let messages: Vec<Vec<u8>> = (0..5).map(|i| format!("sign-{i}").into_bytes()).collect();
        let jobs: Vec<SignJob> = messages
            .iter()
            .map(|m| SignJob {
                message: m,
                secret_key: &kp.secret_key,
            })
            .collect();

        let sigs = batch_sign(&jobs);
        assert_eq!(sigs.len(), 5);
        for (i, sig_result) in sigs.iter().enumerate() {
            let sig = sig_result.as_ref().unwrap();
            assert!(dilithium3_verify(&messages[i], sig, &kp.public_key).unwrap());
        }
    }
}
