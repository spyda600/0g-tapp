use async_trait::async_trait;
use sha2::{Digest, Sha384};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use super::{AttestationEvidence, MeasurementRegister, TeeError, TeeProvider, TeeType};

/// User data format version. Embedded as the first byte of the packed
/// user_data so that verifiers can distinguish layout changes.
const USER_DATA_VERSION: u8 = 1;

/// Software measurement accumulator for Nitro Enclaves.
///
/// Since Nitro PCRs are locked at enclave launch, this provides
/// equivalent runtime measurement semantics via a SHA384 hash chain.
/// The accumulated measurements are embedded in the attestation
/// document's `user_data` field (512 bytes max).
///
/// Layout (v1): [version: 1 byte] [reg0: 48 bytes] [reg1: 48] [reg2: 48] [reg3: 48] = 193 bytes
pub(crate) struct MeasurementAccumulator {
    registers: [[u8; 48]; 4], // 4 registers x 48 bytes (SHA384)
}

impl MeasurementAccumulator {
    pub fn new() -> Self {
        Self {
            registers: [[0u8; 48]; 4],
        }
    }

    /// Extend a measurement register.
    /// new_value = SHA384(current_value || data)
    pub fn extend(&mut self, register: u32, data: &[u8]) -> Result<(), TeeError> {
        if register >= 4 {
            return Err(TeeError::MeasurementFailed(format!(
                "Invalid Nitro software register index: {} (valid: 0-3)",
                register
            )));
        }

        let mut hasher = Sha384::new();
        hasher.update(&self.registers[register as usize]);
        hasher.update(data);
        let result = hasher.finalize();
        self.registers[register as usize].copy_from_slice(&result);
        Ok(())
    }

    /// Pack all register values into a byte array suitable for
    /// the NSM attestation document's `user_data` field.
    /// Format v1: [version(1)] [reg0(48)] [reg1(48)] [reg2(48)] [reg3(48)] = 193 bytes
    /// Fits well within the 512-byte user_data limit.
    pub fn to_user_data(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 4 * 48);
        out.push(USER_DATA_VERSION);
        for reg in &self.registers {
            out.extend_from_slice(reg);
        }
        // NSM user_data field has a 512-byte hard limit
        assert!(
            out.len() <= 512,
            "user_data exceeds NSM 512-byte limit: {} bytes",
            out.len()
        );
        out
    }

    /// Get a reference to all register values.
    pub fn registers(&self) -> &[[u8; 48]; 4] {
        &self.registers
    }
}

impl Default for MeasurementAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// AWS Nitro Enclave TEE provider.
///
/// Uses the Nitro Security Module (NSM) API for attestation and
/// a software MeasurementAccumulator for runtime measurements.
///
/// When running inside a Nitro Enclave:
/// - Attestation documents are generated via the NSM device at /dev/nsm
/// - Runtime measurements are accumulated in software and embedded
///   in the attestation document's `user_data` field
/// - PCR0-PCR8 provide static enclave image integrity
/// - `user_data` provides runtime behavior auditability
pub struct NitroProvider {
    accumulator: Mutex<MeasurementAccumulator>,
}

impl NitroProvider {
    /// Create a new Nitro provider. Restricted to crate-internal use
    /// to prevent external code from constructing fresh instances
    /// (which would reset the measurement accumulator).
    pub(crate) fn new() -> Self {
        Self {
            accumulator: Mutex::new(MeasurementAccumulator::new()),
        }
    }

    /// Generate an attestation document via the Nitro Security Module.
    ///
    /// Uses the `aws-nitro-enclaves-nsm-api` crate which communicates with
    /// `/dev/nsm` via ioctl. The returned COSE Sign1 document is signed by
    /// AWS Nitro Attestation PKI and contains PCRs, user_data, and nonce.
    #[cfg(feature = "nitro")]
    pub(crate) fn nsm_get_attestation_doc(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TeeError> {
        use aws_nitro_enclaves_nsm_api::api::{Request, Response};
        use aws_nitro_enclaves_nsm_api::driver;

        let nsm_fd = driver::nsm_init();
        if nsm_fd < 0 {
            return Err(TeeError::AttestationFailed(
                "Failed to initialize NSM device".to_string(),
            ));
        }

        let request = Request::Attestation {
            user_data: if user_data.is_empty() {
                None
            } else {
                Some(user_data.to_vec().into())
            },
            nonce: if nonce.is_empty() {
                None
            } else {
                Some(nonce.to_vec().into())
            },
            public_key: None,
        };

        let response = driver::nsm_process_request(nsm_fd, request);
        driver::nsm_exit(nsm_fd);

        match response {
            Response::Attestation { document } => {
                info!(
                    doc_len = document.len(),
                    "NSM attestation document generated"
                );
                Ok(document)
            }
            Response::Error(err) => {
                warn!("NSM attestation error (internal): {:?}", err);
                Err(TeeError::AttestationFailed(
                    "Attestation document generation failed".to_string(),
                ))
            }
            other => {
                warn!("Unexpected NSM response (internal): {:?}", other);
                Err(TeeError::AttestationFailed(
                    "Attestation document generation failed".to_string(),
                ))
            }
        }
    }

    #[cfg(not(feature = "nitro"))]
    pub(crate) fn nsm_get_attestation_doc(_user_data: &[u8], _nonce: &[u8]) -> Result<Vec<u8>, TeeError> {
        Err(TeeError::AttestationFailed(
            "NSM attestation requires the 'nitro' feature and a Nitro Enclave environment".to_string(),
        ))
    }
}

// NOTE: No Default impl — NitroProvider::new() is pub(crate) to prevent
// external code from constructing fresh instances (which would zero the
// measurement accumulator). A Default impl would bypass this restriction.

#[async_trait]
impl TeeProvider for NitroProvider {
    async fn init(&self) -> Result<(), TeeError> {
        #[cfg(target_os = "linux")]
        {
            if !std::path::Path::new("/dev/nsm").exists() {
                return Err(TeeError::NotAvailable);
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            return Err(TeeError::NotAvailable);
        }

        info!("Nitro provider initialized — NSM device available");
        Ok(())
    }

    fn tee_type(&self) -> TeeType {
        TeeType::Nitro
    }

    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError> {
        // Hold the lock across the entire attestation operation to prevent
        // TOCTOU races where extend_measurement could mutate registers
        // between reading user_data and generating the attestation doc.
        // The lock is NOT dropped until after nsm_get_attestation_doc returns.
        let acc = self.accumulator.lock().map_err(|e| {
            TeeError::AttestationFailed(format!("Failed to lock accumulator: {}", e))
        })?;
        let user_data = acc.to_user_data();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let raw = Self::nsm_get_attestation_doc(&user_data, runtime_data)?;

        // Lock is released here (end of scope for `acc`)
        drop(acc);

        Ok(AttestationEvidence {
            raw,
            tee_type: TeeType::Nitro,
            timestamp,
        })
    }

    async fn extend_measurement(
        &self,
        register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError> {
        let mut acc = self.accumulator.lock().map_err(|e| {
            TeeError::MeasurementFailed(format!("Failed to lock accumulator: {}", e))
        })?;
        acc.extend(register_index, data)
    }

    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError> {
        let acc = self.accumulator.lock().map_err(|e| {
            TeeError::MeasurementFailed(format!("Failed to lock accumulator: {}", e))
        })?;

        Ok(acc
            .registers()
            .iter()
            .enumerate()
            .map(|(i, value)| MeasurementRegister {
                index: i as u32,
                value: *value,
                description: format!("Nitro software measurement register {}", i),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_new() {
        let acc = MeasurementAccumulator::new();
        for reg in acc.registers().iter() {
            assert_eq!(*reg, [0u8; 48]);
        }
    }

    #[test]
    fn test_accumulator_extend() {
        let mut acc = MeasurementAccumulator::new();
        acc.extend(0, b"test data").unwrap();
        assert_ne!(acc.registers()[0], [0u8; 48]);
        assert_eq!(acc.registers()[1], [0u8; 48]);
    }

    #[test]
    fn test_accumulator_hash_chain() {
        let mut acc1 = MeasurementAccumulator::new();
        acc1.extend(0, b"data_a").unwrap();
        acc1.extend(0, b"data_b").unwrap();

        let mut acc2 = MeasurementAccumulator::new();
        acc2.extend(0, b"data_b").unwrap();
        acc2.extend(0, b"data_a").unwrap();

        assert_ne!(acc1.registers()[0], acc2.registers()[0]);
    }

    #[test]
    fn test_accumulator_invalid_register() {
        let mut acc = MeasurementAccumulator::new();
        assert!(acc.extend(4, b"data").is_err());
        assert!(acc.extend(99, b"data").is_err());
    }

    #[test]
    fn test_accumulator_to_user_data_versioned() {
        let mut acc = MeasurementAccumulator::new();
        acc.extend(0, b"test").unwrap();
        let user_data = acc.to_user_data();
        // Version byte + 4 * 48 bytes = 193
        assert_eq!(user_data.len(), 193);
        assert_eq!(user_data[0], USER_DATA_VERSION);
        // First register (bytes 1..49) should be non-zero
        assert_ne!(&user_data[1..49], &[0u8; 48]);
        // Remaining registers should be zero
        assert_eq!(&user_data[49..193], &[0u8; 144]);
    }

    #[test]
    fn test_accumulator_deterministic() {
        let mut acc1 = MeasurementAccumulator::new();
        let mut acc2 = MeasurementAccumulator::new();
        acc1.extend(2, b"start_app:app123").unwrap();
        acc2.extend(2, b"start_app:app123").unwrap();
        assert_eq!(acc1.registers()[2], acc2.registers()[2]);
    }

    #[tokio::test]
    async fn test_nitro_provider_tee_type() {
        let provider = NitroProvider::new();
        assert_eq!(provider.tee_type(), TeeType::Nitro);
    }

    #[tokio::test]
    async fn test_nitro_provider_extend_and_get() {
        let provider = NitroProvider::new();
        provider
            .extend_measurement(2, b"start_app:test")
            .await
            .unwrap();
        let measurements = provider.get_measurements().await.unwrap();
        assert_eq!(measurements.len(), 4);
        assert_ne!(measurements[2].value, [0u8; 48]);
        assert_eq!(measurements[0].value, [0u8; 48]);
    }
}
