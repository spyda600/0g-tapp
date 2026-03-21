use async_trait::async_trait;
use sha2::{Sha384, Digest};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use super::{TeeProvider, TeeError, TeeType, AttestationEvidence, MeasurementRegister};

/// Software measurement accumulator for Nitro Enclaves.
///
/// Since Nitro PCRs are locked at enclave launch, this provides
/// equivalent runtime measurement semantics via a SHA384 hash chain.
/// The accumulated measurements are embedded in the attestation
/// document's `user_data` field (512 bytes max).
pub struct MeasurementAccumulator {
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
                "Invalid register index: {} (max 3)",
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
    /// 4 registers x 48 bytes = 192 bytes (fits in 512-byte limit).
    pub fn to_user_data(&self) -> [u8; 192] {
        let mut out = [0u8; 192];
        for (i, reg) in self.registers.iter().enumerate() {
            out[i * 48..(i + 1) * 48].copy_from_slice(reg);
        }
        out
    }

    /// Get a copy of all register values.
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
    pub fn new() -> Self {
        Self {
            accumulator: Mutex::new(MeasurementAccumulator::new()),
        }
    }
}

impl Default for NitroProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeeProvider for NitroProvider {
    async fn init(&self) -> Result<(), TeeError> {
        // Verify NSM device is available
        // In a real Nitro Enclave, /dev/nsm exists
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
        // Get accumulated measurements to embed in user_data
        let user_data = {
            let acc = self.accumulator.lock().map_err(|e| {
                TeeError::AttestationFailed(format!("Failed to lock accumulator: {}", e))
            })?;
            acc.to_user_data()
        };

        // In production, this would call the NSM API:
        //   let nsm_fd = nsm_driver::nsm_init();
        //   let request = nsm_driver::Request::Attestation {
        //       user_data: Some(user_data.to_vec()),
        //       nonce: Some(runtime_data.to_vec()),
        //       public_key: None,
        //   };
        //   let response = nsm_driver::nsm_process_request(nsm_fd, request);
        //
        // For now, we create a placeholder that shows the structure.
        // The actual NSM crate integration requires the aws-nitro-enclaves-nsm-api
        // crate which only works inside a real Nitro Enclave.

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Placeholder: In production, `raw` would be the CBOR-encoded
        // NSM attestation document signed by the Nitro hardware.
        let placeholder = serde_json::json!({
            "provider": "nitro",
            "note": "NSM attestation requires running inside a Nitro Enclave",
            "user_data": hex::encode(&user_data),
            "nonce": hex::encode(runtime_data),
            "timestamp": timestamp,
        });

        let raw = serde_json::to_vec(&placeholder).map_err(|e| {
            TeeError::AttestationFailed(format!("Serialization failed: {}", e))
        })?;

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
        // Other registers unchanged
        assert_eq!(acc.registers()[1], [0u8; 48]);
    }

    #[test]
    fn test_accumulator_hash_chain() {
        // Extending with A then B should differ from extending with B then A
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
    fn test_accumulator_to_user_data() {
        let mut acc = MeasurementAccumulator::new();
        acc.extend(0, b"test").unwrap();
        let user_data = acc.to_user_data();
        assert_eq!(user_data.len(), 192);
        // First 48 bytes should be non-zero
        assert_ne!(&user_data[0..48], &[0u8; 48]);
        // Remaining should be zero (registers 1-3 untouched)
        assert_eq!(&user_data[48..192], &[0u8; 144]);
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
        provider.extend_measurement(2, b"start_app:test").await.unwrap();
        let measurements = provider.get_measurements().await.unwrap();
        assert_eq!(measurements.len(), 4);
        assert_ne!(measurements[2].value, [0u8; 48]);
        assert_eq!(measurements[0].value, [0u8; 48]);
    }
}
