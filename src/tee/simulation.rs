use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha384};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use super::{AttestationEvidence, MeasurementRegister, TeeError, TeeProvider, TeeType};

/// Simulation TEE provider for development and testing.
///
/// This provider implements the TeeProvider trait with deterministic,
/// non-cryptographic behavior. Attestation documents are clearly marked
/// as simulated and cannot be confused with real TEE attestations.
pub struct SimulationProvider {
    registers: Mutex<[[u8; 48]; 4]>,
}

impl SimulationProvider {
    pub fn new() -> Self {
        warn!("Using SIMULATION TEE provider -- NOT suitable for production");
        Self {
            registers: Mutex::new([[0u8; 48]; 4]),
        }
    }
}

#[async_trait]
impl TeeProvider for SimulationProvider {
    async fn init(&self) -> Result<(), TeeError> {
        warn!("SimulationProvider initialized -- no real TEE hardware");
        Ok(())
    }

    fn tee_type(&self) -> TeeType {
        TeeType::Simulation
    }

    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError> {
        // Create a clearly-marked simulation attestation document
        let registers = self.registers.lock().map_err(|e| {
            TeeError::AttestationFailed(format!("Failed to lock registers: {}", e))
        })?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let doc = serde_json::json!({
            "simulation": true,
            "tee_type": "simulation",
            "timestamp": timestamp,
            "runtime_data": base64::engine::general_purpose::STANDARD.encode(runtime_data),
            "measurement_registers": registers.iter().enumerate().map(|(i, r)| {
                serde_json::json!({
                    "index": i,
                    "value": hex::encode(r),
                })
            }).collect::<Vec<_>>(),
            "warning": "THIS IS A SIMULATED ATTESTATION - NOT FROM REAL TEE HARDWARE"
        });

        let raw = serde_json::to_vec(&doc).map_err(|e| {
            TeeError::AttestationFailed(format!("Failed to serialize attestation: {}", e))
        })?;

        Ok(AttestationEvidence {
            raw,
            tee_type: TeeType::Simulation,
            timestamp,
        })
    }

    async fn extend_measurement(
        &self,
        register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError> {
        if register_index >= 4 {
            return Err(TeeError::MeasurementFailed(format!(
                "Invalid register index: {} (max 3)",
                register_index
            )));
        }

        let mut registers = self.registers.lock().map_err(|e| {
            TeeError::MeasurementFailed(format!("Failed to lock registers: {}", e))
        })?;

        // SHA384(current_value || data) -- same semantics as real RTMR extend
        let mut hasher = Sha384::new();
        hasher.update(&registers[register_index as usize]);
        hasher.update(data);
        let result = hasher.finalize();
        registers[register_index as usize].copy_from_slice(&result);

        Ok(())
    }

    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError> {
        let registers = self.registers.lock().map_err(|e| {
            TeeError::MeasurementFailed(format!("Failed to lock registers: {}", e))
        })?;

        Ok(registers
            .iter()
            .enumerate()
            .map(|(i, value)| MeasurementRegister {
                index: i as u32,
                value: *value,
                description: format!("Simulation register {}", i),
            })
            .collect())
    }
}

impl Default for SimulationProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn create_provider() -> SimulationProvider {
        SimulationProvider {
            registers: Mutex::new([[0u8; 48]; 4]),
        }
    }

    #[tokio::test]
    async fn test_init() {
        let provider = create_provider();
        assert!(provider.init().await.is_ok());
    }

    #[tokio::test]
    async fn test_tee_type() {
        let provider = create_provider();
        assert_eq!(provider.tee_type(), TeeType::Simulation);
    }

    #[tokio::test]
    async fn test_evidence_is_simulation_marked() {
        let provider = create_provider();
        let evidence = provider.get_evidence(b"test-data").await.unwrap();

        assert_eq!(evidence.tee_type, TeeType::Simulation);

        let doc: serde_json::Value = serde_json::from_slice(&evidence.raw).unwrap();
        assert_eq!(doc["simulation"], serde_json::json!(true));
        assert_eq!(doc["tee_type"], serde_json::json!("simulation"));
        assert!(doc["warning"].as_str().unwrap().contains("SIMULATED"));

        // Verify runtime_data is base64-encoded in the document
        let encoded = doc["runtime_data"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(decoded, b"test-data");
    }

    #[tokio::test]
    async fn test_extend_measurement() {
        let provider = create_provider();

        let before = provider.get_measurements().await.unwrap();
        assert_eq!(before[0].value, [0u8; 48]);

        provider.extend_measurement(0, b"some data").await.unwrap();

        let after = provider.get_measurements().await.unwrap();
        assert_ne!(after[0].value, [0u8; 48], "register should change after extend");
        // Other registers remain untouched
        assert_eq!(after[1].value, [0u8; 48]);
    }

    #[tokio::test]
    async fn test_measurement_chain() {
        // Extending twice should differ from extending once with combined data
        // because extend does SHA384(current || data), creating a hash chain.
        let provider_a = create_provider();
        provider_a.extend_measurement(0, b"first").await.unwrap();
        provider_a.extend_measurement(0, b"second").await.unwrap();
        let chain_value = provider_a.get_measurements().await.unwrap()[0].value;

        let provider_b = create_provider();
        provider_b
            .extend_measurement(0, b"firstsecond")
            .await
            .unwrap();
        let combined_value = provider_b.get_measurements().await.unwrap()[0].value;

        assert_ne!(
            chain_value, combined_value,
            "hash chain should differ from single extend with concatenated data"
        );
    }

    #[tokio::test]
    async fn test_invalid_register() {
        let provider = create_provider();
        let result = provider.extend_measurement(4, b"data").await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            TeeError::MeasurementFailed(msg) => {
                assert!(msg.contains("Invalid register index"));
            }
            _ => panic!("Expected MeasurementFailed error"),
        }
    }
}
