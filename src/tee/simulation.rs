use super::provider::TeeProvider;
use super::types::{TeeError, TeeEvidence, TeeType};
use async_trait::async_trait;
use tracing::{debug, warn};

/// Simulation TEE provider for development and testing without real TEE hardware.
///
/// All operations succeed but produce dummy data. Measurements are logged but
/// not persisted to any hardware register.
pub struct SimulationProvider;

impl SimulationProvider {
    pub fn new() -> Self {
        warn!("Using SIMULATION TEE provider — no real attestation available");
        Self
    }
}

#[async_trait]
impl TeeProvider for SimulationProvider {
    async fn init(&self) -> Result<(), TeeError> {
        debug!("Simulation TEE provider initialized (no-op)");
        Ok(())
    }

    fn tee_type(&self) -> TeeType {
        TeeType::Simulation
    }

    async fn get_evidence(&self, report_data: &[u8]) -> Result<TeeEvidence, TeeError> {
        debug!(
            report_data_len = report_data.len(),
            "Simulation: generating dummy evidence"
        );
        // Return a clearly-fake evidence blob
        let mut raw = b"SIMULATION_EVIDENCE:".to_vec();
        raw.extend_from_slice(report_data);
        Ok(TeeEvidence {
            raw,
            tee_type: TeeType::Simulation,
        })
    }

    async fn extend_measurement(&self, register: u32, data: &[u8]) -> Result<(), TeeError> {
        debug!(
            register = register,
            data_len = data.len(),
            "Simulation: extending measurement (no-op)"
        );
        Ok(())
    }
}
