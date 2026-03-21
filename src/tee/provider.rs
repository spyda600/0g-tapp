use async_trait::async_trait;

use super::error::TeeError;
use super::types::{AttestationEvidence, MeasurementRegister, TeeType};

/// Core trait that all TEE backends must implement.
///
/// This trait abstracts TEE-specific operations (attestation, measurement)
/// so that TAPP can run on different TEE platforms (TDX, Nitro, simulation)
/// without changing core logic.
#[async_trait]
pub trait TeeProvider: Send + Sync + 'static {
    /// Initialize the TEE environment.
    async fn init(&self) -> Result<(), TeeError>;

    /// Get the TEE type identifier.
    fn tee_type(&self) -> TeeType;

    /// Generate attestation evidence with the given runtime data bound into it.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError>;

    /// Extend a runtime measurement register.
    /// Semantics: register = SHA384(register || data)
    async fn extend_measurement(
        &self,
        register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError>;

    /// Get current measurement register values.
    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError>;
}
