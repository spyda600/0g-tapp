use super::types::{TeeError, TeeEvidence, TeeType};
use async_trait::async_trait;

/// Trait abstracting TEE operations across different hardware providers.
///
/// Implementations exist for TDX (via AttestationAgent), AWS Nitro Enclaves,
/// and a simulation provider for development without TEE hardware.
#[async_trait]
pub trait TeeProvider: Send + Sync {
    /// Initialize the TEE provider (e.g., connect to hardware, load keys).
    async fn init(&self) -> Result<(), TeeError>;

    /// Return the TEE type this provider represents.
    fn tee_type(&self) -> TeeType;

    /// Generate attestation evidence with the given report data.
    async fn get_evidence(&self, report_data: &[u8]) -> Result<TeeEvidence, TeeError>;

    /// Extend a runtime measurement register.
    ///
    /// - `register`: The RTMR / PCR index to extend (e.g., 2 or 3).
    /// - `data`: The measurement data to hash into the register.
    async fn extend_measurement(&self, register: u32, data: &[u8]) -> Result<(), TeeError>;
}
