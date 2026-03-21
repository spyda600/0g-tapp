use async_trait::async_trait;
use thiserror::Error;

/// Errors that can occur during TEE operations.
#[derive(Error, Debug)]
pub enum TeeError {
    #[error("Initialization failed: {0}")]
    InitFailed(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Measurement failed: {0}")]
    MeasurementFailed(String),
}

/// The type of TEE environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeType {
    /// Intel TDX (Trust Domain Extensions)
    Tdx,
    /// Intel SGX (Software Guard Extensions)
    Sgx,
    /// AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
    SevSnp,
    /// Arm CCA (Confidential Compute Architecture)
    Cca,
    /// Simulation mode for development and testing
    Simulation,
}

/// Attestation evidence produced by a TEE.
#[derive(Debug, Clone)]
pub struct AttestationEvidence {
    /// Raw attestation document bytes.
    pub raw: Vec<u8>,
    /// The TEE type that produced this evidence.
    pub tee_type: TeeType,
    /// Unix timestamp when the evidence was generated.
    pub timestamp: u64,
}

/// A single measurement register value.
#[derive(Debug, Clone)]
pub struct MeasurementRegister {
    /// Register index (e.g., RTMR index for TDX).
    pub index: u32,
    /// The 48-byte register value (SHA-384 sized).
    pub value: [u8; 48],
    /// Human-readable description of what this register measures.
    pub description: String,
}

/// Trait abstracting TEE hardware operations.
///
/// Implementations of this trait provide attestation and measurement
/// capabilities for different TEE environments (TDX, SGX, simulation, etc.).
#[async_trait]
pub trait TeeProvider: Send + Sync {
    /// Initialize the TEE provider.
    async fn init(&self) -> Result<(), TeeError>;

    /// Return the type of TEE this provider implements.
    fn tee_type(&self) -> TeeType;

    /// Generate attestation evidence, binding the given `runtime_data`.
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError>;

    /// Extend a measurement register with additional data.
    ///
    /// The semantics follow TDX RTMR extend: `register = SHA384(register || data)`.
    async fn extend_measurement(
        &self,
        register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError>;

    /// Read all measurement registers.
    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError>;
}
