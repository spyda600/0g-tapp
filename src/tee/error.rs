use thiserror::Error;

#[derive(Error, Debug)]
pub enum TeeError {
    #[error("TEE hardware not available")]
    NotAvailable,

    #[error("TEE initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Measurement operation failed: {0}")]
    MeasurementFailed(String),

    #[error("Provider-specific error: {0}")]
    ProviderSpecific(Box<dyn std::error::Error + Send + Sync>),
}
