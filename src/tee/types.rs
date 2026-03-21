use std::fmt;

/// Supported TEE types
#[derive(Debug, Clone, PartialEq)]
pub enum TeeType {
    Tdx,
    Nitro,
    Simulation,
}

impl fmt::Display for TeeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TeeType::Tdx => write!(f, "TDX"),
            TeeType::Nitro => write!(f, "Nitro"),
            TeeType::Simulation => write!(f, "Simulation"),
        }
    }
}

/// Evidence returned from a TEE provider
#[derive(Debug, Clone)]
pub struct TeeEvidence {
    /// Raw evidence bytes
    pub raw: Vec<u8>,
    /// TEE type that produced this evidence
    pub tee_type: TeeType,
}

/// Errors from TEE operations
#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("TEE initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Evidence generation failed: {0}")]
    EvidenceGenerationFailed(String),

    #[error("Measurement extension failed: {0}")]
    MeasurementFailed(String),

    #[error("TEE not supported: {0}")]
    NotSupported(String),
}
