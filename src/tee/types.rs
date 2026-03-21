use serde::{Deserialize, Serialize};

/// TEE type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeType {
    Tdx,
    Nitro,
    Simulation,
}

impl std::fmt::Display for TeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeType::Tdx => write!(f, "tdx"),
            TeeType::Nitro => write!(f, "nitro"),
            TeeType::Simulation => write!(f, "simulation"),
        }
    }
}

/// Attestation evidence from a TEE
pub struct AttestationEvidence {
    pub raw: Vec<u8>,
    pub tee_type: TeeType,
    pub timestamp: u64,
}

/// A single measurement register value
pub struct MeasurementRegister {
    pub index: u32,
    pub value: [u8; 48], // SHA384
    pub description: String,
}
