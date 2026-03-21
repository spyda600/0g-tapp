use super::provider::TeeProvider;
use super::types::{TeeError, TeeEvidence, TeeType};
use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use std::sync::Arc;
use tokio::sync::Mutex;

/// TDX-based TEE provider using the AttestationAgent from guest-components.
pub struct TdxProvider {
    aa: Arc<Mutex<AttestationAgent>>,
}

impl TdxProvider {
    /// Create a new TDX provider.
    ///
    /// `aa_config_path` is an optional path to the attestation-agent config file.
    pub fn new(aa_config_path: Option<&str>) -> Result<Self, TeeError> {
        // Ensure AA config file exists if path is provided
        if let Some(path) = aa_config_path {
            crate::boot::BootService::ensure_aa_config(path)
                .map_err(|e| TeeError::InitializationFailed(format!("AA config error: {}", e)))?;
        }

        let aa = AttestationAgent::new(aa_config_path)
            .map_err(|e| TeeError::InitializationFailed(format!("AttestationAgent: {}", e)))?;

        Ok(Self {
            aa: Arc::new(Mutex::new(aa)),
        })
    }
}

#[async_trait]
impl TeeProvider for TdxProvider {
    async fn init(&self) -> Result<(), TeeError> {
        self.aa
            .lock()
            .await
            .init()
            .await
            .map_err(|e| TeeError::InitializationFailed(format!("AA init: {}", e)))
    }

    fn tee_type(&self) -> TeeType {
        TeeType::Tdx
    }

    async fn get_evidence(&self, report_data: &[u8]) -> Result<TeeEvidence, TeeError> {
        let raw = self
            .aa
            .lock()
            .await
            .get_evidence(report_data)
            .await
            .map_err(|e| TeeError::EvidenceGenerationFailed(e.to_string()))?;

        Ok(TeeEvidence {
            raw,
            tee_type: TeeType::Tdx,
        })
    }

    async fn extend_measurement(&self, _register: u32, data: &[u8]) -> Result<(), TeeError> {
        let domain = super::ZGEL_DOMAIN;
        // Parse measurement data back: "domain:operation:data"
        let data_str = String::from_utf8_lossy(data);
        let parts: Vec<&str> = data_str.splitn(3, ':').collect();
        let (operation, op_data) = if parts.len() == 3 {
            (parts[1], parts[2])
        } else {
            ("unknown", data_str.as_ref())
        };

        self.aa
            .lock()
            .await
            .extend_runtime_measurement(domain, operation, op_data, None)
            .await
            .map_err(|e| TeeError::MeasurementFailed(e.to_string()))
    }
}
