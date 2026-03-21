use async_trait::async_trait;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::info;

use super::{TeeProvider, TeeError, TeeType, AttestationEvidence, MeasurementRegister};

/// The measurement domain used for RTMR extensions
const ZGEL_DOMAIN: &str = "tapp.0g.com";

/// TDX TEE provider — wraps the existing attestation-agent for Alibaba Cloud TDX.
pub struct TdxProvider {
    aa: Arc<Mutex<AttestationAgent>>,
}

impl TdxProvider {
    /// Create a new TDX provider.
    ///
    /// `aa_config_path` is the optional path to the attestation-agent config file.
    pub fn new(aa_config_path: Option<&str>) -> Result<Self, TeeError> {
        let aa = AttestationAgent::new(aa_config_path)
            .map_err(|e| TeeError::InitializationFailed(format!("Failed to create AttestationAgent: {}", e)))?;

        Ok(Self {
            aa: Arc::new(Mutex::new(aa)),
        })
    }

    /// Get a reference to the underlying AttestationAgent.
    /// This is provided for backward compatibility during migration.
    pub fn attestation_agent(&self) -> &Arc<Mutex<AttestationAgent>> {
        &self.aa
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
            .map_err(|e| TeeError::InitializationFailed(format!("AttestationAgent init failed: {}", e)))?;

        let tee_type = self.aa.lock().await.get_tee_type();
        info!("TDX provider initialized, TEE type: {:?}", tee_type);
        Ok(())
    }

    fn tee_type(&self) -> TeeType {
        TeeType::Tdx
    }

    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError> {
        let evidence = self.aa
            .lock()
            .await
            .get_evidence(runtime_data)
            .await
            .map_err(|e| TeeError::AttestationFailed(format!("Failed to get TDX evidence: {}", e)))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(AttestationEvidence {
            raw: evidence,
            tee_type: TeeType::Tdx,
            timestamp,
        })
    }

    async fn extend_measurement(
        &self,
        _register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError> {
        // The attestation-agent's extend_runtime_measurement API takes string data
        // and handles register selection internally based on domain/operation.
        // We hex-encode binary data to avoid lossy UTF-8 conversion which could
        // silently corrupt measurement inputs (e.g., raw hash digests).
        let data_str = hex::encode(data);

        // Note: The AA internally determines which RTMR register to use.
        // The register_index parameter is ignored for TDX because the AA
        // maps domain+operation to registers. For callers that need explicit
        // register control, use Nitro or Simulation providers.
        self.aa
            .lock()
            .await
            .extend_runtime_measurement(
                ZGEL_DOMAIN,
                "measurement",
                &data_str,
                None,
            )
            .await
            .map_err(|e| TeeError::MeasurementFailed(format!("RTMR extend failed: {}", e)))?;

        Ok(())
    }

    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError> {
        // TDX RTMR values are not directly readable via attestation-agent API.
        // Return empty — the actual RTMR values are included in attestation evidence.
        Ok(vec![])
    }
}
