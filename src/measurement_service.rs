use crate::error::TappResult;
use attestation_agent::{AttestationAPIs, AttestationAgent};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub const ZGEL_DOMAIN: &str = "tapp.0g.com";

// Operation names for measurements
pub const OPERATION_NAME_START_APP: &str = "start_app";
pub const OPERATION_NAME_STOP_APP: &str = "stop_app";
pub const OPERATION_NAME_GET_APP_SECRET_KEY: &str = "get_app_secret_key";
pub const OPERATION_NAME_ADD_TO_WHITELIST: &str = "add_to_whitelist";
pub const OPERATION_NAME_REMOVE_FROM_WHITELIST: &str = "remove_from_whitelist";

pub struct MeasurementService {
    aa: Arc<Mutex<AttestationAgent>>,
}

impl MeasurementService {
    pub fn new(aa: Arc<Mutex<AttestationAgent>>) -> Self {
        Self { aa }
    }

    /// Extend runtime measurement for any operation
    pub async fn extend_measurement(&self, operation_name: &str, data: &str) -> TappResult<()> {
        self.aa
            .lock()
            .await
            .extend_runtime_measurement(ZGEL_DOMAIN, operation_name, data, None)
            .await?;

        info!(
            operation = %operation_name,
            "Runtime measurement extended"
        );

        Ok(())
    }

    /// Get TEE type
    pub async fn get_tee_type(&self) -> String {
        format!("{:?}", self.aa.lock().await.get_tee_type())
    }

    /// Get evidence
    pub async fn get_evidence(&self, report_data: &[u8]) -> TappResult<Vec<u8>> {
        let evidence = self.aa.lock().await.get_evidence(report_data).await?;
        Ok(evidence)
    }
}
