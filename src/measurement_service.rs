use crate::error::TappResult;
use crate::tee::TeeProvider;
use std::sync::Arc;
use tracing::info;

pub const ZGEL_DOMAIN: &str = "tapp.0g.com";

// Operation names for measurements
pub const OPERATION_NAME_START_APP: &str = "start_app";
pub const OPERATION_NAME_STOP_APP: &str = "stop_app";
pub const OPERATION_NAME_GET_APP_SECRET_KEY: &str = "get_app_secret_key";
pub const OPERATION_NAME_ADD_TO_WHITELIST: &str = "add_to_whitelist";
pub const OPERATION_NAME_REMOVE_FROM_WHITELIST: &str = "remove_from_whitelist";
pub const OPERATION_NAME_WITHDRAW_BALANCE: &str = "withdraw_balance";
pub const OPERATION_NAME_DOCKER_LOGIN: &str = "docker_login";
pub const OPERATION_NAME_DOCKER_LOGOUT: &str = "docker_logout";
pub const OPERATION_NAME_STOP_SERVICE: &str = "stop_service";
pub const OPERATION_NAME_START_SERVICE: &str = "start_service";

pub struct MeasurementService {
    provider: Arc<dyn TeeProvider>,
}

impl MeasurementService {
    pub fn new(provider: Arc<dyn TeeProvider>) -> Self {
        Self { provider }
    }

    /// Extend runtime measurement for any operation
    pub async fn extend_measurement(&self, operation_name: &str, data: &str) -> TappResult<()> {
        // Use register 2 for most operations, register 3 for key/balance operations
        let register = match operation_name {
            "get_app_secret_key" | "withdraw_balance" => 3,
            _ => 2,
        };

        let measurement_data = format!("{}:{}:{}", ZGEL_DOMAIN, operation_name, data);
        self.provider
            .extend_measurement(register, measurement_data.as_bytes())
            .await
            .map_err(|e| crate::error::TappError::Internal(format!("Measurement failed: {}", e)))?;

        info!(
            operation = %operation_name,
            register = register,
            "Runtime measurement extended"
        );

        Ok(())
    }

    /// Get TEE type
    pub async fn get_tee_type(&self) -> String {
        self.provider.tee_type().to_string()
    }

    /// Get evidence
    pub async fn get_evidence(&self, report_data: &[u8]) -> TappResult<Vec<u8>> {
        let evidence = self
            .provider
            .get_evidence(report_data)
            .await
            .map_err(|e| {
                crate::error::TappError::Internal(format!("Evidence generation failed: {}", e))
            })?;
        Ok(evidence.raw)
    }
}
