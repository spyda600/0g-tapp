pub mod app_key;
pub mod auth_layer;
pub mod boot;
pub mod config;
pub mod error;
pub mod measurement_service;
pub mod nonce_manager;
pub mod permission;
pub mod service_monitor;
pub mod signature_auth;
pub mod task_manager;
pub mod utils;
pub use boot::BootService;
pub use config::TappConfig;
pub use error::{TappError, TappResult};
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{error, info};

// Re-export generated protobuf types
pub mod proto {
    tonic::include_proto!("tapp_service");
}

// // Re-export common types
pub use proto::{
    tapp_service_client::TappServiceClient,
    tapp_service_server::{TappService, TappServiceServer},
    *,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

pub struct TappServiceImpl {
    pub config: TappConfig,
    pub boot_service: Arc<BootService>,
    pub app_key_service: app_key::AppKeyService,
    pub nonce_manager: nonce_manager::NonceManager,
    pub logs_service: service_monitor::logs::LogsService,
    pub permission_manager: Option<Arc<permission::PermissionManager>>,
    pub measurement_service: Arc<measurement_service::MeasurementService>,
}

impl TappServiceImpl {
    /// Check if an IP address is allowed to access sensitive operations
    /// Allows: localhost (IPv4/IPv6) and Docker bridge networks
    fn is_allowed_local_access(ip: std::net::IpAddr) -> bool {
        // 1. Check if it's loopback
        if ip.is_loopback() {
            return true;
        }

        // 2. Check if it's in Docker network ranges
        if let std::net::IpAddr::V4(ipv4) = ip {
            let octets = ipv4.octets();

            // Docker default bridge network: 172.17.0.0/16
            if octets[0] == 172 && octets[1] == 17 {
                return true;
            }

            // Docker custom bridge networks: 172.18.0.0/16 - 172.31.0.0/16
            if octets[0] == 172 && octets[1] >= 18 && octets[1] <= 31 {
                return true;
            }
        }

        false
    }

    /// Determine the source type for logging
    fn get_source_type(ip: std::net::IpAddr) -> &'static str {
        if ip.is_loopback() {
            "localhost"
        } else if let std::net::IpAddr::V4(ipv4) = ip {
            let octets = ipv4.octets();
            if octets[0] == 172 && (octets[1] >= 17 && octets[1] <= 31) {
                "docker-network"
            } else {
                "unknown"
            }
        } else {
            "unknown"
        }
    }

    pub async fn new(
        config: TappConfig,
        permission_manager: Option<Arc<permission::PermissionManager>>,
        measurement_service: Arc<measurement_service::MeasurementService>,
    ) -> TappResult<Self> {
        info!("Initializing TAPP service components");

        // Initialize TaskManager
        let task_manager = Arc::new(task_manager::TaskManager::new());

        // Initialize BootService with measurement_service and task_manager
        let boot_service = Arc::new(
            BootService::new(&config.boot, measurement_service.clone(), task_manager).await?,
        );

        // Initialize AppKeyService
        let app_key_service = if let Some(ref kbs) = config.kbs {
            info!("Using KBS for app key management");
            app_key::AppKeyService::new(Some(kbs), false).await?
        } else {
            info!("KBS config not provided, using in-memory key generation");
            app_key::AppKeyService::new(None, true).await?
        };

        // Initialize NonceManager for replay attack prevention
        let nonce_manager = nonce_manager::NonceManager::new();

        // Initialize LogsService
        let logs_service =
            service_monitor::logs::LogsService::new(config.logging.file_path.clone());

        info!("All TAPP service components initialized successfully");

        Ok(Self {
            boot_service,
            app_key_service,
            nonce_manager,
            logs_service,
            permission_manager,
            measurement_service,
            config,
        })
    }
}

#[tonic::async_trait]
impl TappService for TappServiceImpl {
    /// Get attestation evidence from TEE platform
    async fn get_evidence(
        &self,
        request: Request<GetEvidenceRequest>,
    ) -> Result<Response<GetEvidenceResponse>, Status> {
        let req = request.into_inner();
        let evidence = self.boot_service.get_evidence(req).await?;
        Ok(Response::new(evidence))
    }

    async fn start_app(
        &self,
        request: Request<StartAppRequest>,
    ) -> Result<Response<StartAppResponse>, Status> {
        // Signature validation is handled by AuthLayer
        // Get signer address before consuming request
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();

        // Get deployer address (signer EVM address)
        // If no signer (auth disabled), use a default placeholder
        let deployer = signer
            .clone()
            .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

        // Start the app with deployer address
        let response = self
            .boot_service
            .clone()
            .start_app(req_inner, deployer.clone())
            .await?;

        // Record ownership if permission management is enabled
        if let Some(pm) = &self.permission_manager {
            if let Some(signer_addr) = signer {
                pm.record_app_start(app_id.clone(), signer_addr.clone())
                    .await;

                info!(
                    app_id = %app_id,
                    owner = %signer_addr,
                    deployer = %deployer,
                    event = "APP_OWNERSHIP_RECORDED",
                    "App ownership recorded"
                );
            }
        }

        Ok(Response::new(response))
    }

    async fn stop_app(
        &self,
        request: Request<StopAppRequest>,
    ) -> Result<Response<StopAppResponse>, Status> {
        // Get signer address before consuming request
        let signer = auth_layer::get_signer_address(&request);
        let req_inner = request.into_inner();
        let app_id = req_inner.app_id.clone();

        // Check ownership if permission management is enabled
        if let Some(pm) = &self.permission_manager {
            if let Some(signer_addr) = signer {
                // Check if user can manage this app
                if !pm.can_manage_app(&app_id, &signer_addr).await {
                    error!(
                        app_id = %app_id,
                        requester = %signer_addr,
                        event = "APP_STOP_AUTHORIZED",
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    );
                    return Err(Status::permission_denied(format!(
                        "You don't have permission to stop app {}. Only the app owner or tapp owner can stop it.",
                        app_id
                    )));
                }

                info!(
                    app_id = %app_id,
                    requester = %signer_addr,
                    event = "APP_STOP_AUTHORIZED",
                    "User authorized to stop app"
                );
            }
        }

        // Stop the app
        self.boot_service.stop_app(&app_id).await?;

        // Mark app as stopped in ownership tracking
        if let Some(pm) = &self.permission_manager {
            pm.mark_app_stopped(&app_id).await;

            info!(
                app_id = %app_id,
                event = "APP_OWNERSHIP_UPDATED",
                "App marked as stopped"
            );
        }

        Ok(Response::new(StopAppResponse {
            success: true,
            message: format!("Application {} stopped successfully", app_id),
            timestamp: utils::current_timestamp(),
        }))
    }

    async fn get_task_status(
        &self,
        request: Request<GetTaskStatusRequest>,
    ) -> Result<Response<GetTaskStatusResponse>, Status> {
        let req = request.into_inner();

        match self.boot_service.get_task_status(&req.task_id).await {
            Some(task) => Ok(Response::new(GetTaskStatusResponse {
                success: true,
                message: "Task found".to_string(),
                task_id: task.id.clone(),
                status: task.to_proto_status() as i32,
                result: task.to_proto_result(),
                created_at: task.created_at,
                updated_at: task.updated_at,
            })),
            None => Ok(Response::new(GetTaskStatusResponse {
                success: false,
                message: format!("Task not found: {}", req.task_id),
                task_id: req.task_id,
                status: 0,
                result: None,
                created_at: 0,
                updated_at: 0,
            })),
        }
    }

    async fn list_app_measurements(
        &self,
        request: Request<ListAppMeasurementsRequest>,
    ) -> Result<Response<ListAppMeasurementsResponse>, Status> {
        let req = request.into_inner();

        let deployer_filter = if req.deployer_filter.is_empty() {
            None
        } else {
            Some(req.deployer_filter)
        };

        let measurements = self
            .boot_service
            .list_app_measurements(deployer_filter)
            .await;

        let measurement_infos: Vec<AppMeasurementInfo> = measurements
            .iter()
            .map(|m| AppMeasurementInfo {
                app_id: m.app_id.clone(),
                operation: m.operation.clone(),
                result: m.result.clone(),
                error: m.error.clone().unwrap_or_default(),
                compose_hash: m.compose_hash.clone(),
                volumes_hash: m.volumes_hash.clone(),
                deployer: m.deployer.clone(),
                timestamp: m.timestamp,
            })
            .collect();

        let total_count = measurement_infos.len() as i32;

        Ok(Response::new(ListAppMeasurementsResponse {
            success: true,
            message: format!("Found {} measurements", total_count),
            measurements: measurement_infos,
            total_count,
            hash_algorithm: self.boot_service.get_hash_algorithm(),
        }))
    }

    async fn get_app_key(
        &self,
        request: Request<GetAppKeyRequest>,
    ) -> Result<Response<GetAppKeyResponse>, Status> {
        let req = request.into_inner();

        // Default to "ethereum" if key_type is not specified
        let key_type = if req.key_type.is_empty() {
            "ethereum"
        } else {
            &req.key_type
        };

        let response = self
            .app_key_service
            .get_app_key(&req.app_id, key_type)
            .await?;
        Ok(Response::new(response))
    }

    async fn get_app_secret_key(
        &self,
        request: Request<GetAppSecretKeyRequest>,
    ) -> Result<Response<GetAppSecretKeyResponse>, Status> {
        // Extract remote address BEFORE consuming request
        let remote_addr = request.remote_addr();

        // Validate that the request is from localhost or Docker network
        let (is_allowed, source_type) = if let Some(addr) = remote_addr {
            let ip = addr.ip();
            let allowed = Self::is_allowed_local_access(ip);
            let source = Self::get_source_type(ip);
            (allowed, source)
        } else {
            // No remote address (e.g., Unix socket) - allow
            (true, "unix-socket")
        };

        if !is_allowed {
            // SECURITY: Log rejected attempts with full details
            tracing::error!(
                remote_addr = ?remote_addr,
                event = "SECRET_KEY_ACCESS_DENIED",
                reason = "not in allowed network range",
                "Rejected GetAppSecretKey request from non-allowed address"
            );

            return Err(Status::permission_denied(
                "GetAppSecretKey can only be called from localhost or same-host Docker containers",
            ));
        }

        let req = request.into_inner();

        // SECURITY: Verify nonce and timestamp to prevent replay attacks
        if let Err(e) = self
            .nonce_manager
            .verify_and_consume(&req.nonce, req.timestamp)
            .await
        {
            tracing::error!(
                app_id = %req.app_id,
                remote_addr = ?remote_addr,
                source_type = source_type,
                event = "SECRET_KEY_ACCESS_DENIED",
                reason = "nonce verification failed",
                error = %e,
                "Nonce verification failed"
            );

            return Err(Status::permission_denied(format!(
                "Nonce verification failed: {}",
                e
            )));
        }

        // SECURITY: Get deployer public key from app measurements
        let app_measurements = self.boot_service.list_app_measurements(None).await;
        let app_measurement = app_measurements
            .iter()
            .find(|m| m.app_id == req.app_id)
            .ok_or_else(|| {
                tracing::error!(
                    app_id = %req.app_id,
                    remote_addr = ?remote_addr,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "app not found",
                    "App not found in measurements"
                );
                Status::not_found(format!("App {} not found", req.app_id))
            })?;

        // Decode deployer public key from hex
        let deployer_pubkey = hex::decode(&app_measurement.deployer).map_err(|e| {
            tracing::error!(
                app_id = %req.app_id,
                error = %e,
                "Failed to decode deployer public key"
            );
            Status::internal("Failed to decode deployer public key")
        })?;

        // SECURITY: Verify deployer signature
        // Message format: app_id || nonce || timestamp (as bytes)
        let mut message = Vec::new();
        message.extend_from_slice(req.app_id.as_bytes());
        message.extend_from_slice(req.nonce.as_bytes());
        message.extend_from_slice(&req.timestamp.to_le_bytes());

        let signature_valid = app_key::verify_signature(&deployer_pubkey, &message, &req.signature)
            .map_err(|e| {
                tracing::error!(
                    app_id = %req.app_id,
                    remote_addr = ?remote_addr,
                    event = "SECRET_KEY_ACCESS_DENIED",
                    reason = "signature verification error",
                    error = %e,
                    "Signature verification error"
                );
                Status::internal(format!("Signature verification error: {}", e))
            })?;

        if !signature_valid {
            tracing::error!(
                app_id = %req.app_id,
                remote_addr = ?remote_addr,
                source_type = source_type,
                event = "SECRET_KEY_ACCESS_DENIED",
                reason = "invalid deployer signature",
                "Invalid deployer signature"
            );

            return Err(Status::permission_denied(
                "Invalid deployer signature. Only the app deployer can access the private key.",
            ));
        }

        // SECURITY: Log all successful private key access attempts
        tracing::warn!(
            app_id = %req.app_id,
            remote_addr = ?remote_addr,
            source_type = source_type,
            deployer = %app_measurement.deployer,
            event = "SECRET_KEY_ACCESS",
            timestamp = %chrono::Utc::now(),
            "Private key access attempt from allowed source with valid signature"
        );

        // Also get public key and address for response
        let key_response = self
            .app_key_service
            .get_app_key(&req.app_id, "ethereum")
            .await?;

        // Get private key
        let private_key = self.app_key_service.get_private_key(&req.app_id).await?;

        // SECURITY: Log successful retrieval
        tracing::warn!(
            app_id = %req.app_id,
            remote_addr = ?remote_addr,
            source_type = source_type,
            event = "SECRET_KEY_RETRIEVED",
            timestamp = %chrono::Utc::now(),
            "Private key successfully retrieved"
        );

        Ok(Response::new(GetAppSecretKeyResponse {
            success: true,
            message: format!("Private key for app {}", req.app_id),
            private_key,
            public_key: key_response.public_key,
            eth_address: key_response.eth_address,
        }))
    }

    async fn get_app_info(
        &self,
        request: Request<GetAppInfoRequest>,
    ) -> Result<Response<GetAppInfoResponse>, Status> {
        let req = request.into_inner();
        let app_id = req.app_id;

        let compose_content = self.boot_service.get_app_compose_content(&app_id).await?;
        let volumes_content = self.boot_service.get_app_mount_files(&app_id).await?;

        let compose_content = compose_content.ok_or(TappError::InvalidParameter {
            field: "app_id".to_string(),
            reason: format!("App {} not found", app_id),
        })?;
        let volumes_content = volumes_content.ok_or(TappError::InvalidParameter {
            field: "app_id".to_string(),
            reason: format!("App {} not found", app_id),
        })?;

        Ok(Response::new(GetAppInfoResponse {
            success: true,
            message: format!("App info for {}", app_id),
            app_id,
            compose_content,
            volumes_content,
        }))
    }

    async fn get_service_status(
        &self,
        _request: Request<GetServiceStatusRequest>,
    ) -> Result<Response<GetServiceStatusResponse>, Status> {
        todo!()
    }

    async fn get_service_logs(
        &self,
        request: Request<GetServiceLogsRequest>,
    ) -> Result<Response<GetServiceLogsResponse>, Status> {
        let req = request.into_inner();
        let response = self.logs_service.get_logs(req).await?;
        Ok(Response::new(response))
    }

    async fn get_app_logs(
        &self,
        request: Request<GetAppLogsRequest>,
    ) -> Result<Response<GetAppLogsResponse>, Status> {
        let req = request.into_inner();

        let service_name = if req.service_name.is_empty() {
            None
        } else {
            Some(req.service_name.as_str())
        };

        let content = self
            .boot_service
            .get_app_logs(&req.app_id, req.lines, service_name)
            .await?;

        let total_lines = content.lines().count() as i32;

        Ok(Response::new(GetAppLogsResponse {
            success: true,
            message: format!("Retrieved {} lines from app {}", total_lines, req.app_id),
            content,
            total_lines,
        }))
    }

    // ============================================================================
    // Permission Management Methods
    // ============================================================================

    async fn add_to_whitelist(
        &self,
        request: Request<AddToWhitelistRequest>,
    ) -> Result<Response<AddToWhitelistResponse>, Status> {
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Add address to whitelist
        pm.add_to_whitelist(req.evm_address.clone())
            .await
            .map_err(|e| Status::internal(format!("Failed to add to whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_ADD_TO_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_ADDED",
            "Address added to whitelist and measurement extended"
        );

        Ok(Response::new(AddToWhitelistResponse {
            success: true,
            message: format!("Address {} added to whitelist", req.evm_address),
        }))
    }

    async fn remove_from_whitelist(
        &self,
        request: Request<RemoveFromWhitelistRequest>,
    ) -> Result<Response<RemoveFromWhitelistResponse>, Status> {
        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Remove address from whitelist
        pm.remove_from_whitelist(&req.evm_address)
            .await
            .map_err(|e| Status::internal(format!("Failed to remove from whitelist: {}", e)))?;

        // Extend runtime measurement for this security-critical operation
        let measurement_data = serde_json::json!({
            "operation": measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
            "address": req.evm_address,
            "timestamp": utils::current_timestamp()
        })
        .to_string();

        self.measurement_service
            .extend_measurement(
                measurement_service::OPERATION_NAME_REMOVE_FROM_WHITELIST,
                &measurement_data,
            )
            .await
            .map_err(|e| Status::internal(format!("Failed to extend measurement: {}", e)))?;

        info!(
            address = %req.evm_address,
            event = "WHITELIST_REMOVED",
            "Address removed from whitelist and measurement extended"
        );

        Ok(Response::new(RemoveFromWhitelistResponse {
            success: true,
            message: format!("Address {} removed from whitelist", req.evm_address),
        }))
    }

    async fn list_whitelist(
        &self,
        _request: Request<ListWhitelistRequest>,
    ) -> Result<Response<ListWhitelistResponse>, Status> {
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let addresses = pm.list_whitelist().await;

        Ok(Response::new(ListWhitelistResponse {
            success: true,
            message: format!("Found {} whitelisted address(es)", addresses.len()),
            addresses,
        }))
    }

    async fn get_app_ownership(
        &self,
        request: Request<GetAppOwnershipRequest>,
    ) -> Result<Response<GetAppOwnershipResponse>, Status> {
        // Get signer address before consuming request
        let signer = auth_layer::get_signer_address(&request)
            .ok_or_else(|| Status::unauthenticated("Signer address not found"))?;

        let req = request.into_inner();

        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        // Check if user can view this app's ownership
        // Owner can view all, others can only view if they can manage the app
        if !pm.can_manage_app(&req.app_id, &signer).await && signer != pm.get_tapp_owner_address() {
            return Err(Status::permission_denied(
                "You don't have permission to view this app's ownership",
            ));
        }

        let ownership = pm.get_app_ownership(&req.app_id).await;

        match ownership {
            Some(own) => Ok(Response::new(GetAppOwnershipResponse {
                success: true,
                message: format!("Ownership info for app {}", req.app_id),
                ownership: Some(AppOwnershipInfo {
                    app_id: own.app_id,
                    owner_address: own.owner_address,
                    started_at: own.started_at,
                    status: match own.status {
                        permission::AppStatus::Active => proto::AppStatus::Active.into(),
                        permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                    },
                    stopped_at: own.stopped_at.unwrap_or(0),
                }),
            })),
            None => Err(Status::not_found(format!("App {} not found", req.app_id))),
        }
    }

    async fn list_all_ownerships(
        &self,
        _request: Request<ListAllOwnershipsRequest>,
    ) -> Result<Response<ListAllOwnershipsResponse>, Status> {
        let pm = self
            .permission_manager
            .as_ref()
            .ok_or_else(|| Status::unavailable("Permission management not enabled"))?;

        let ownerships_list = pm.list_all_ownerships().await;

        let ownerships: Vec<AppOwnershipInfo> = ownerships_list
            .into_iter()
            .map(|own| AppOwnershipInfo {
                app_id: own.app_id,
                owner_address: own.owner_address,
                started_at: own.started_at,
                status: match own.status {
                    permission::AppStatus::Active => proto::AppStatus::Active.into(),
                    permission::AppStatus::Stopped => proto::AppStatus::Stopped.into(),
                },
                stopped_at: own.stopped_at.unwrap_or(0),
            })
            .collect();

        Ok(Response::new(ListAllOwnershipsResponse {
            success: true,
            message: format!("Found {} app ownership(s)", ownerships.len()),
            ownerships,
        }))
    }
}

/// Initialize tracing based on configuration
pub fn init_tracing(config: &config::LoggingConfig) -> TappResult<()> {
    use tracing_subscriber::{
        fmt::{self, format::FmtSpan},
        layer::SubscriberExt,
        util::SubscriberInitExt,
        EnvFilter, Layer,
    };

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.level))
        .map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.level".to_string(),
            reason: format!("Invalid log level: {}", e),
        })?;

    let stdout_layer = match config.format.as_str() {
        "json" => fmt::layer()
            .json()
            .with_writer(std::io::stdout)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        "pretty" => fmt::layer()
            .pretty()
            .with_writer(std::io::stdout)
            .with_ansi(true)
            .with_span_events(FmtSpan::CLOSE)
            .boxed(),
        _ => {
            return Err(error::ConfigError::InvalidValue {
                field: "logging.format".to_string(),
                reason: format!("Unsupported log format: {}", config.format),
            }
            .into());
        }
    };

    if let Some(file_path) = &config.file_path {
        use tracing_appender::rolling::{RollingFileAppender, Rotation};

        let path = std::path::Path::new(file_path);

        let (directory, file_name_prefix) = if file_path.to_string_lossy().ends_with('/') {
            (path, "app")
        } else if path.extension().is_some() {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_stem().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        } else {
            let directory = path.parent().unwrap_or(std::path::Path::new("."));
            let file_name_prefix = path.file_name().and_then(|n| n.to_str()).unwrap_or("app");
            (directory, file_name_prefix)
        };

        std::fs::create_dir_all(directory).map_err(|e| error::ConfigError::InvalidValue {
            field: "logging.file_path".to_string(),
            reason: format!("Cannot create log directory: {}", e),
        })?;

        let file_appender = RollingFileAppender::new(Rotation::DAILY, directory, file_name_prefix);

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        std::mem::forget(_guard);

        let file_layer = match config.format.as_str() {
            "json" => fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            "pretty" => fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_span_events(FmtSpan::CLOSE)
                .boxed(),
            _ => unreachable!(),
        };

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_app_id() {
        assert!(utils::validate_app_id("my-app"));
        assert!(utils::validate_app_id("app_123"));
        assert!(utils::validate_app_id("test-application-1"));

        assert!(!utils::validate_app_id("ab")); // too short
        assert!(!utils::validate_app_id("a".repeat(65).as_str())); // too long
        assert!(!utils::validate_app_id("app@123")); // invalid character
        assert!(!utils::validate_app_id("app space")); // contains space
    }

    #[test]
    fn test_sha256_hex() {
        let data = b"hello world";
        let hash = utils::sha256_hex(data);
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(utils::format_bytes(0), "0 B");
        assert_eq!(utils::format_bytes(1024), "1.00 KB");
        assert_eq!(utils::format_bytes(1536), "1.50 KB");
        assert_eq!(utils::format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_pad_to_length() {
        let data = b"hello";
        let padded = utils::pad_to_length(data, 10);
        assert_eq!(padded.len(), 10);
        assert_eq!(&padded[0..5], b"hello");
        assert_eq!(&padded[5..], &[0u8; 5]);
    }
}
