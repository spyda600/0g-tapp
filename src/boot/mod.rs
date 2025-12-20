pub mod manager;
pub mod measurement;

pub use manager::{AppStatus, ContainerStatus, DockerComposeManager, MountFile};
pub use measurement::{AppMeasurement, ComposeMeasurement, HashAlgorithm};

use crate::config::BootServiceConfig;
use crate::error::{DockerError, TappError, TappResult};
use crate::measurement_service::MeasurementService;
use crate::proto::{GetEvidenceRequest, GetEvidenceResponse, StartAppRequest, StartAppResponse};
use crate::task_manager::{Task, TaskManager, TaskSuccessResult};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct BootService {
    config: BootServiceConfig,
    manager: Mutex<DockerComposeManager>,
    app_measurements: Mutex<HashMap<String, Vec<AppMeasurement>>>,
    measurement_service: Arc<MeasurementService>,
    task_manager: Arc<TaskManager>,
    app_compose_content: Mutex<HashMap<String, String>>,
    app_mount_files: Mutex<HashMap<String, String>>,
}

impl BootService {
    /// Ensure attestation agent config file exists with default values
    pub fn ensure_aa_config(config_path: &str) -> TappResult<()> {
        let path = Path::new(config_path);

        // If file already exists, do nothing
        if path.exists() {
            return Ok(());
        }

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| DockerError::ContainerOperationFailed {
                operation: "create_config_dir".to_string(),
                reason: format!("Failed to create config directory: {}", e),
            })?;
        }

        // Create default config file with enable_eventlog = true
        let default_config = r#"[eventlog_config]
enable_eventlog = true
"#;

        std::fs::write(path, default_config).map_err(|e| {
            DockerError::ContainerOperationFailed {
                operation: "write_config".to_string(),
                reason: format!("Failed to write default config: {}", e),
            }
        })?;

        info!(
            "Created default attestation-agent config at: {}",
            config_path
        );
        Ok(())
    }

    /// Create new Docker Compose service
    pub async fn new(
        config: &BootServiceConfig,
        measurement_service: Arc<MeasurementService>,
        task_manager: Arc<TaskManager>,
    ) -> TappResult<Self> {
        let manager = DockerComposeManager::new(&config.socket_path).await?;

        Ok(Self {
            config: config.clone(),
            manager: Mutex::new(manager),
            app_measurements: Mutex::new(HashMap::new()),
            measurement_service,
            task_manager,
            app_compose_content: Mutex::new(HashMap::new()),
            app_mount_files: Mutex::new(HashMap::new()),
        })
    }

    /// Internal method to handle the actual app start logic
    async fn _start_app(&self, request: StartAppRequest, deployer: String, task_id: String) {
        let app_id = request.app_id.clone();

        // Convert proto MountFile to our MountFile structure (needed for both success and failure)
        let mount_files: Vec<MountFile> = request
            .mount_files
            .iter()
            .map(|mf| MountFile {
                source_path: mf.source_path.clone(),
                content: mf.content.clone(),
                mode: if mf.mode.is_empty() {
                    "0644".to_string()
                } else {
                    mf.mode.clone()
                },
            })
            .collect();

        // Calculate application measurement once (before we know success/failure)
        let base_measurement_result = self
            .calculate_app_measurement(
                &request,
                &mount_files,
                &app_id,
                &deployer,
                crate::measurement_service::OPERATION_NAME_START_APP,
            )
            .await;

        // Handle the measurement calculation result
        let (base_measurement, compose_content, volumes_content) = match base_measurement_result {
            Ok(result) => result,
            Err(e) => {
                // If measurement calculation fails, mark task as failed and return
                self.task_manager
                    .mark_failed(&task_id, format!("Failed to calculate measurement: {}", e))
                    .await;
                return;
            }
        };

        // Try to start the application
        let result = async {
            let app_id = request.app_id.clone();
            info!(
                task_id = %task_id,
                app_id = %app_id,
                mount_files_count = request.mount_files.len(),
                "Starting application with Docker Compose"
            );

            // Store compose content and mount files
            self.app_compose_content
                .lock()
                .await
                .insert(app_id.clone(), compose_content);

            self.app_mount_files
                .lock()
                .await
                .insert(app_id.clone(), volumes_content);

            // Start the Docker Compose application with mount files
            DockerComposeManager::deploy_compose(&app_id, &request.compose_content, &mount_files)
                .await?;

            info!(
                task_id = %task_id,
                app_id = %app_id,
                "Application started successfully"
            );

            Ok::<_, crate::error::TappError>((app_id, deployer.clone()))
        }
        .await;

        // Mark measurement as success or failure based on result
        let final_measurement = match &result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Store measurement and extend runtime measurement (ONCE for both success/failure)
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        info!("measurement_json: {}", measurement_json);

        // Store measurement in memory (append to history)
        self.app_measurements
            .lock()
            .await
            .entry(app_id.clone())
            .or_insert_with(Vec::new)
            .push(final_measurement.clone());

        // Extend runtime measurement via measurement service
        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_START_APP,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement: {}", e);
        }

        // Update task status based on result
        match result {
            Ok((app_id, deployer)) => {
                self.task_manager
                    .mark_completed(&task_id, TaskSuccessResult { app_id, deployer })
                    .await;
            }
            Err(e) => {
                self.task_manager
                    .mark_failed(&task_id, format!("{}", e))
                    .await;
            }
        }
    }

    /// Handle start app request (async - returns task ID immediately)
    /// This method should be called with Arc<Self> from the service implementation
    pub async fn start_app(
        self: std::sync::Arc<Self>,
        request: StartAppRequest,
        deployer: String, // EVM address from signature authentication
    ) -> TappResult<StartAppResponse> {
        // Validate request
        self.validate_request(&request)?;

        // Create a new task
        let task = self.task_manager.create_task().await;
        let task_id = task.id.clone();

        info!(
            task_id = %task_id,
            app_id = %request.app_id,
            "Created task for starting application"
        );

        // Mark task as running
        self.task_manager.mark_running(&task_id).await;

        // Clone Arc for background task
        let service = self.clone();
        let task_id_clone = task_id.clone();

        // Spawn background task
        tokio::spawn(async move {
            service._start_app(request, deployer, task_id_clone).await;
        });

        Ok(StartAppResponse {
            success: true,
            message: format!("Task created successfully. Use task_id to check status."),
            task_id: task_id,
            timestamp: crate::utils::current_timestamp(),
        })
    }

    /// Get task status
    pub async fn get_task_status(&self, task_id: &str) -> Option<Task> {
        self.task_manager.get_task(task_id).await
    }

    /// Get the hash algorithm currently in use
    pub fn get_hash_algorithm(&self) -> String {
        // Return the algorithm used by ComposeMeasurement
        let algo = HashAlgorithm::default();
        match algo {
            HashAlgorithm::Sha256 => "sha256".to_string(),
            HashAlgorithm::Sha384 => "sha384".to_string(),
        }
    }

    /// Get application logs from docker compose
    pub async fn get_app_logs(
        &self,
        app_id: &str,
        lines: i32,
        service_name: Option<&str>,
    ) -> TappResult<String> {
        DockerComposeManager::get_app_logs(app_id, lines, service_name).await
    }

    /// List all app measurements (returns all historical measurements)
    pub async fn list_app_measurements(
        &self,
        deployer_filter: Option<String>,
    ) -> Vec<AppMeasurement> {
        let measurements = self.app_measurements.lock().await;

        // Flatten all measurement histories into a single vec
        let mut result: Vec<AppMeasurement> = measurements
            .values()
            .flatten()
            .filter(|m| {
                // Apply deployer filter if provided
                if let Some(ref filter) = deployer_filter {
                    // Filter can be with or without 0x prefix
                    let filter_normalized = filter.trim_start_matches("0x").to_lowercase();
                    m.deployer.to_lowercase().contains(&filter_normalized)
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        // Sort by timestamp descending (newest first)
        result.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        result
    }

    /// Get the latest measurement for a specific app
    pub async fn get_latest_app_measurement(&self, app_id: &str) -> Option<AppMeasurement> {
        let measurements = self.app_measurements.lock().await;
        measurements
            .get(app_id)
            .and_then(|history| history.last())
            .cloned()
    }

    pub async fn get_evidence(
        &self,
        request: GetEvidenceRequest,
    ) -> TappResult<GetEvidenceResponse> {
        // Prepare report data
        let report_data = if request.report_data.is_empty() {
            // Use zero-filled 64 bytes as default
            vec![0u8; 64]
        } else {
            // Validate and pad report data to 64 bytes
            if request.report_data.len() > 64 {
                return Err(DockerError::InvalidComposeContent {
                    reason: format!(
                        "Report data must be at most 64 bytes, got {}",
                        request.report_data.len()
                    ),
                }
                .into());
            }
            let mut padded = request.report_data.clone();
            padded.resize(64, 0);
            padded
        };

        info!("report_data: {:?}", hex::encode(&report_data));

        let evidence = self.measurement_service.get_evidence(&report_data).await?;
        let tee_type = self.measurement_service.get_tee_type().await;
        Ok(GetEvidenceResponse {
            success: true,
            message: "Evidence generated successfully".to_string(),
            evidence,
            tee_type,
            timestamp: crate::utils::current_timestamp(),
        })
    }

    /// Validate start app request
    fn validate_request(&self, request: &StartAppRequest) -> TappResult<()> {
        if request.compose_content.is_empty() {
            return Err(DockerError::InvalidComposeContent {
                reason: "Compose content cannot be empty".to_string(),
            }
            .into());
        }

        if request.app_id.is_empty() {
            return Err(DockerError::InvalidComposeContent {
                reason: "App ID cannot be empty".to_string(),
            }
            .into());
        }

        if !crate::utils::validate_app_id(&request.app_id) {
            return Err(DockerError::InvalidComposeContent {
                reason: format!("Invalid app ID format: {}", request.app_id),
            }
            .into());
        }

        Ok(())
    }

    /// Calculate application measurement
    async fn calculate_app_measurement(
        &self,
        request: &StartAppRequest,
        mount_files: &[MountFile],
        app_id: &str,
        deployer: &str,  // EVM address from signature
        operation: &str, // Operation name like "start_app"
    ) -> TappResult<(AppMeasurement, String, String)> {
        let measurement = ComposeMeasurement::new();

        // Calculate compose file hash
        let compose_hash = measurement.calculate_compose_hash(&request.compose_content)?;

        // Calculate volumes hash from mount files (uploaded files)
        let (volumes_hash, volumes_content) =
            measurement.calculate_mount_files_hash(mount_files)?;

        Ok((
            AppMeasurement {
                app_id: app_id.to_string(),
                operation: operation.to_string(),
                result: String::new(), // Will be set by with_success() or with_failure()
                error: None,           // Will be set by with_failure() if needed
                compose_hash,
                volumes_hash,
                deployer: deployer.to_string(),
                timestamp: crate::utils::current_timestamp(),
            },
            request.compose_content.clone(),
            volumes_content,
        ))
    }

    pub async fn stop_app(&self, app_id: &str) -> TappResult<()> {
        info!(app_id = %app_id, "Stopping application");

        // Get the latest measurement for this app (to use for stop operation measurement)
        let base_measurement = {
            let measurements = self.app_measurements.lock().await;
            if let Some(history) = measurements.get(app_id) {
                if let Some(latest) = history.last() {
                    // Create a new measurement for stop operation based on the latest one
                    AppMeasurement {
                        app_id: app_id.to_string(),
                        operation: crate::measurement_service::OPERATION_NAME_STOP_APP.to_string(),
                        result: String::new(),
                        error: None,
                        compose_hash: latest.compose_hash.clone(),
                        volumes_hash: latest.volumes_hash.clone(),
                        deployer: latest.deployer.clone(),
                        timestamp: crate::utils::current_timestamp(),
                    }
                } else {
                    return Err(TappError::InvalidParameter {
                        field: "app_id".to_string(),
                        reason: format!("No measurement found for app {}", app_id),
                    });
                }
            } else {
                return Err(TappError::InvalidParameter {
                    field: "app_id".to_string(),
                    reason: format!("No measurement found for app {}", app_id),
                });
            }
        };

        // Try to stop the application
        let result = async {
            // 1. Stop compose
            DockerComposeManager::stop_compose(app_id).await?;

            // 2. Delete app directory
            let app_dir = DockerComposeManager::get_app_dir(app_id);
            if app_dir.exists() {
                tokio::fs::remove_dir_all(&app_dir).await.map_err(|e| {
                    TappError::Docker(DockerError::ContainerOperationFailed {
                        operation: "delete_app_dir".to_string(),
                        reason: format!("Failed to delete app directory: {}", e),
                    })
                })?;
                info!(app_id = %app_id, "App directory deleted successfully");
            }

            Ok::<_, crate::error::TappError>(())
        }
        .await;

        // Mark measurement as success or failure based on result
        let final_measurement = match &result {
            Ok(_) => base_measurement.with_success(),
            Err(e) => base_measurement.with_failure(format!("{}", e)),
        };

        // Extend runtime measurement (but don't store in memory - stop doesn't change code)
        let measurement_json = serde_json::to_string(&final_measurement)
            .unwrap_or_else(|e| format!("{{\"error\": \"Failed to serialize: {}\"}}", e));

        info!("stop_app measurement_json: {}", measurement_json);

        // Extend TEE measurement via measurement service
        if let Err(e) = self
            .measurement_service
            .extend_measurement(
                crate::measurement_service::OPERATION_NAME_STOP_APP,
                &measurement_json,
            )
            .await
        {
            tracing::error!("Failed to extend measurement for stop operation: {}", e);
        }

        info!(app_id = %app_id, "Application stopped successfully");

        // Return the original result
        result
    }

    pub async fn get_app_compose_content(&self, app_id: &str) -> TappResult<Option<String>> {
        let compose_content = self.app_compose_content.lock().await.get(app_id).cloned();
        Ok(compose_content)
    }

    pub async fn get_app_mount_files(&self, app_id: &str) -> TappResult<Option<String>> {
        let mount_files = self.app_mount_files.lock().await.get(app_id).cloned();
        Ok(mount_files)
    }
}

#[cfg(test)]
mod tests {}
