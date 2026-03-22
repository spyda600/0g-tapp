//! Docker proxy client for Nitro Enclaves.
//!
//! Inside a Nitro Enclave there is no Docker daemon. This module sends Docker
//! commands to the parent EC2 instance over vsock, where a companion proxy
//! script executes them and returns the result.

use crate::error::{DockerError, TappError, TappResult};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::VsockStream;
use tracing::{error, info};

/// The vsock CID for the parent/host (always 3 in Nitro Enclaves).
const PARENT_CID: u32 = 3;

/// The vsock port the parent-side proxy listens on.
const DOCKER_PROXY_PORT: u32 = 50052;

// ---------------------------------------------------------------------------
// Wire protocol types
// ---------------------------------------------------------------------------

/// A request sent from the enclave to the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerProxyRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compose_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_image: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prune_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

/// The response received from the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerProxyResponse {
    pub success: bool,
    #[serde(default)]
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Send a [`DockerProxyRequest`] to the parent over vsock and return the
/// parsed [`DockerProxyResponse`].
///
/// The wire format is length-prefixed JSON:
///   [4-byte big-endian length][JSON payload]
async fn send_request(request: &DockerProxyRequest) -> TappResult<DockerProxyResponse> {
    let payload = serde_json::to_vec(request).map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_serialize".to_string(),
            reason: format!("Failed to serialize proxy request: {}", e),
        })
    })?;

    info!(
        command = %request.command,
        app_id = ?request.app_id,
        payload_len = payload.len(),
        "Connecting to parent Docker proxy via vsock"
    );

    let mut stream =
        VsockStream::connect(PARENT_CID, DOCKER_PROXY_PORT)
            .await
            .map_err(|e| {
                TappError::Docker(DockerError::ContainerOperationFailed {
                    operation: "docker_proxy_connect".to_string(),
                    reason: format!(
                        "Failed to connect to parent Docker proxy (CID={}, port={}): {}",
                        PARENT_CID, DOCKER_PROXY_PORT, e
                    ),
                })
            })?;

    // Write length prefix + payload
    let len_bytes = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await.map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_write".to_string(),
            reason: format!("Failed to write to vsock: {}", e),
        })
    })?;
    stream.write_all(&payload).await.map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_write".to_string(),
            reason: format!("Failed to write payload to vsock: {}", e),
        })
    })?;
    stream.flush().await.ok(); // best-effort flush

    // Read response length prefix
    let mut resp_len_buf = [0u8; 4];
    stream.read_exact(&mut resp_len_buf).await.map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_read".to_string(),
            reason: format!("Failed to read response length: {}", e),
        })
    })?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

    // Safety bound: reject absurdly large responses (>16 MiB)
    if resp_len > 16 * 1024 * 1024 {
        return Err(TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_read".to_string(),
            reason: format!("Response too large: {} bytes", resp_len),
        }));
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_read".to_string(),
            reason: format!("Failed to read response body: {}", e),
        })
    })?;

    let response: DockerProxyResponse = serde_json::from_slice(&resp_buf).map_err(|e| {
        TappError::Docker(DockerError::ContainerOperationFailed {
            operation: "docker_proxy_deserialize".to_string(),
            reason: format!("Failed to deserialize proxy response: {}", e),
        })
    })?;

    if !response.success {
        error!(
            command = %request.command,
            exit_code = response.exit_code,
            stderr = %response.stderr,
            "Docker proxy command failed on parent"
        );
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// High-level API (matches DockerComposeManager signatures)
// ---------------------------------------------------------------------------

/// Run `docker compose up -d` on the parent for the given app.
///
/// The parent writes `compose_content` to `working_dir/docker-compose.yml`
/// before running the command.
pub async fn compose_up(app_id: &str, compose_content: &str, working_dir: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_up".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: Some(compose_content.to_string()),
        working_dir: Some(working_dir.to_string()),
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose down` on the parent.
pub async fn compose_down(app_id: &str, working_dir: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_down".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Retrieve `docker compose logs` from the parent.
pub async fn compose_logs(
    app_id: &str,
    working_dir: &str,
    service_name: Option<&str>,
    tail: i32,
) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_logs".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: service_name.map(|s| s.to_string()),
        tail: Some(tail),
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose ps --format json` on the parent.
pub async fn compose_ps(app_id: &str, working_dir: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_ps".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose images --format json` on the parent.
pub async fn compose_images(app_id: &str, working_dir: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_images".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose stop <service>` on the parent.
pub async fn compose_stop_service(
    app_id: &str,
    working_dir: &str,
    service_name: &str,
) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_stop_service".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: Some(service_name.to_string()),
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose up -d [--pull always] <service>` on the parent.
pub async fn compose_start_service(
    app_id: &str,
    working_dir: &str,
    service_name: &str,
    pull_image: bool,
) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_start_service".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: Some(service_name.to_string()),
        tail: None,
        pull_image: Some(pull_image),
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker compose ps --services --filter status=running` on the parent.
pub async fn compose_is_service_running(
    app_id: &str,
    working_dir: &str,
    service_name: &str,
) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "compose_is_service_running".to_string(),
        app_id: Some(app_id.to_string()),
        compose_content: None,
        working_dir: Some(working_dir.to_string()),
        service_name: Some(service_name.to_string()),
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker inspect --format={{index .RepoDigests 0}} <image_id>` on the parent.
pub async fn docker_inspect_digest(image_id: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "inspect_digest".to_string(),
        app_id: None,
        compose_content: None,
        working_dir: None,
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: Some(image_id.to_string()),
        container_name: None,
    };
    send_request(&req).await
}

/// Run `docker inspect --format={{.State.StartedAt}} <container_name>` on the parent.
pub async fn docker_inspect_started_at(container_name: &str) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "inspect_started_at".to_string(),
        app_id: None,
        compose_content: None,
        working_dir: None,
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: None,
        image_id: None,
        container_name: Some(container_name.to_string()),
    };
    send_request(&req).await
}

/// Run `docker system prune -f [--all]` on the parent.
pub async fn docker_prune(all: bool) -> TappResult<DockerProxyResponse> {
    let req = DockerProxyRequest {
        command: "system_prune".to_string(),
        app_id: None,
        compose_content: None,
        working_dir: None,
        service_name: None,
        tail: None,
        pull_image: None,
        prune_all: Some(all),
        image_id: None,
        container_name: None,
    };
    send_request(&req).await
}
