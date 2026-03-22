//! KMS-based key persistence for AWS Nitro Enclaves.
//!
//! Encrypts application private keys via AWS KMS using the Nitro attestation
//! Recipient field, then stores the encrypted blobs on the parent EC2 instance.
//! On enclave restart, keys can be recovered by decrypting the blobs (KMS
//! verifies the enclave PCRs before releasing plaintext).
//!
//! # Security model
//!
//! - Private keys never leave the enclave unencrypted.
//! - KMS key policy binds decrypt to specific PCR values, so only the same
//!   enclave image can recover keys.
//! - Encrypted blobs are opaque to the parent — compromise of the parent
//!   EC2 instance does NOT expose plaintext keys.
//! - All plaintext key material is held in `Zeroizing<Vec<u8>>` and erased
//!   from memory on drop.

use crate::config::KmsConfig;
use crate::error::{TappError, TappResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// KMS wire types (subset of the AWS KMS JSON API)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct KmsEncryptRequest {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "Plaintext")]
    plaintext: String, // base64-encoded
    #[serde(rename = "EncryptionContext")]
    encryption_context: HashMap<String, String>,
    /// COSE Sign1 attestation document, base64-encoded.
    /// This is the Nitro-specific "Recipient" field that tells KMS to return
    /// ciphertext for the enclave instead of a normal response.
    #[serde(rename = "Recipient", skip_serializing_if = "Option::is_none")]
    recipient: Option<KmsRecipientInfo>,
}

#[derive(Serialize)]
struct KmsRecipientInfo {
    /// Must be "RECIPIENT_ATTESTATION_DOCUMENT"
    #[serde(rename = "KeyEncryptionAlgorithm")]
    key_encryption_algorithm: String,
    /// Base64-encoded COSE Sign1 attestation document
    #[serde(rename = "AttestationDocument")]
    attestation_document: String,
}

#[derive(Deserialize)]
struct KmsEncryptResponse {
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String, // base64
    #[serde(rename = "CiphertextForRecipient")]
    ciphertext_for_recipient: Option<String>, // base64, present in Nitro mode
}

#[derive(Serialize)]
struct KmsDecryptRequest {
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String, // base64
    #[serde(rename = "EncryptionContext")]
    encryption_context: HashMap<String, String>,
    #[serde(rename = "Recipient", skip_serializing_if = "Option::is_none")]
    recipient: Option<KmsRecipientInfo>,
}

#[derive(Deserialize)]
struct KmsDecryptResponse {
    /// In normal mode this is the plaintext (base64). In Nitro Recipient
    /// mode this is empty and `CiphertextForRecipient` holds the
    /// re-encrypted blob that only the enclave can unwrap.
    #[serde(rename = "Plaintext")]
    plaintext: Option<String>,
    #[serde(rename = "CiphertextForRecipient")]
    ciphertext_for_recipient: Option<String>,
}

/// Error response from KMS.
#[derive(Deserialize)]
struct KmsErrorResponse {
    #[serde(rename = "__type")]
    error_type: Option<String>,
    #[serde(rename = "Message", alias = "message")]
    message: Option<String>,
}

// ---------------------------------------------------------------------------
// Vsock file-proxy wire types
// ---------------------------------------------------------------------------

/// Request to read/write files on the parent via the vsock proxy.
/// This extends the Docker proxy protocol with file operations scoped
/// to the configured storage path.
#[derive(Serialize)]
struct FileProxyRequest {
    command: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>, // base64-encoded for write
}

#[derive(Deserialize)]
struct FileProxyResponse {
    success: bool,
    #[serde(default)]
    data: String, // base64-encoded for read
    #[serde(default)]
    error: String,
    #[serde(default)]
    exists: bool,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypted key persistence backed by AWS KMS and parent-side storage.
pub struct KmsPersistence {
    #[allow(dead_code)] // Used only in nitro builds
    kms_key_id: String,
    storage_path: String,
    #[allow(dead_code)] // Used only in nitro builds
    region: String,
    #[cfg(feature = "nitro")]
    http_client: reqwest::Client,
}

impl KmsPersistence {
    /// Create a new KMS persistence instance.
    ///
    /// Does NOT perform any network calls; the first encrypt/decrypt
    /// operation will validate connectivity.
    pub fn new(config: &KmsConfig) -> TappResult<Self> {
        if config.kms_key_id.is_empty() {
            return Err(TappError::InvalidParameter {
                field: "kms_key_id".to_string(),
                reason: "KMS key ARN must not be empty".to_string(),
            });
        }

        info!(
            kms_key_id = %config.kms_key_id,
            storage_path = %config.storage_path,
            region = %config.region,
            "KMS persistence initialized"
        );

        Ok(Self {
            kms_key_id: config.kms_key_id.clone(),
            storage_path: config.storage_path.clone(),
            region: config.region.clone(),
            #[cfg(feature = "nitro")]
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| TappError::Internal(format!("Failed to create HTTP client: {}", e)))?,
        })
    }

    /// Encrypt and backup a private key for the given app.
    ///
    /// 1. Gets a fresh NSM attestation document
    /// 2. Calls KMS Encrypt with the Recipient attestation document
    /// 3. Writes the encrypted blob to `{storage_path}/{app_id}.key.enc`
    ///    on the parent via vsock
    pub async fn encrypt_and_backup(
        &self,
        app_id: &str,
        private_key: &[u8],
    ) -> TappResult<()> {
        info!(app_id = %app_id, "Starting KMS key backup");

        // Step 1: Get attestation document from NSM
        let attestation_doc = self.get_attestation_document()?;
        debug!(
            app_id = %app_id,
            attestation_doc_len = attestation_doc.len(),
            "Obtained NSM attestation document for KMS Encrypt"
        );

        // Step 2: Build encryption context (ties ciphertext to this app)
        let encryption_context = self.build_encryption_context(app_id);

        // Step 3: Call KMS Encrypt
        let ciphertext = self
            .kms_encrypt(private_key, &attestation_doc, &encryption_context)
            .await?;

        info!(
            app_id = %app_id,
            ciphertext_len = ciphertext.len(),
            "KMS encryption successful"
        );

        // Step 4: Write encrypted blob to parent storage
        let blob_path = self.blob_path(app_id);
        self.write_file_to_parent(&blob_path, &ciphertext).await?;

        info!(
            app_id = %app_id,
            path = %blob_path,
            "Key backup written to parent storage"
        );

        Ok(())
    }

    /// Recover a private key for the given app from the encrypted backup.
    ///
    /// 1. Reads the encrypted blob from parent storage
    /// 2. Gets a fresh NSM attestation document
    /// 3. Calls KMS Decrypt with the Recipient attestation document
    /// 4. Returns the decrypted private key
    ///
    /// If the backup file does not exist, returns an error.
    pub async fn recover_key(&self, app_id: &str) -> TappResult<Zeroizing<Vec<u8>>> {
        info!(app_id = %app_id, "Attempting key recovery from KMS backup");

        // Step 1: Read encrypted blob from parent
        let blob_path = self.blob_path(app_id);
        let ciphertext = self.read_file_from_parent(&blob_path).await?;

        debug!(
            app_id = %app_id,
            ciphertext_len = ciphertext.len(),
            "Read encrypted blob from parent"
        );

        // Step 2: Get fresh attestation document
        let attestation_doc = self.get_attestation_document()?;

        // Step 3: Build encryption context (must match what was used for encryption)
        let encryption_context = self.build_encryption_context(app_id);

        // Step 4: Call KMS Decrypt
        let plaintext = self
            .kms_decrypt(&ciphertext, &attestation_doc, &encryption_context)
            .await?;

        info!(app_id = %app_id, "Key recovery from KMS backup successful");

        Ok(plaintext)
    }

    /// Check if an encrypted backup exists for the given app.
    /// Returns Err on connectivity issues — caller must NOT treat errors as "no backup".
    pub async fn has_backup(&self, app_id: &str) -> Result<bool, crate::error::TappError> {
        let blob_path = self.blob_path(app_id);
        self.file_exists_on_parent(&blob_path).await.map_err(|e| {
            error!(
                app_id = %app_id,
                error = %e,
                "Failed to check backup existence — connectivity issue, NOT treating as 'no backup'"
            );
            crate::error::TappError::Internal(format!(
                "Cannot verify backup status for '{}': {}. Refusing to proceed.",
                app_id, e
            ))
        })
    }

    /// Verify that the backup for an app matches the provided in-memory key.
    ///
    /// This should be called before planned restarts/updates to ensure
    /// the backup is valid and can be recovered.
    ///
    /// Returns `Ok(true)` if the backup decrypts to the same key,
    /// `Ok(false)` if it decrypts to a different key, or an error if
    /// decryption fails entirely.
    pub async fn verify_backup(
        &self,
        app_id: &str,
        in_memory_key: &[u8],
    ) -> TappResult<bool> {
        info!(app_id = %app_id, "Verifying KMS key backup integrity");

        let recovered = self.recover_key(app_id).await?;

        // Constant-time comparison to avoid timing side channels
        let matches = constant_time_eq(in_memory_key, &recovered);

        if matches {
            info!(app_id = %app_id, "Backup verification PASSED");
        } else {
            error!(app_id = %app_id, "Backup verification FAILED - backup does not match in-memory key");
        }

        Ok(matches)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the encryption context map for a given app.
    fn build_encryption_context(&self, app_id: &str) -> HashMap<String, String> {
        let mut ctx = HashMap::new();
        ctx.insert("app_id".to_string(), app_id.to_string());
        ctx.insert("service".to_string(), "tapp".to_string());
        ctx
    }

    /// Compute the storage path for an app's encrypted key blob.
    fn blob_path(&self, app_id: &str) -> String {
        // Sanitize app_id: only allow alphanumeric, dash, underscore
        let safe_id: String = app_id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if safe_id.is_empty() {
            // Fallback for pathological input
            format!("{}/unknown.key.enc", self.storage_path)
        } else {
            format!("{}/{}.key.enc", self.storage_path, safe_id)
        }
    }

    /// Get an attestation document from NSM for use as a KMS Recipient.
    #[cfg(feature = "nitro")]
    fn get_attestation_document(&self) -> TappResult<Vec<u8>> {
        use crate::tee::nitro::NitroProvider;
        // Empty user_data and nonce — the attestation doc is used only for
        // the KMS Recipient field, where PCRs are what matter.
        NitroProvider::nsm_get_attestation_doc(&[], &[]).map_err(|e| {
            TappError::Internal(format!(
                "Failed to get NSM attestation document for KMS: {}",
                e
            ))
        })
    }

    #[cfg(not(feature = "nitro"))]
    fn get_attestation_document(&self) -> TappResult<Vec<u8>> {
        Err(TappError::Internal(
            "KMS key persistence requires the 'nitro' feature (Nitro Enclave environment)"
                .to_string(),
        ))
    }

    /// Call AWS KMS Encrypt with Nitro Recipient attestation.
    #[cfg(feature = "nitro")]
    async fn kms_encrypt(
        &self,
        plaintext: &[u8],
        attestation_doc: &[u8],
        encryption_context: &HashMap<String, String>,
    ) -> TappResult<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let request = KmsEncryptRequest {
            key_id: self.kms_key_id.clone(),
            plaintext: STANDARD.encode(plaintext),
            encryption_context: encryption_context.clone(),
            recipient: Some(KmsRecipientInfo {
                key_encryption_algorithm: "RSAES_OAEP_SHA_256".to_string(),
                attestation_document: STANDARD.encode(attestation_doc),
            }),
        };

        let url = format!(
            "https://kms.{}.amazonaws.com/",
            self.region
        );

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "TrentService.Encrypt")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                TappError::Internal(format!("KMS Encrypt HTTP request failed: {}", e))
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| {
            TappError::Internal(format!("Failed to read KMS Encrypt response: {}", e))
        })?;

        if !status.is_success() {
            let kms_err: KmsErrorResponse =
                serde_json::from_str(&body).unwrap_or(KmsErrorResponse {
                    error_type: Some("Unknown".to_string()),
                    message: Some(body.clone()),
                });
            return Err(TappError::Internal(format!(
                "KMS Encrypt failed (HTTP {}): {} - {}",
                status,
                kms_err.error_type.unwrap_or_default(),
                kms_err.message.unwrap_or_default(),
            )));
        }

        let kms_response: KmsEncryptResponse = serde_json::from_str(&body).map_err(|e| {
            TappError::Internal(format!("Failed to parse KMS Encrypt response: {}", e))
        })?;

        // In Nitro Recipient mode, the actual ciphertext is in CiphertextForRecipient.
        // This is a CMS EnvelopedData structure that only the enclave can unwrap.
        // We store the *standard* CiphertextBlob which can be passed to KMS Decrypt
        // (KMS will re-encrypt for the new attestation document on decrypt).
        let ciphertext_b64 = kms_response.ciphertext_for_recipient
            .or(Some(kms_response.ciphertext_blob))
            .unwrap_or_default();

        // Store as raw bytes (the blob itself is already encrypted)
        STANDARD.decode(&ciphertext_b64).map_err(|e| {
            TappError::Internal(format!("Failed to decode KMS ciphertext: {}", e))
        })
    }

    #[cfg(not(feature = "nitro"))]
    async fn kms_encrypt(
        &self,
        _plaintext: &[u8],
        _attestation_doc: &[u8],
        _encryption_context: &HashMap<String, String>,
    ) -> TappResult<Vec<u8>> {
        Err(TappError::Internal(
            "KMS Encrypt requires the 'nitro' feature".to_string(),
        ))
    }

    /// Call AWS KMS Decrypt with Nitro Recipient attestation.
    #[cfg(feature = "nitro")]
    async fn kms_decrypt(
        &self,
        ciphertext: &[u8],
        attestation_doc: &[u8],
        encryption_context: &HashMap<String, String>,
    ) -> TappResult<Zeroizing<Vec<u8>>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let request = KmsDecryptRequest {
            ciphertext_blob: STANDARD.encode(ciphertext),
            encryption_context: encryption_context.clone(),
            recipient: Some(KmsRecipientInfo {
                key_encryption_algorithm: "RSAES_OAEP_SHA_256".to_string(),
                attestation_document: STANDARD.encode(attestation_doc),
            }),
        };

        let url = format!(
            "https://kms.{}.amazonaws.com/",
            self.region
        );

        let response = self
            .http_client
            .post(&url)
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "TrentService.Decrypt")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                TappError::Internal(format!("KMS Decrypt HTTP request failed: {}", e))
            })?;

        let status = response.status();
        let body = response.text().await.map_err(|e| {
            TappError::Internal(format!("Failed to read KMS Decrypt response: {}", e))
        })?;

        if !status.is_success() {
            let kms_err: KmsErrorResponse =
                serde_json::from_str(&body).unwrap_or(KmsErrorResponse {
                    error_type: Some("Unknown".to_string()),
                    message: Some(body.clone()),
                });
            return Err(TappError::Internal(format!(
                "KMS Decrypt failed (HTTP {}): {} - {}",
                status,
                kms_err.error_type.unwrap_or_default(),
                kms_err.message.unwrap_or_default(),
            )));
        }

        let kms_response: KmsDecryptResponse = serde_json::from_str(&body).map_err(|e| {
            TappError::Internal(format!("Failed to parse KMS Decrypt response: {}", e))
        })?;

        // In Nitro Recipient mode, the plaintext is delivered encrypted to the
        // enclave via CiphertextForRecipient. The NSM will have decrypted it
        // and the Plaintext field should contain the actual key material.
        // In practice with the Recipient field, KMS returns the plaintext
        // re-encrypted for the enclave's attestation document.
        let plaintext_b64 = kms_response
            .plaintext
            .ok_or_else(|| {
                TappError::Internal(
                    "KMS Decrypt response missing Plaintext field".to_string(),
                )
            })?;

        let plaintext = STANDARD.decode(&plaintext_b64).map_err(|e| {
            TappError::Internal(format!("Failed to decode KMS plaintext: {}", e))
        })?;

        Ok(Zeroizing::new(plaintext))
    }

    #[cfg(not(feature = "nitro"))]
    async fn kms_decrypt(
        &self,
        _ciphertext: &[u8],
        _attestation_doc: &[u8],
        _encryption_context: &HashMap<String, String>,
    ) -> TappResult<Zeroizing<Vec<u8>>> {
        Err(TappError::Internal(
            "KMS Decrypt requires the 'nitro' feature".to_string(),
        ))
    }

    // -----------------------------------------------------------------------
    // Parent filesystem operations via vsock
    // -----------------------------------------------------------------------

    /// Write a file to the parent EC2 instance via the vsock proxy.
    #[cfg(feature = "nitro")]
    async fn write_file_to_parent(&self, path: &str, data: &[u8]) -> TappResult<()> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let request = FileProxyRequest {
            command: "write_file".to_string(),
            path: path.to_string(),
            data: Some(STANDARD.encode(data)),
        };

        let response = self.send_file_proxy_request(&request).await?;

        if !response.success {
            return Err(TappError::Internal(format!(
                "Failed to write file to parent: {}",
                response.error
            )));
        }

        Ok(())
    }

    #[cfg(not(feature = "nitro"))]
    async fn write_file_to_parent(&self, path: &str, data: &[u8]) -> TappResult<()> {
        // Non-Nitro fallback: write to local filesystem (for testing)
        let parent = Path::new(path).parent();
        if let Some(dir) = parent {
            tokio::fs::create_dir_all(dir).await.map_err(|e| {
                TappError::Internal(format!("Failed to create directory {:?}: {}", dir, e))
            })?;
        }
        tokio::fs::write(path, data).await.map_err(|e| {
            TappError::Internal(format!("Failed to write file {}: {}", path, e))
        })
    }

    /// Read a file from the parent EC2 instance via the vsock proxy.
    #[cfg(feature = "nitro")]
    async fn read_file_from_parent(&self, path: &str) -> TappResult<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let request = FileProxyRequest {
            command: "read_file".to_string(),
            path: path.to_string(),
            data: None,
        };

        let response = self.send_file_proxy_request(&request).await?;

        if !response.success {
            return Err(TappError::Internal(format!(
                "Failed to read file from parent: {}",
                response.error
            )));
        }

        STANDARD.decode(&response.data).map_err(|e| {
            TappError::Internal(format!("Failed to decode file data from parent: {}", e))
        })
    }

    #[cfg(not(feature = "nitro"))]
    async fn read_file_from_parent(&self, path: &str) -> TappResult<Vec<u8>> {
        tokio::fs::read(path).await.map_err(|e| {
            TappError::Internal(format!("Failed to read file {}: {}", path, e))
        })
    }

    /// Check if a file exists on the parent EC2 instance.
    #[cfg(feature = "nitro")]
    async fn file_exists_on_parent(&self, path: &str) -> TappResult<bool> {
        let request = FileProxyRequest {
            command: "file_exists".to_string(),
            path: path.to_string(),
            data: None,
        };

        let response = self.send_file_proxy_request(&request).await?;
        Ok(response.exists)
    }

    #[cfg(not(feature = "nitro"))]
    async fn file_exists_on_parent(&self, path: &str) -> TappResult<bool> {
        Ok(Path::new(path).exists())
    }

    /// Send a request to the file proxy on the parent via vsock.
    ///
    /// Uses the same length-prefixed JSON wire format as the Docker proxy
    /// but on a dedicated port to separate concerns.
    #[cfg(feature = "nitro")]
    async fn send_file_proxy_request(
        &self,
        request: &FileProxyRequest,
    ) -> TappResult<FileProxyResponse> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// vsock CID for the parent (always 3 in Nitro Enclaves).
        const PARENT_CID: u32 = 3;
        /// Dedicated vsock port for file proxy operations.
        /// Separate from the Docker proxy port (50052) to maintain isolation.
        const FILE_PROXY_PORT: u32 = 50053;

        let payload = serde_json::to_vec(request).map_err(|e| {
            TappError::Internal(format!("Failed to serialize file proxy request: {}", e))
        })?;

        let addr = tokio_vsock::VsockAddr::new(PARENT_CID, FILE_PROXY_PORT);
        let mut stream = tokio_vsock::VsockStream::connect(addr).await.map_err(|e| {
            TappError::Internal(format!(
                "Failed to connect to parent file proxy (CID={}, port={}): {}",
                PARENT_CID, FILE_PROXY_PORT, e
            ))
        })?;

        // Write length-prefixed JSON
        let len_bytes = (payload.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await.map_err(|e| {
            TappError::Internal(format!("Failed to write to file proxy: {}", e))
        })?;
        stream.write_all(&payload).await.map_err(|e| {
            TappError::Internal(format!("Failed to write payload to file proxy: {}", e))
        })?;
        stream.flush().await.ok();

        // Read response
        let mut resp_len_buf = [0u8; 4];
        stream.read_exact(&mut resp_len_buf).await.map_err(|e| {
            TappError::Internal(format!("Failed to read file proxy response length: {}", e))
        })?;
        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;

        // Reject absurdly large responses (>16 MiB)
        if resp_len > 16 * 1024 * 1024 {
            return Err(TappError::Internal(format!(
                "File proxy response too large: {} bytes",
                resp_len
            )));
        }

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.map_err(|e| {
            TappError::Internal(format!("Failed to read file proxy response body: {}", e))
        })?;

        serde_json::from_slice(&resp_buf).map_err(|e| {
            TappError::Internal(format!("Failed to parse file proxy response: {}", e))
        })
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Constant-time byte comparison to prevent timing side channels on key material.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        let a = b"short";
        let b = b"longer string";
        assert!(!constant_time_eq(a, b));
    }

    #[test]
    fn test_blob_path_normal() {
        let config = KmsConfig {
            kms_key_id: "arn:aws:kms:us-east-1:123456:key/abc".to_string(),
            storage_path: "/opt/tapp/keys".to_string(),
            region: "us-east-1".to_string(),
        };
        let persistence = KmsPersistence {
            kms_key_id: config.kms_key_id,
            storage_path: config.storage_path,
            region: config.region,
            #[cfg(feature = "nitro")]
            http_client: reqwest::Client::new(),
        };
        assert_eq!(
            persistence.blob_path("my-app-123"),
            "/opt/tapp/keys/my-app-123.key.enc"
        );
    }

    #[test]
    fn test_blob_path_sanitization() {
        let config = KmsConfig {
            kms_key_id: "arn:aws:kms:us-east-1:123456:key/abc".to_string(),
            storage_path: "/opt/tapp/keys".to_string(),
            region: "us-east-1".to_string(),
        };
        let persistence = KmsPersistence {
            kms_key_id: config.kms_key_id,
            storage_path: config.storage_path,
            region: config.region,
            #[cfg(feature = "nitro")]
            http_client: reqwest::Client::new(),
        };
        // Path traversal attempt should be sanitized
        assert_eq!(
            persistence.blob_path("../../../etc/passwd"),
            "/opt/tapp/keys/etcpasswd.key.enc"
        );
    }

    #[test]
    fn test_blob_path_empty_after_sanitization() {
        let config = KmsConfig {
            kms_key_id: "arn:aws:kms:us-east-1:123456:key/abc".to_string(),
            storage_path: "/opt/tapp/keys".to_string(),
            region: "us-east-1".to_string(),
        };
        let persistence = KmsPersistence {
            kms_key_id: config.kms_key_id,
            storage_path: config.storage_path,
            region: config.region,
            #[cfg(feature = "nitro")]
            http_client: reqwest::Client::new(),
        };
        assert_eq!(
            persistence.blob_path("../../.."),
            "/opt/tapp/keys/unknown.key.enc"
        );
    }

    #[test]
    fn test_build_encryption_context() {
        let config = KmsConfig {
            kms_key_id: "arn:aws:kms:us-east-1:123456:key/abc".to_string(),
            storage_path: "/opt/tapp/keys".to_string(),
            region: "us-east-1".to_string(),
        };
        let persistence = KmsPersistence {
            kms_key_id: config.kms_key_id,
            storage_path: config.storage_path,
            region: config.region,
            #[cfg(feature = "nitro")]
            http_client: reqwest::Client::new(),
        };
        let ctx = persistence.build_encryption_context("test-app");
        assert_eq!(ctx.get("app_id").unwrap(), "test-app");
        assert_eq!(ctx.get("service").unwrap(), "tapp");
        assert_eq!(ctx.len(), 2);
    }
}
