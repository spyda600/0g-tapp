pub mod kbs_client;
pub mod kms_persistence;
pub use kbs_client::KbsClient;
pub use kms_persistence::KmsPersistence;

use crate::config::{KbsConfig, KmsConfig};
use crate::error::{DockerError, TappError, TappResult};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

/// Ethereum key pair
///
/// Private key material is wrapped in `Zeroizing` to ensure it is securely
/// erased from memory when dropped. Clone is intentionally not derived to
/// prevent uncontrolled duplication of private key material.
pub struct EthKeyPair {
    pub private_key: Zeroizing<Vec<u8>>, // 32-byte private key (zeroized on drop)
    pub public_key: Vec<u8>,              // 64-byte uncompressed public key (without 0x04 prefix)
    pub eth_address: Vec<u8>,             // 20-byte Ethereum address
    pub x25519_public_key: Option<Vec<u8>>, // 32-byte X25519 public key
}

impl EthKeyPair {
    /// Create a duplicate of this key pair with separately allocated (and zeroized) private key.
    /// This is intentionally not `Clone` to make private key duplication explicit.
    fn duplicate(&self) -> Self {
        EthKeyPair {
            private_key: Zeroizing::new(self.private_key.to_vec()),
            public_key: self.public_key.clone(),
            eth_address: self.eth_address.clone(),
            x25519_public_key: self.x25519_public_key.clone(),
        }
    }
}

/// Application key service implementation
pub struct AppKeyService {
    kbs_client: Option<KbsClient>,
    /// In-memory key storage: app_id -> EthKeyPair
    app_keys: Mutex<HashMap<String, EthKeyPair>>,
    /// Whether to use in-memory keys (if false, use KBS)
    use_in_memory: bool,
    /// Optional KMS-based key persistence for Nitro Enclaves.
    /// When present, keys are encrypted and backed up to the parent EC2
    /// instance so they survive enclave restarts.
    kms_persistence: Option<KmsPersistence>,
}

impl AppKeyService {
    /// Create new app key service
    pub async fn new(
        kbs_config: Option<&KbsConfig>,
        use_in_memory: bool,
        kms_config: Option<&KmsConfig>,
    ) -> TappResult<Self> {
        let kbs_client = if let Some(config) = kbs_config {
            info!(endpoint = %config.endpoint, "Initializing KBS client");
            Some(KbsClient::new(&config.endpoint).await?)
        } else {
            info!("KBS client not initialized (in-memory mode)");
            None
        };

        let kms_persistence = match kms_config {
            Some(config) => match KmsPersistence::new(config) {
                Ok(kms) => {
                    info!(
                        kms_key_id = %config.kms_key_id,
                        "KMS key persistence enabled - keys will survive enclave restarts"
                    );
                    Some(kms)
                }
                Err(e) => {
                    // LOUD warning: key persistence is configured but failed to initialize.
                    // Fall back to in-memory only. This means keys WILL be lost on restart.
                    error!(
                        error = %e,
                        "CRITICAL: KMS persistence configured but failed to initialize! \
                         Keys will NOT be persisted across restarts. \
                         Funds may be at risk if the enclave restarts."
                    );
                    warn!("Falling back to in-memory-only key storage (NO PERSISTENCE)");
                    None
                }
            },
            None => {
                if use_in_memory {
                    warn!(
                        "No KMS persistence configured. In-memory keys will be lost on restart. \
                         Configure [kms] in config.toml for production deployments."
                    );
                }
                None
            }
        };

        info!(
            use_in_memory = use_in_memory,
            has_kbs_client = kbs_client.is_some(),
            has_kms_persistence = kms_persistence.is_some(),
            "Initialized app key service"
        );

        Ok(Self {
            kbs_client,
            app_keys: Mutex::new(HashMap::new()),
            use_in_memory,
            kms_persistence,
        })
    }

    /// Generate a new Ethereum key pair for an app
    fn generate_eth_keypair(x25519: bool) -> TappResult<EthKeyPair> {
        use k256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let private_key = Zeroizing::new(signing_key.to_bytes().to_vec());
        let verifying_key = signing_key.verifying_key();

        // Get uncompressed public key
        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        // Remove the 0x04 prefix to get 64 bytes for address calculation
        let public_key_without_prefix = &public_key_bytes[1..];

        // Store complete public key (with prefix) if needed
        let public_key = public_key_bytes.to_vec();

        // Generate x25519 key pair if requested
        // Compatible with eciesjs: directly use secp256k1 private key as x25519 private key
        let x25519_public_key = if x25519 {
            // Convert secp256k1 private key to x25519 private key
            // eciesjs uses the same 32-byte private key for both secp256k1 and x25519
            let mut x25519_private_bytes = [0u8; 32];
            x25519_private_bytes.copy_from_slice(&private_key[..32]);

            // Create x25519 secret from the same private key
            let x25519_secret = x25519_dalek::StaticSecret::from(x25519_private_bytes);

            // Zeroize the stack copy of private key bytes
            x25519_private_bytes.zeroize();

            // Derive x25519 public key
            let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

            Some(x25519_public.as_bytes().to_vec())
        } else {
            None
        };

        // Calculate Ethereum address from 64-byte public key (without prefix)
        let mut hasher = Keccak256::new();
        hasher.update(public_key_without_prefix);
        let hash = hasher.finalize();
        let eth_address = hash[12..].to_vec(); // Last 20 bytes

        Ok(EthKeyPair {
            private_key,
            public_key,
            eth_address,
            x25519_public_key,
        })
    }

    /// Get or create key for an app (in-memory mode with optional KMS persistence).
    ///
    /// Flow:
    /// 1. If key exists in memory, return it.
    /// 2. If KMS persistence is configured, attempt to recover from backup.
    /// 3. If no backup exists (or KMS is unavailable), generate a new key.
    /// 4. If a new key was generated and KMS is configured, back it up.
    async fn get_or_create_in_memory_key(
        &self,
        app_id: &str,
        x25519: bool,
    ) -> TappResult<EthKeyPair> {
        let mut keys = self.app_keys.lock().await;

        // Step 1: Check in-memory cache
        if let Some(key_pair) = keys.get(app_id) {
            debug!(app_id = %app_id, "Using existing in-memory key");
            return Ok(key_pair.duplicate());
        }

        // Step 2: Attempt KMS recovery if persistence is configured
        if let Some(ref kms) = self.kms_persistence {
            // has_backup returns Err on connectivity issues — propagate the error
            // rather than assuming no backup (which would generate a new key).
            if kms.has_backup(app_id).await? {
                info!(app_id = %app_id, "Found KMS backup, attempting key recovery");
                match kms.recover_key(app_id).await {
                    Ok(recovered_private_key) => {
                        info!(app_id = %app_id, "Successfully recovered key from KMS backup");
                        let key_pair =
                            Self::reconstruct_keypair_from_private_key(&recovered_private_key, x25519)?;
                        let result = key_pair.duplicate();
                        keys.insert(app_id.to_string(), key_pair);
                        return Ok(result);
                    }
                    Err(e) => {
                        // SAFETY: A backup EXISTS but decryption FAILED.
                        // DO NOT generate a new key — that would make the old key's
                        // funds permanently inaccessible.
                        // This could be: PCR mismatch (update without policy change),
                        // transient KMS error, or network issue.
                        // The operator must fix the issue and retry.
                        error!(
                            app_id = %app_id,
                            error = %e,
                            "CRITICAL: KMS key recovery failed! A backup exists but could not be \
                             decrypted. REFUSING to generate a new key to prevent fund loss. \
                             Check: 1) KMS key policy includes current PCR0, \
                             2) IAM instance profile is attached, \
                             3) Network connectivity to KMS. \
                             Use the emergency backup if KMS cannot be restored."
                        );
                        return Err(crate::error::TappError::Internal(format!(
                            "Key recovery failed for app '{}': backup exists but cannot be decrypted. \
                             Refusing to generate new key to prevent fund loss. Error: {}",
                            app_id, e
                        )));
                    }
                }
            } else {
                debug!(app_id = %app_id, "No KMS backup found, will generate new key");
            }
        }

        // Step 3: Generate new key
        info!(
            app_id = %app_id,
            x25519_enabled = x25519,
            "Generating new in-memory key"
        );
        let key_pair = Self::generate_eth_keypair(x25519)?;

        // Step 4: Back up to KMS if persistence is configured
        if let Some(ref kms) = self.kms_persistence {
            match kms.encrypt_and_backup(app_id, &key_pair.private_key).await {
                Ok(()) => {
                    info!(app_id = %app_id, "New key backed up to KMS successfully");
                }
                Err(e) => {
                    // SAFETY: Backup failed. Do NOT serve an unbacked key.
                    // If we returned it and the enclave crashes, the key and
                    // any funds sent to its address would be permanently lost.
                    error!(
                        app_id = %app_id,
                        error = %e,
                        "CRITICAL: Failed to backup new key to KMS! Refusing to serve \
                         an unbacked key to prevent potential fund loss. \
                         Fix KMS connectivity and retry."
                    );
                    return Err(crate::error::TappError::Internal(format!(
                        "Key generated but KMS backup failed for app '{}'. \
                         Refusing to serve unbacked key to prevent fund loss. Error: {}",
                        app_id, e
                    )));
                }
            }
        }

        // Return a duplicate; store the original in the map
        let result = key_pair.duplicate();
        keys.insert(app_id.to_string(), key_pair);

        Ok(result)
    }

    /// Reconstruct a full EthKeyPair from a recovered private key.
    fn reconstruct_keypair_from_private_key(
        private_key_bytes: &[u8],
        x25519: bool,
    ) -> TappResult<EthKeyPair> {
        if private_key_bytes.len() != 32 {
            return Err(DockerError::ContainerOperationFailed {
                operation: "reconstruct_keypair".to_string(),
                reason: format!(
                    "Recovered private key must be 32 bytes, got {}",
                    private_key_bytes.len()
                ),
            }
            .into());
        }

        let signing_key = SigningKey::from_slice(private_key_bytes).map_err(|e| {
            DockerError::ContainerOperationFailed {
                operation: "reconstruct_keypair".to_string(),
                reason: format!("Invalid recovered private key: {}", e),
            }
        })?;

        let private_key = Zeroizing::new(private_key_bytes.to_vec());
        let verifying_key = signing_key.verifying_key();

        let public_key_point = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key_point.as_bytes();
        let public_key_without_prefix = &public_key_bytes[1..];
        let public_key = public_key_bytes.to_vec();

        let x25519_public_key = if x25519 {
            let mut x25519_private_bytes = [0u8; 32];
            x25519_private_bytes.copy_from_slice(&private_key[..32]);
            let x25519_secret = x25519_dalek::StaticSecret::from(x25519_private_bytes);
            x25519_private_bytes.zeroize();
            let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);
            Some(x25519_public.as_bytes().to_vec())
        } else {
            None
        };

        let mut hasher = Keccak256::new();
        hasher.update(public_key_without_prefix);
        let hash = hasher.finalize();
        let eth_address = hash[12..].to_vec();

        Ok(EthKeyPair {
            private_key,
            public_key,
            eth_address,
            x25519_public_key,
        })
    }

    /// Verify that the KMS backup for an app matches the current in-memory key.
    ///
    /// Call this before planned restarts or enclave updates to ensure keys
    /// can be recovered. Returns `Ok(true)` if backup matches, `Ok(false)` if
    /// mismatch, or an error if verification cannot be performed.
    pub async fn verify_key_backup(&self, app_id: &str) -> TappResult<bool> {
        let kms = self.kms_persistence.as_ref().ok_or_else(|| {
            TappError::Internal(
                "KMS persistence not configured - cannot verify backup".to_string(),
            )
        })?;

        let keys = self.app_keys.lock().await;
        let key_pair = keys.get(app_id).ok_or_else(|| {
            DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
        })?;

        // Drop the lock before the async KMS call
        let private_key_copy = Zeroizing::new(key_pair.private_key.to_vec());
        drop(keys);

        kms.verify_backup(app_id, &private_key_copy).await
    }

    /// Get private key for an app (internal use only)
    /// WARNING: This returns sensitive private key material wrapped in Zeroizing
    /// to ensure it is erased from memory when dropped.
    pub async fn get_private_key(&self, app_id: &str) -> TappResult<Zeroizing<Vec<u8>>> {
        if !self.use_in_memory {
            return Err(DockerError::ContainerOperationFailed {
                operation: "get_private_key".to_string(),
                reason: "Private key retrieval only supported in in-memory mode".to_string(),
            }
            .into());
        }

        let keys = self.app_keys.lock().await;
        if let Some(key_pair) = keys.get(app_id) {
            warn!(
                app_id = %app_id,
                "Private key retrieved - ensure this is for local access only"
            );
            Ok(Zeroizing::new(key_pair.private_key.to_vec()))
        } else {
            Err(DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
            .into())
        }
    }

    /// Get public key for an app (internal use only)
    pub async fn get_public_key(
        &self,
        app_id: &str,
    ) -> TappResult<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
        if !self.use_in_memory {
            return Err(DockerError::ContainerOperationFailed {
                operation: "get_public_key".to_string(),
                reason: "Public key retrieval only supported in in-memory mode".to_string(),
            }
            .into());
        }

        let keys = self.app_keys.lock().await;
        if let Some(key_pair) = keys.get(app_id) {
            Ok((
                key_pair.eth_address.clone(),
                key_pair.public_key.clone(),
                key_pair.x25519_public_key.clone(),
            ))
        } else {
            Err(DockerError::ServiceNotFound {
                service_name: format!("Key for app_id: {}", app_id),
            }
            .into())
        }
    }

    /// List all app IDs that currently have keys in memory.
    /// Used by update safety checks to enumerate keys that need backup verification.
    pub async fn list_app_ids(&self) -> Vec<String> {
        let keys = self.app_keys.lock().await;
        keys.keys().cloned().collect()
    }

    /// Get a snapshot of all keys for backup purposes.
    /// Returns (app_id, private_key_bytes, eth_address_hex) for each key.
    ///
    /// SECURITY: This method exists solely for emergency backup. The caller is
    /// responsible for encrypting the returned key material immediately and
    /// zeroizing any intermediate buffers.
    pub async fn snapshot_all_keys(&self) -> TappResult<Vec<(String, Vec<u8>, String)>> {
        let keys = self.app_keys.lock().await;
        let mut result = Vec::with_capacity(keys.len());
        for (app_id, key_pair) in keys.iter() {
            let eth_addr_hex = format!("0x{}", hex::encode(&key_pair.eth_address));
            result.push((app_id.clone(), key_pair.private_key.to_vec(), eth_addr_hex));
        }
        Ok(result)
    }

    /// Handle get app key request (public key only - for gRPC)
    pub async fn get_app_key(
        &self,
        app_id: &str,
        key_type: &str,
        x25519: bool,
    ) -> TappResult<EthKeyPair> {
        info!(
            app_id = %app_id,
            key_type = %key_type,
            use_in_memory = self.use_in_memory,
            "Processing app key request"
        );

        if self.use_in_memory {
            // Use in-memory key generation
            match key_type {
                "ethereum" => {
                    let key_pair = self.get_or_create_in_memory_key(app_id, x25519).await?;
                    info!(
                        app_id = %app_id,
                        public_key_hex = format!("0x{}", hex::encode(&key_pair.public_key)),
                        eth_address_hex = format!("0x{}", hex::encode(&key_pair.eth_address)),
                        x25519_public_key_hex = format!("0x{:?}", key_pair.x25519_public_key),
                        "Generated new Ethereum key pair"
                    );
                    Ok(key_pair)
                }
                _ => {
                    warn!(key_type = %key_type, "Unsupported key type for in-memory mode");
                    Err(DockerError::ContainerOperationFailed {
                        operation: "get_app_key".to_string(),
                        reason: format!("Unsupported key type: {}", key_type),
                    }
                    .into())
                }
            }
        } else {
            // Use KBS
            let kbs_client =
                self.kbs_client
                    .as_ref()
                    .ok_or_else(|| DockerError::ContainerOperationFailed {
                        operation: "get_app_key".to_string(),
                        reason: "KBS client not configured".to_string(),
                    })?;

            let resource_uri = format!("kbs:///default/key/{}", app_id);
            match kbs_client.get_resource(&resource_uri).await {
                Ok(_key_data) => Ok(EthKeyPair {
                    private_key: Zeroizing::new(vec![]),
                    public_key: _key_data,
                    eth_address: vec![],
                    x25519_public_key: None,
                }),
                Err(e) => {
                    tracing::error!(
                        app_id = %app_id,
                        error = %e,
                        "Failed to retrieve app key from KBS"
                    );
                    Err(e)
                }
            }
        }
    }
}

/// Sign a message using a private key
pub fn sign_message(private_key: &[u8], message: &[u8]) -> TappResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(DockerError::ContainerOperationFailed {
            operation: "sign_message".to_string(),
            reason: format!("Private key must be 32 bytes, got {}", private_key.len()),
        }
        .into());
    }

    let signing_key =
        SigningKey::from_slice(private_key).map_err(|e| DockerError::ContainerOperationFailed {
            operation: "sign_message".to_string(),
            reason: format!("Invalid private key: {}", e),
        })?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature using a public key
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> TappResult<bool> {
    if public_key.len() != 64 {
        return Err(DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Public key must be 64 bytes, got {}", public_key.len()),
        }
        .into());
    }

    // Add 0x04 prefix for uncompressed public key
    let public_key_with_prefix = [&[0x04u8], &public_key[..]].concat();

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_with_prefix).map_err(|e| {
        DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Invalid public key: {}", e),
        }
    })?;

    let sig =
        Signature::from_slice(signature).map_err(|e| DockerError::ContainerOperationFailed {
            operation: "verify_signature".to_string(),
            reason: format!("Invalid signature: {}", e),
        })?;

    match verifying_key.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        // Generate a test key pair
        let key_pair = AppKeyService::generate_eth_keypair(true).unwrap();

        // Test message
        let message = b"Hello, TAPP!";

        // Sign the message
        let signature = sign_message(&key_pair.private_key, message).unwrap();

        // Verify the signature
        let is_valid = verify_signature(&key_pair.public_key, message, &signature).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let is_valid = verify_signature(&key_pair.public_key, wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }
}
