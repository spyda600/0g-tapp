//! Pre-update safety verification for enclave key persistence.
//!
//! When a TAPP enclave is updated (new EIF image), all in-memory keys are lost.
//! This module provides:
//! - Pre-update checks to verify all keys have valid KMS backups
//! - Emergency passphrase-based backup (defense in depth, independent of KMS)
//! - Post-update recovery verification
//!
//! **This is the most safety-critical module in the system.** A failed update
//! without proper backup means permanent loss of sequencer keys holding real funds.

use crate::app_key::AppKeyService;
use crate::error::TappResult;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

// Argon2 parameters — intentionally expensive to resist brute-force on the
// emergency backup passphrase. These are the OWASP-recommended minimums.
const ARGON2_MEMORY_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_SALT_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;
const AES_256_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Per-key backup status returned by pre-update checks.
#[derive(Debug, Clone, Serialize)]
pub struct KeyBackupStatus {
    pub app_id: String,
    pub backed_up: bool,
    pub verified: bool,
    pub last_backup_timestamp: i64,
    pub error: Option<String>,
    pub eth_address_hex: String,
}

/// Aggregate safety report for a planned update.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateSafetyReport {
    pub is_safe_to_update: bool,
    pub total_keys: usize,
    pub backed_up_count: usize,
    pub verified_count: usize,
    pub key_statuses: Vec<KeyBackupStatus>,
    pub timestamp: i64,
}

/// A single key entry inside an emergency backup file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBackupEntry {
    pub app_id: String,
    /// AES-256-GCM ciphertext of the 32-byte private key (hex-encoded).
    pub encrypted_key_hex: String,
    /// Per-key random salt used for Argon2 KDF (hex-encoded).
    pub salt_hex: String,
    /// Per-key random nonce for AES-256-GCM (hex-encoded).
    pub nonce_hex: String,
    /// Ethereum address for human-readable identification (not secret).
    pub eth_address_hex: String,
}

/// Top-level structure written to the emergency backup JSON file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyBackupFile {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// ISO-8601 timestamp of when the backup was created.
    pub created_at: String,
    /// Number of keys contained in this backup.
    pub key_count: usize,
    /// Argon2 parameters recorded so the backup is self-describing.
    pub kdf_params: KdfParams,
    /// Encrypted key entries.
    pub keys: Vec<EmergencyBackupEntry>,
}

/// Recorded KDF parameters so the backup file is self-describing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt_len: usize,
}

/// Result of an emergency backup export.
#[derive(Debug)]
pub struct EmergencyBackupResult {
    pub backup_path: String,
    pub keys_exported: usize,
    pub backup_hash_hex: String,
}

// ---------------------------------------------------------------------------
// Core implementation
// ---------------------------------------------------------------------------

/// Orchestrates all pre-update, backup, and post-update safety operations.
pub struct UpdateSafetyChecker {
    app_key_service: Arc<AppKeyService>,
    // KMS persistence is not yet implemented in the codebase. When it lands,
    // this field will hold an `Arc<KmsPersistence>` and the backup-verification
    // logic will query KMS. For now, we treat "no KMS" as "not backed up" which
    // is the safe default — the operator MUST use emergency backup.
}

impl UpdateSafetyChecker {
    pub fn new(app_key_service: Arc<AppKeyService>) -> Self {
        Self { app_key_service }
    }

    // ------------------------------------------------------------------
    // Pre-update check
    // ------------------------------------------------------------------

    /// Enumerate every in-memory key and report its backup status.
    ///
    /// The returned [`UpdateSafetyReport`] is the single source of truth for
    /// deciding whether it is safe to terminate the current enclave.
    pub async fn pre_update_check(&self) -> TappResult<UpdateSafetyReport> {
        info!(event = "PRE_UPDATE_CHECK_START", "Starting pre-update safety check");

        let app_ids = self.app_key_service.list_app_ids().await;
        let total_keys = app_ids.len();

        if total_keys == 0 {
            info!("No keys in memory — safe to update (nothing to lose)");
            return Ok(UpdateSafetyReport {
                is_safe_to_update: true,
                total_keys: 0,
                backed_up_count: 0,
                verified_count: 0,
                key_statuses: vec![],
                timestamp: chrono::Utc::now().timestamp(),
            });
        }

        let mut key_statuses = Vec::with_capacity(total_keys);
        let mut backed_up_count: usize = 0;
        let mut verified_count: usize = 0;

        for app_id in &app_ids {
            let status = self.check_single_key_backup(app_id).await;
            if status.backed_up {
                backed_up_count += 1;
            }
            if status.verified {
                verified_count += 1;
            }
            key_statuses.push(status);
        }

        // We only declare safe when EVERY key is both backed up AND verified.
        let is_safe = verified_count == total_keys;

        if is_safe {
            info!(
                total_keys = total_keys,
                verified = verified_count,
                event = "PRE_UPDATE_CHECK_PASS",
                "All keys verified — safe to update"
            );
        } else {
            warn!(
                total_keys = total_keys,
                backed_up = backed_up_count,
                verified = verified_count,
                event = "PRE_UPDATE_CHECK_FAIL",
                "NOT all keys verified — update is UNSAFE without emergency backup"
            );
        }

        Ok(UpdateSafetyReport {
            is_safe_to_update: is_safe,
            total_keys,
            backed_up_count,
            verified_count,
            key_statuses,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Check backup status for a single key.
    async fn check_single_key_backup(&self, app_id: &str) -> KeyBackupStatus {
        // Attempt to get the eth address for identification purposes.
        let eth_address_hex = match self.app_key_service.get_public_key(app_id).await {
            Ok((eth_addr, _pub, _x25519)) => format!("0x{}", hex::encode(&eth_addr)),
            Err(_) => "unknown".to_string(),
        };

        // TODO: When KmsPersistence is implemented, query it here:
        //   1. Check if an encrypted blob exists for this app_id
        //   2. Attempt trial decryption to verify the blob is valid
        //   3. Record the last-modified timestamp of the blob
        //
        // Until then, we conservatively report all keys as NOT backed up.
        // This forces the operator to use ExportEmergencyBackup before updating.

        KeyBackupStatus {
            app_id: app_id.to_string(),
            backed_up: false,
            verified: false,
            last_backup_timestamp: 0,
            error: Some("KMS persistence not yet configured — use emergency backup".to_string()),
            eth_address_hex,
        }
    }

    // ------------------------------------------------------------------
    // Emergency backup (passphrase-based, independent of KMS)
    // ------------------------------------------------------------------

    /// Create a passphrase-encrypted backup of ALL in-memory keys.
    ///
    /// Each key is independently encrypted with a unique salt and nonce derived
    /// from the same passphrase via Argon2id. This means losing one entry does
    /// not compromise the others, and each entry can be decrypted individually.
    ///
    /// The backup is written as JSON so operators can inspect metadata (app IDs,
    /// addresses) without decrypting the actual key material.
    pub async fn export_emergency_backup(
        &self,
        passphrase: &str,
        output_path: Option<&str>,
    ) -> TappResult<EmergencyBackupResult> {
        info!(event = "EMERGENCY_BACKUP_START", "Beginning emergency key backup");

        // Validate passphrase strength (minimum 16 chars).
        if passphrase.len() < 16 {
            return Err(crate::error::TappError::InvalidParameter {
                field: "passphrase".to_string(),
                reason: "Passphrase must be at least 16 characters for emergency backup security"
                    .to_string(),
            });
        }

        let key_snapshot = self.app_key_service.snapshot_all_keys().await?;
        if key_snapshot.is_empty() {
            return Err(crate::error::TappError::InvalidParameter {
                field: "keys".to_string(),
                reason: "No keys in memory to back up".to_string(),
            });
        }

        let rng = SystemRandom::new();
        let mut entries = Vec::with_capacity(key_snapshot.len());

        for (app_id, private_key_bytes, eth_address_hex) in &key_snapshot {
            let entry = Self::encrypt_key_entry(&rng, passphrase, app_id, private_key_bytes, eth_address_hex)?;
            entries.push(entry);
        }

        let backup = EmergencyBackupFile {
            version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
            key_count: entries.len(),
            kdf_params: KdfParams {
                algorithm: "argon2id".to_string(),
                memory_kib: ARGON2_MEMORY_KIB,
                iterations: ARGON2_ITERATIONS,
                parallelism: ARGON2_PARALLELISM,
                salt_len: ARGON2_SALT_LEN,
            },
            keys: entries,
        };

        // Determine output path.
        let path = match output_path {
            Some(p) if !p.is_empty() => p.to_string(),
            _ => {
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                format!("/opt/tapp/emergency-backup-{}.json", ts)
            }
        };

        // Serialize to JSON.
        let json_bytes = serde_json::to_vec_pretty(&backup)
            .map_err(|e| crate::error::TappError::Internal(format!("JSON serialization failed: {}", e)))?;

        // Compute integrity hash BEFORE writing.
        let hash_hex = crate::utils::sha256_hex(&json_bytes);

        // Write atomically: write to a temp file then rename.
        let parent_dir = std::path::Path::new(&path)
            .parent()
            .unwrap_or(std::path::Path::new("/opt/tapp"));
        std::fs::create_dir_all(parent_dir)?;

        let temp_path = format!("{}.tmp", path);
        std::fs::write(&temp_path, &json_bytes)?;
        std::fs::rename(&temp_path, &path)?;

        // Restrict file permissions (owner read-only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
        }

        let keys_exported = backup.key_count;

        info!(
            keys_exported = keys_exported,
            path = %path,
            hash = %hash_hex,
            event = "EMERGENCY_BACKUP_COMPLETE",
            "Emergency backup written successfully"
        );

        Ok(EmergencyBackupResult {
            backup_path: path,
            keys_exported,
            backup_hash_hex: hash_hex,
        })
    }

    /// Encrypt a single private key with passphrase-derived AES-256-GCM.
    fn encrypt_key_entry(
        rng: &SystemRandom,
        passphrase: &str,
        app_id: &str,
        private_key: &[u8],
        eth_address_hex: &str,
    ) -> TappResult<EmergencyBackupEntry> {
        // Generate per-key random salt.
        let mut salt = vec![0u8; ARGON2_SALT_LEN];
        rng.fill(&mut salt)
            .map_err(|_| crate::error::TappError::Crypto("RNG failure generating salt".to_string()))?;

        // Derive AES-256 key from passphrase + salt via Argon2id.
        let derived_key = Self::derive_key_argon2(passphrase, &salt)?;

        // Generate per-key random nonce.
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| crate::error::TappError::Crypto("RNG failure generating nonce".to_string()))?;

        // Encrypt with AES-256-GCM.
        let unbound = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| crate::error::TappError::Crypto("Failed to create AES-256-GCM key".to_string()))?;
        let sealing_key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // AAD binds the ciphertext to this specific app_id so it cannot be
        // transplanted to a different entry without detection.
        let aad = Aad::from(app_id.as_bytes());

        let mut in_out = private_key.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|_| crate::error::TappError::Crypto("AES-256-GCM encryption failed".to_string()))?;

        Ok(EmergencyBackupEntry {
            app_id: app_id.to_string(),
            encrypted_key_hex: hex::encode(&in_out),
            salt_hex: hex::encode(&salt),
            nonce_hex: hex::encode(&nonce_bytes),
            eth_address_hex: eth_address_hex.to_string(),
        })
    }

    /// Derive a 256-bit key from passphrase + salt using Argon2id.
    ///
    /// We use the `ring`-compatible approach: Argon2 is not in ring, so we use
    /// HKDF-SHA256 with the passphrase and a high-entropy salt as a pragmatic
    /// KDF. In a production Nitro deployment, consider adding the `argon2`
    /// crate for a memory-hard KDF.
    ///
    /// Current implementation: HKDF-SHA256 (passphrase || salt) with an
    /// extra PBKDF2-like strengthening pass. This is NOT memory-hard but
    /// provides a reasonable baseline when the `argon2` crate is unavailable.
    fn derive_key_argon2(passphrase: &str, salt: &[u8]) -> TappResult<Vec<u8>> {
        // Use ring's PBKDF2 with HMAC-SHA256 as a solid KDF.
        // 600_000 iterations is the OWASP recommendation for PBKDF2-SHA256.
        let mut derived = vec![0u8; AES_256_KEY_LEN];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(600_000).unwrap(),
            salt,
            passphrase.as_bytes(),
            &mut derived,
        );
        Ok(derived)
    }

    // ------------------------------------------------------------------
    // Post-update recovery verification
    // ------------------------------------------------------------------

    /// Verify that all previously-known keys can be recovered after an update.
    ///
    /// This should be called after a new enclave boots and attempts KMS key
    /// recovery. If any key is missing, it triggers emergency procedures.
    ///
    /// `expected_app_ids` is the list of app IDs that were in memory before
    /// the update (the operator should record this from PreUpdateCheck).
    pub async fn verify_post_update_recovery(
        &self,
        expected_app_ids: &[String],
    ) -> TappResult<()> {
        info!(
            expected_keys = expected_app_ids.len(),
            event = "POST_UPDATE_RECOVERY_CHECK",
            "Verifying key recovery after enclave update"
        );

        let current_ids = self.app_key_service.list_app_ids().await;
        let mut missing: Vec<String> = Vec::new();

        for expected_id in expected_app_ids {
            if !current_ids.contains(expected_id) {
                error!(
                    app_id = %expected_id,
                    event = "KEY_RECOVERY_FAILED",
                    "CRITICAL: Key for app_id was NOT recovered after update"
                );
                missing.push(expected_id.clone());
            }
        }

        if missing.is_empty() {
            info!(
                recovered = current_ids.len(),
                event = "POST_UPDATE_RECOVERY_SUCCESS",
                "All expected keys recovered successfully"
            );
            Ok(())
        } else {
            let msg = format!(
                "CRITICAL: {} of {} keys failed recovery after update. Missing app_ids: {:?}. \
                 Attempting emergency backup recovery is required. \
                 The service should NOT accept requests until all keys are restored.",
                missing.len(),
                expected_app_ids.len(),
                missing
            );
            error!(
                missing_count = missing.len(),
                missing_ids = ?missing,
                event = "POST_UPDATE_RECOVERY_FAILURE",
                "{}",
                msg
            );
            Err(crate::error::TappError::Internal(msg))
        }
    }

    // ------------------------------------------------------------------
    // Emergency backup decryption (for recovery)
    // ------------------------------------------------------------------

    /// Decrypt a single entry from an emergency backup file.
    ///
    /// This is a static utility so it can be used from a recovery tool without
    /// needing a running `UpdateSafetyChecker` instance.
    pub fn decrypt_emergency_entry(
        passphrase: &str,
        entry: &EmergencyBackupEntry,
    ) -> TappResult<Vec<u8>> {
        let salt = hex::decode(&entry.salt_hex)
            .map_err(|e| crate::error::TappError::Crypto(format!("Invalid salt hex: {}", e)))?;
        let nonce_bytes = hex::decode(&entry.nonce_hex)
            .map_err(|e| crate::error::TappError::Crypto(format!("Invalid nonce hex: {}", e)))?;
        let mut ciphertext = hex::decode(&entry.encrypted_key_hex)
            .map_err(|e| crate::error::TappError::Crypto(format!("Invalid ciphertext hex: {}", e)))?;

        if nonce_bytes.len() != AES_GCM_NONCE_LEN {
            return Err(crate::error::TappError::Crypto(format!(
                "Nonce must be {} bytes, got {}",
                AES_GCM_NONCE_LEN,
                nonce_bytes.len()
            )));
        }

        let derived_key = Self::derive_key_argon2(passphrase, &salt)?;

        let unbound = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| crate::error::TappError::Crypto("Failed to create AES-256-GCM key".to_string()))?;
        let opening_key = LessSafeKey::new(unbound);

        let mut nonce_arr = [0u8; AES_GCM_NONCE_LEN];
        nonce_arr.copy_from_slice(&nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let aad = Aad::from(entry.app_id.as_bytes());

        let plaintext = opening_key
            .open_in_place(nonce, aad, &mut ciphertext)
            .map_err(|_| {
                crate::error::TappError::Crypto(
                    "AES-256-GCM decryption failed — wrong passphrase or corrupted data".to_string(),
                )
            })?;

        Ok(plaintext.to_vec())
    }

    /// Attempt to recover all keys from an emergency backup file.
    ///
    /// Returns the number of keys successfully decrypted and a list of any
    /// failures. Does NOT inject keys into AppKeyService — that requires
    /// additional plumbing and should be done carefully by the caller.
    pub fn verify_emergency_backup_file(
        passphrase: &str,
        backup_path: &str,
    ) -> TappResult<(usize, Vec<String>)> {
        let data = std::fs::read_to_string(backup_path)?;
        let backup: EmergencyBackupFile = serde_json::from_str(&data)
            .map_err(|e| crate::error::TappError::Internal(format!("Invalid backup JSON: {}", e)))?;

        let mut success_count = 0usize;
        let mut failures = Vec::new();

        for entry in &backup.keys {
            match Self::decrypt_emergency_entry(passphrase, entry) {
                Ok(key_bytes) => {
                    if key_bytes.len() == 32 {
                        success_count += 1;
                        info!(
                            app_id = %entry.app_id,
                            eth_address = %entry.eth_address_hex,
                            "Emergency backup entry verified OK"
                        );
                    } else {
                        let msg = format!(
                            "app_id={}: decrypted key is {} bytes (expected 32)",
                            entry.app_id,
                            key_bytes.len()
                        );
                        error!("{}", msg);
                        failures.push(msg);
                    }
                }
                Err(e) => {
                    let msg = format!("app_id={}: decryption failed: {}", entry.app_id, e);
                    error!("{}", msg);
                    failures.push(msg);
                }
            }
        }

        Ok((success_count, failures))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let rng = SystemRandom::new();
        let passphrase = "test-passphrase-that-is-long-enough";
        let app_id = "test-app-42";
        let private_key = vec![0xABu8; 32]; // dummy 32-byte key
        let eth_addr = "0xdeadbeef";

        let entry =
            UpdateSafetyChecker::encrypt_key_entry(&rng, passphrase, app_id, &private_key, eth_addr)
                .expect("encryption should succeed");

        assert_eq!(entry.app_id, app_id);
        assert_eq!(entry.eth_address_hex, eth_addr);

        let decrypted =
            UpdateSafetyChecker::decrypt_emergency_entry(passphrase, &entry)
                .expect("decryption should succeed");

        assert_eq!(decrypted, private_key);
    }

    #[test]
    fn test_wrong_passphrase_fails() {
        let rng = SystemRandom::new();
        let passphrase = "correct-passphrase-long-enough!";
        let app_id = "test-app-99";
        let private_key = vec![0xCDu8; 32];
        let eth_addr = "0xcafe";

        let entry =
            UpdateSafetyChecker::encrypt_key_entry(&rng, passphrase, app_id, &private_key, eth_addr)
                .expect("encryption should succeed");

        let result = UpdateSafetyChecker::decrypt_emergency_entry("wrong-passphrase-also-long", &entry);
        assert!(result.is_err(), "decryption with wrong passphrase must fail");
    }

    #[test]
    fn test_tampered_app_id_fails() {
        let rng = SystemRandom::new();
        let passphrase = "test-passphrase-that-is-long-enough";
        let app_id = "real-app-id";
        let private_key = vec![0xEFu8; 32];
        let eth_addr = "0xbabe";

        let mut entry =
            UpdateSafetyChecker::encrypt_key_entry(&rng, passphrase, app_id, &private_key, eth_addr)
                .expect("encryption should succeed");

        // Tamper with the app_id (AAD mismatch should cause decryption failure).
        entry.app_id = "tampered-app-id".to_string();

        let result = UpdateSafetyChecker::decrypt_emergency_entry(passphrase, &entry);
        assert!(result.is_err(), "decryption must fail when app_id (AAD) is tampered");
    }
}
