use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Permission level for operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Permission {
    Owner,     // Full control (tapp owner)
    Whitelist, // Can start apps and manage own apps
    Public,    // Read-only access
}

/// App status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    Active,
    Stopped,
}

/// App ownership tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppOwnership {
    pub app_id: String,
    pub owner_address: String, // EVM address of who owns this app (who started it)
    pub started_at: i64,
    pub status: AppStatus,
    pub stopped_at: Option<i64>,
}

/// Permission manager - manages whitelist and app ownership
pub struct PermissionManager {
    /// Tapp owner EVM address (from config)
    tapp_owner_address: String,

    /// Whitelist of EVM addresses allowed to start apps
    whitelist: Arc<RwLock<HashSet<String>>>,

    /// App ownership tracking: app_id -> ownership
    app_ownership: Arc<RwLock<HashMap<String, AppOwnership>>>,
}

impl PermissionManager {
    pub fn new(tapp_owner_address: String) -> Self {
        Self {
            tapp_owner_address: Self::normalize_address(&tapp_owner_address),
            whitelist: Arc::new(RwLock::new(HashSet::new())),
            app_ownership: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Normalize EVM address (lowercase, with 0x prefix)
    fn normalize_address(addr: &str) -> String {
        let addr = addr.trim().to_lowercase();
        if addr.starts_with("0x") {
            addr
        } else {
            format!("0x{}", addr)
        }
    }

    /// Get permission level for an EVM address
    pub async fn get_permission(&self, evm_address: &str) -> Permission {
        let addr = Self::normalize_address(evm_address);

        if addr == self.tapp_owner_address {
            return Permission::Owner;
        }

        if self.whitelist.read().await.contains(&addr) {
            return Permission::Whitelist;
        }

        Permission::Public
    }

    /// Add address to whitelist (tapp owner only)
    pub async fn add_to_whitelist(&self, evm_address: String) -> Result<(), String> {
        let addr = Self::normalize_address(&evm_address);
        self.whitelist.write().await.insert(addr);
        Ok(())
    }

    /// Remove from whitelist (tapp owner only)
    pub async fn remove_from_whitelist(&self, evm_address: &str) -> Result<(), String> {
        let addr = Self::normalize_address(evm_address);
        self.whitelist.write().await.remove(&addr);
        Ok(())
    }

    /// List all whitelisted addresses
    pub async fn list_whitelist(&self) -> Vec<String> {
        self.whitelist.read().await.iter().cloned().collect()
    }

    /// Record app ownership when started
    pub async fn record_app_start(&self, app_id: String, owner_address: String) {
        let ownership = AppOwnership {
            app_id: app_id.clone(),
            owner_address: Self::normalize_address(&owner_address),
            started_at: chrono::Utc::now().timestamp(),
            status: AppStatus::Active,
            stopped_at: None,
        };
        self.app_ownership.write().await.insert(app_id, ownership);
    }

    /// Update app status to stopped
    pub async fn mark_app_stopped(&self, app_id: &str) {
        if let Some(ownership) = self.app_ownership.write().await.get_mut(app_id) {
            ownership.status = AppStatus::Stopped;
            ownership.stopped_at = Some(chrono::Utc::now().timestamp());
        }
    }

    /// Check if user can manage this app
    /// - Tapp owner can manage all apps
    /// - App owner can manage their own running apps
    pub async fn can_manage_app(&self, app_id: &str, evm_address: &str) -> bool {
        let addr = Self::normalize_address(evm_address);

        // Tapp owner can manage all apps
        if addr == self.tapp_owner_address {
            return true;
        }

        // App owner can manage their own running apps
        if let Some(ownership) = self.app_ownership.read().await.get(app_id) {
            return ownership.owner_address == addr && ownership.status == AppStatus::Active;
        }

        false
    }

    /// Get app ownership info
    pub async fn get_app_ownership(&self, app_id: &str) -> Option<AppOwnership> {
        self.app_ownership.read().await.get(app_id).cloned()
    }

    /// List all app ownerships
    pub async fn list_all_ownerships(&self) -> Vec<AppOwnership> {
        self.app_ownership.read().await.values().cloned().collect()
    }

    /// Get tapp owner address
    pub fn get_tapp_owner_address(&self) -> &str {
        &self.tapp_owner_address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_permission_levels() {
        let pm = PermissionManager::new("0x1234567890123456789012345678901234567890".to_string());

        // Test tapp owner
        let perm = pm
            .get_permission("0x1234567890123456789012345678901234567890")
            .await;
        assert_eq!(perm, Permission::Owner);

        // Test public
        let perm = pm
            .get_permission("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
            .await;
        assert_eq!(perm, Permission::Public);

        // Add to whitelist
        pm.add_to_whitelist("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string())
            .await
            .unwrap();
        let perm = pm
            .get_permission("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
            .await;
        assert_eq!(perm, Permission::Whitelist);
    }

    #[tokio::test]
    async fn test_app_ownership_lifecycle() {
        let pm = PermissionManager::new("0x1234567890123456789012345678901234567890".to_string());
        let app_owner = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";

        // Record ownership
        pm.record_app_start("test-app".to_string(), app_owner.to_string())
            .await;

        // App owner can manage running app
        assert!(pm.can_manage_app("test-app", app_owner).await);

        // Stop app
        pm.mark_app_stopped("test-app").await;

        // App owner can't manage stopped app
        assert!(!pm.can_manage_app("test-app", app_owner).await);

        // Tapp owner can still manage stopped apps
        assert!(
            pm.can_manage_app("test-app", "0x1234567890123456789012345678901234567890")
                .await
        );

        // Ownership record still exists
        let ownership = pm.get_app_ownership("test-app").await;
        assert!(ownership.is_some());
        assert_eq!(ownership.unwrap().status, AppStatus::Stopped);
    }

    #[test]
    fn test_address_normalization() {
        let addr1 =
            PermissionManager::normalize_address("1234567890123456789012345678901234567890");
        assert_eq!(addr1, "0x1234567890123456789012345678901234567890");

        let addr2 =
            PermissionManager::normalize_address("0x1234567890123456789012345678901234567890");
        assert_eq!(addr2, "0x1234567890123456789012345678901234567890");

        let addr3 =
            PermissionManager::normalize_address("0X1234567890123456789012345678901234567890");
        assert_eq!(addr3, "0x1234567890123456789012345678901234567890");
    }
}
