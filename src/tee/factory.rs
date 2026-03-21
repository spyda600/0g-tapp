use super::{TeeError, TeeProvider};
use crate::config::TappConfig;
use tracing::{info, warn};

// Compile-time guard: simulation must not be enabled alongside real TEE features.
// This prevents accidental production builds that could be downgraded to simulation.
#[cfg(all(feature = "simulation", feature = "nitro"))]
compile_error!("Cannot enable both 'simulation' and 'nitro' features. Use only one TEE provider per build.");

#[cfg(all(feature = "simulation", feature = "tdx"))]
compile_error!("Cannot enable both 'simulation' and 'tdx' features. Use only one TEE provider per build.");

/// Create the appropriate TEE provider based on configuration and feature flags.
///
/// Provider selection priority (when auto-detecting):
/// 1. TDX (if compiled with --features tdx)
/// 2. Nitro (if compiled with --features nitro)
/// 3. Simulation (if compiled with --features simulation) — development only
pub fn create_tee_provider(config: &TappConfig) -> Result<Box<dyn TeeProvider>, TeeError> {
    // Check explicit config first
    if let Some(ref tee_type) = config.boot.tee_type {
        return match tee_type.to_lowercase().as_str() {
            #[cfg(feature = "tdx")]
            "tdx" => {
                info!("Creating TDX provider (explicit config)");
                let provider = super::TdxProvider::new(config.boot.aa_config_path.as_deref())?;
                Ok(Box::new(provider))
            }
            #[cfg(feature = "nitro")]
            "nitro" => {
                info!("Creating Nitro provider (explicit config)");
                Ok(Box::new(super::NitroProvider::new()))
            }
            #[cfg(feature = "simulation")]
            "simulation" => {
                warn!("Creating Simulation provider (explicit config) — NOT FOR PRODUCTION");
                Ok(Box::new(super::SimulationProvider::new()))
            }
            other => Err(TeeError::InitializationFailed(format!(
                "Unknown TEE type '{}'. Available types depend on compiled features.",
                other
            ))),
        };
    }

    // Auto-detect from feature flags (priority: tdx > nitro > simulation)
    #[cfg(feature = "tdx")]
    {
        info!("Auto-selecting TDX provider (feature flag)");
        let provider = super::TdxProvider::new(config.boot.aa_config_path.as_deref())?;
        return Ok(Box::new(provider));
    }

    #[cfg(feature = "nitro")]
    {
        info!("Auto-selecting Nitro provider (feature flag)");
        return Ok(Box::new(super::NitroProvider::new()));
    }

    #[cfg(feature = "simulation")]
    {
        warn!("Auto-selecting Simulation provider — no real TEE feature enabled");
        return Ok(Box::new(super::SimulationProvider::new()));
    }

    #[allow(unreachable_code)]
    Err(TeeError::InitializationFailed(
        "No TEE provider available. Compile with --features tdx, --features nitro, or --features simulation".to_string(),
    ))
}
