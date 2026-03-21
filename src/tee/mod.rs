pub mod factory;
pub mod provider;
pub mod types;

#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "simulation")]
pub mod simulation;

// Re-exports
pub use factory::create_tee_provider;
pub use provider::TeeProvider;
pub use types::{TeeError, TeeEvidence, TeeType};

#[cfg(feature = "tdx")]
pub use tdx::TdxProvider;

#[cfg(feature = "simulation")]
pub use simulation::SimulationProvider;

/// Default domain used for ZGEL runtime measurements.
pub const ZGEL_DOMAIN: &str = "tapp.0g.com";
