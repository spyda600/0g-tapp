use clap::Parser;
use std::sync::Arc;
use tapp_service::{
    auth_layer::AuthLayer, config::TappConfig, init_tracing, permission::PermissionManager,
    tee::create_tee_provider, TappServiceImpl, TappServiceServer, VERSION,
};
use tonic::transport::Server;
use tower::ServiceBuilder;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "tapp-server")]
#[command(about = "TAPP gRPC Server", version = VERSION)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/tapp/config.toml")]
    config: String,

    /// Bind address (overrides config)
    #[arg(short, long)]
    bind: Option<String>,

    /// Enable verbose logging (overrides config)
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Step 1: Load configuration first (before initializing logging)
    let mut config = match TappConfig::load(args.config.clone()) {
        Ok(config) => {
            // Use println because tracing is not initialized yet
            println!("✓ Configuration loaded from: {}", args.config);
            config
        }
        Err(e) => {
            println!("⚠ Failed to load config from {}: {}", args.config, e);
            println!("Using default configuration");
            TappConfig::default()
        }
    };

    // Step 2: Override config with command-line args if provided
    if args.verbose {
        config.logging.level = "debug".to_string();
    }

    // Step 3: Initialize tracing with config
    init_tracing(&config.logging)?;

    info!("🚀 Starting TDX TAPP Service Server");
    info!("Version: {}", VERSION);
    info!("Configuration loaded from: {}", args.config);
    info!(
        logging_level = %config.logging.level,
        logging_format = %config.logging.format,
        logging_file = ?config.logging.file_path,
        "Logging initialized"
    );

    // Step 4: Determine bind address
    let bind_address = args
        .bind
        .unwrap_or_else(|| config.server.bind_address.clone());

    info!("Bind address configured: {}", bind_address);

    // Step 5: Initialize PermissionManager if configured
    let permission_manager = if let Some(ref perm_config) = config.server.permission {
        if perm_config.enabled {
            info!("🔐 Permission-based authentication enabled");
            info!("   Tapp owner: {}", perm_config.owner_address);

            let pm = Arc::new(PermissionManager::new(perm_config.owner_address.clone()));

            // Initialize whitelist with addresses from config
            if !perm_config.initial_whitelist.is_empty() {
                info!(
                    "   Initializing whitelist with {} address(es)",
                    perm_config.initial_whitelist.len()
                );
                for addr in &perm_config.initial_whitelist {
                    pm.add_to_whitelist(addr.clone()).await.ok();
                    info!("      - {}", addr);
                }
            }

            Some(pm)
        } else {
            info!("🔓 Permission-based authentication disabled");
            None
        }
    } else {
        info!("🔓 Permission-based authentication not configured");
        None
    };

    // Step 6: Initialize TEE Provider (replaces AttestationAgent init)
    let tee_provider: Arc<dyn tapp_service::tee::TeeProvider> = match create_tee_provider(&config) {
        Ok(provider) => {
            info!("TEE provider created: {}", provider.tee_type());
            Arc::from(provider)
        }
        Err(e) => {
            error!("Failed to create TEE provider: {}", e);
            error!("Hint: Run with --features simulation for development without TEE hardware");
            std::process::exit(1);
        }
    };

    if let Err(e) = tee_provider.init().await {
        error!("Failed to initialize TEE provider: {}", e);
        error!("Hint: Ensure TEE hardware is available, or use --features simulation");
        std::process::exit(1);
    }

    let measurement_service = Arc::new(
        tapp_service::measurement_service::MeasurementService::new(tee_provider.clone()),
    );
    info!(
        "✓ Detected TEE type: {}",
        measurement_service.get_tee_type().await
    );

    // Step 7: Initialize service with PermissionManager and MeasurementService
    let service = match TappServiceImpl::new(
        config.clone(),
        permission_manager.clone(),
        measurement_service,
    )
    .await
    {
        Ok(service) => {
            info!("✓ TAPP service initialized successfully");
            service
        }
        Err(e) => {
            error!("✗ Failed to initialize TAPP service: {}", e);
            std::process::exit(1);
        }
    };

    // Step 8: Create gRPC server with auth layer
    let auth_layer = if let Some(pm) = permission_manager {
        AuthLayer::with_permission_manager(pm)
    } else {
        AuthLayer::new(config.server.permission.clone())
    };

    let layer = ServiceBuilder::new().layer(auth_layer).into_inner();

    // Step 9: Start gRPC server
    #[cfg(feature = "nitro")]
    {
        // In a Nitro Enclave, the ONLY way to communicate with the parent
        // is via vsock. We listen on vsock CID_ANY (accept from any CID)
        // and feed connections into tonic via serve_with_incoming.
        let vsock_port: u32 = bind_address
            .split(':')
            .last()
            .and_then(|p| p.parse().ok())
            .unwrap_or(50051);

        // VMADDR_CID_ANY = 0xFFFFFFFF — accept connections from any CID
        let mut vsock_listener = tokio_vsock::VsockListener::bind(0xFFFFFFFF, vsock_port)
            .map_err(|e| format!("Failed to bind vsock port {}: {}", vsock_port, e))?;

        info!("TAPP gRPC server listening on vsock port {} (Nitro Enclave)", vsock_port);

        // VsockListener::incoming() returns a Stream of VsockStream.
        // tonic's serve_with_incoming needs Stream<Item=Result<impl AsyncRead+AsyncWrite+Connected+Unpin>>
        // tokio_vsock::VsockStream implements AsyncRead + AsyncWrite + Unpin.
        // tonic provides a blanket Connected impl.
        let incoming = vsock_listener.incoming();

        let server = Server::builder()
            .layer(layer)
            .add_service(TappServiceServer::new(service))
            .serve_with_incoming(incoming);

        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    error!("Server error: {}", e);
                    std::process::exit(1);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, stopping server");
            }
        }
    }

    #[cfg(not(feature = "nitro"))]
    {
        let addr: std::net::SocketAddr = bind_address
            .parse()
            .map_err(|e| format!("Invalid bind address '{}': {}", bind_address, e))?;

        let server = Server::builder()
            .layer(layer)
            .add_service(TappServiceServer::new(service))
            .serve(addr);

        info!("TAPP gRPC server listening on {}", addr);

        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    error!("Server error: {}", e);
                    std::process::exit(1);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received shutdown signal, stopping server");
            }
        }
    }

    info!("TAPP server shutdown complete");
    Ok(())
}
