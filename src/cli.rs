use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tapp_service::proto::{
    tapp_service_client::TappServiceClient, GetAppKeyRequest, GetAppSecretKeyRequest,
    GetEvidenceRequest, MountFile, StartAppRequest,
};
use tonic::Request;

#[derive(Parser)]
#[command(name = "tapp-cli")]
#[command(about = "TAPP Service CLI - Interact with TAPP gRPC server", long_about = None)]
struct Cli {
    /// gRPC server address
    #[arg(short, long, default_value = "http://127.0.0.1:50051")]
    server: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an application with Docker Compose
    StartApp {
        /// Path to Docker Compose file
        #[arg(short, long)]
        compose_file: PathBuf,

        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Mount files in format: source_path:file_path:mode
        /// Example: ./nginx.conf:/path/to/nginx.conf:0644
        #[arg(short, long)]
        mount: Vec<String>,
    },

    /// Get attestation evidence with custom report data
    GetEvidence {
        /// Custom report data (hex encoded, up to 64 bytes, with or without 0x prefix)
        /// If not provided, will use zero-filled 64 bytes
        #[arg(short, long, default_value = "")]
        report_data: String,
    },

    /// Get application public key (public interface)
    GetAppKey {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Key type (default: ethereum)
        #[arg(short = 't', long, default_value = "ethereum")]
        key_type: String,
    },

    /// Get application secret key (private key - local access only)
    GetAppSecretKey {
        /// Application ID
        #[arg(short, long)]
        app_id: String,

        /// Deployer's private key (32 bytes hex) for signing the request
        #[arg(short = 'd', long)]
        deployer_private_key: String,

        /// Output in JSON format (for programmatic use)
        #[arg(long)]
        json: bool,
    },

    /// Sign a message using a private key
    SignMessage {
        /// Private key (32 bytes hex)
        #[arg(short, long)]
        private_key: String,

        /// Message to sign (will be treated as UTF-8 string)
        #[arg(short, long)]
        message: String,
    },

    /// Verify a signature using a public key
    VerifySignature {
        /// Public key (64 bytes hex)
        #[arg(short, long)]
        public_key: String,

        /// Message that was signed
        #[arg(short, long)]
        message: String,

        /// Signature (hex)
        #[arg(short, long)]
        signature: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::StartApp {
            compose_file,
            app_id,
            mount,
        } => {
            start_app(&cli.server, compose_file, app_id, mount).await?;
        }
        Commands::GetEvidence { report_data } => {
            get_evidence(&cli.server, report_data).await?;
        }
        Commands::GetAppKey { app_id, key_type } => {
            get_app_key(&cli.server, app_id, key_type).await?;
        }
        Commands::GetAppSecretKey {
            app_id,
            deployer_private_key,
            json,
        } => {
            get_app_secret_key(&cli.server, app_id, deployer_private_key, json).await?;
        }
        Commands::SignMessage {
            private_key,
            message,
        } => {
            sign_message(private_key, message)?;
        }
        Commands::VerifySignature {
            public_key,
            message,
            signature,
        } => {
            verify_signature(public_key, message, signature)?;
        }
    }

    Ok(())
}

async fn start_app(
    server: &str,
    compose_file: PathBuf,
    app_id: String,
    mounts: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    // Read compose file
    let compose_content = std::fs::read_to_string(&compose_file)?;

    // Parse mount files
    let mut mount_files = Vec::new();
    for mount_spec in mounts {
        let parts: Vec<&str> = mount_spec.split(':').collect();
        if parts.len() != 3 {
            eprintln!(
                "Invalid mount format: {}. Expected: source_path:file_path:mode",
                mount_spec
            );
            std::process::exit(1);
        }

        let source_path = parts[0].to_string();
        let file_path = parts[1];
        let mode = parts[2].to_string();

        // Read file content
        let content = std::fs::read(file_path)?;

        mount_files.push(MountFile {
            source_path,
            content,
            mode,
        });
    }

    let request = Request::new(StartAppRequest {
        compose_content,
        app_id: app_id.clone(),
        mount_files,
    });

    let response = client.start_app(request).await?;
    let result = response.into_inner();

    println!("✓ Application started successfully");
    println!("  Task ID: {}", result.task_id);
    println!("  Message: {}", result.message);
    println!("  Timestamp: {}", result.timestamp);

    Ok(())
}

async fn get_evidence(
    server: &str,
    report_data_hex: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    // Decode report data if provided
    let report_data_bytes = if report_data_hex.is_empty() {
        vec![]
    } else {
        // Remove 0x prefix if present
        let hex_str = report_data_hex
            .trim_start_matches("0x")
            .trim_start_matches("0X");

        // Validate and decode
        if hex_str.len() > 128 {
            eprintln!(
                "ERROR: Report data must be at most 64 bytes (128 hex characters), got {}",
                hex_str.len()
            );
            std::process::exit(1);
        }

        hex::decode(hex_str)?
    };

    let request = Request::new(GetEvidenceRequest {
        report_data: report_data_bytes.clone(),
    });

    let response = client.get_evidence(request).await?;
    let result = response.into_inner();

    println!("✓ Evidence generated successfully");
    println!("  TEE Type: {}", result.tee_type);
    println!("  Timestamp: {}", result.timestamp);
    println!("  Evidence (hex): {}", hex::encode(&result.evidence));
    println!("  Evidence (base64): {}", base64::encode(&result.evidence));

    if !report_data_bytes.is_empty() {
        println!("\nReport data used: 0x{}", hex::encode(&report_data_bytes));
    } else {
        println!("\nReport data: (empty, will use zero-filled 64 bytes)");
    }

    Ok(())
}

async fn get_app_key(
    server: &str,
    app_id: String,
    key_type: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    let request = Request::new(GetAppKeyRequest {
        app_id: app_id.clone(),
        key_type: key_type.clone(),
        additional_data: vec![],
        kbs_resource_uri: String::new(),
    });

    let response = client.get_app_key(request).await?;
    let result = response.into_inner();

    if !result.success {
        eprintln!("ERROR: {}", result.message);
        std::process::exit(1);
    }

    println!("✓ Application key retrieved successfully");
    println!("  App ID: {}", app_id);
    println!("  Key Type: {}", key_type);
    println!("  Key Source: {}", result.key_source);
    println!("  Public Key (hex): 0x{}", hex::encode(&result.public_key));

    if key_type == "ethereum" && !result.eth_address.is_empty() {
        println!("  Ethereum Address: 0x{}", hex::encode(&result.eth_address));
    }

    Ok(())
}

async fn get_app_secret_key(
    server: &str,
    app_id: String,
    deployer_private_key_hex: String,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = TappServiceClient::connect(server.to_string()).await?;

    // Remove 0x prefix if present
    let deployer_private_key_hex = deployer_private_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if deployer_private_key_hex.len() != 64 {
        eprintln!(
            "ERROR: Deployer private key must be 32 bytes (64 hex characters), got {}",
            deployer_private_key_hex.len()
        );
        std::process::exit(1);
    }

    let deployer_private_key = hex::decode(deployer_private_key_hex)?;

    // Generate random nonce (16 bytes hex = 32 characters)
    use rand::Rng;
    let nonce: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Get current timestamp
    let timestamp = chrono::Utc::now().timestamp();

    // Construct message: app_id || nonce || timestamp (as bytes)
    let mut message = Vec::new();
    message.extend_from_slice(app_id.as_bytes());
    message.extend_from_slice(nonce.as_bytes());
    message.extend_from_slice(&timestamp.to_le_bytes());

    let request = Request::new(GetAppSecretKeyRequest {
        app_id: app_id.clone(),
    });

    // Server will validate signature and that the connection is from localhost
    let response = match client.get_app_secret_key(request).await {
        Ok(resp) => resp,
        Err(e) if e.code() == tonic::Code::PermissionDenied => {
            eprintln!("╔════════════════════════════════════════════════════════════╗");
            eprintln!("║              SECURITY RESTRICTION                          ║");
            eprintln!("╠════════════════════════════════════════════════════════════╣");

            if e.message().contains("Nonce") {
                eprintln!("║ Nonce verification failed (replay attack detected)        ║");
                eprintln!("║                                                            ║");
                eprintln!("║ This could mean:                                           ║");
                eprintln!("║ - The request was replayed                                 ║");
                eprintln!("║ - The timestamp is outside the validity window             ║");
                eprintln!("║ - The nonce was already used                               ║");
            } else if e.message().contains("signature") {
                eprintln!("║ Signature verification failed!                             ║");
                eprintln!("║                                                            ║");
                eprintln!("║ This means:                                                ║");
                eprintln!("║ - The deployer private key is incorrect                    ║");
                eprintln!("║ - You are not the deployer of this application             ║");
                eprintln!("║                                                            ║");
                eprintln!("║ Only the application deployer can access the private key.  ║");
            } else {
                eprintln!("║ GetAppSecretKey can ONLY be called from localhost or      ║");
                eprintln!("║ same-host Docker containers!                               ║");
                eprintln!("║                                                            ║");
                eprintln!("║ Server: {:<51} ║", server);
                eprintln!("║                                                            ║");
                eprintln!("║ Private keys will NEVER be sent over the network.         ║");
                eprintln!("║ This command must be run on the same machine as the       ║");
                eprintln!("║ TAPP server (inside the TEE).                             ║");
            }

            eprintln!("║                                                            ║");
            eprintln!("║ Server says: {:<43} ║", e.message());
            eprintln!("╚════════════════════════════════════════════════════════════╝");
            std::process::exit(1);
        }
        Err(e) if e.code() == tonic::Code::NotFound => {
            eprintln!("╔════════════════════════════════════════════════════════════╗");
            eprintln!("║              APPLICATION NOT FOUND                         ║");
            eprintln!("╠════════════════════════════════════════════════════════════╣");
            eprintln!(
                "║ The application '{}' was not found.{:<16} ║",
                if app_id.len() <= 30 {
                    &app_id
                } else {
                    &app_id[..30]
                },
                ""
            );
            eprintln!("║                                                            ║");
            eprintln!("║ Make sure the application has been deployed using          ║");
            eprintln!("║ the StartApp interface.                                    ║");
            eprintln!("╚════════════════════════════════════════════════════════════╝");
            std::process::exit(1);
        }
        Err(e) => return Err(e.into()),
    };

    let result = response.into_inner();

    if !result.success {
        eprintln!("ERROR: {}", result.message);
        std::process::exit(1);
    }

    if json_output {
        let output = serde_json::json!({
            "private_key": format!("0x{}", hex::encode(&result.private_key)),
            "public_key": format!("0x{}", hex::encode(&result.public_key)),
            "evm_address": if !result.eth_address.is_empty() {
                format!("0x{}", hex::encode(&result.eth_address))
            } else {
                String::new()
            },
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║           APPLICATION SECRET KEY (SENSITIVE!)              ║");
        println!("╠════════════════════════════════════════════════════════════╣");
        println!("║ WARNING: This is highly sensitive information!            ║");
        println!("║ Keep this private key secure and never share it.          ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
        println!("  App ID: {}", app_id);
        println!(
            "  Private Key (hex): 0x{}",
            hex::encode(&result.private_key)
        );
        println!("  Public Key (hex):  0x{}", hex::encode(&result.public_key));

        if !result.eth_address.is_empty() {
            println!(
                "  Ethereum Address:  0x{}",
                hex::encode(&result.eth_address)
            );
        }

        println!();
        println!("💡 You can use this private key with:");
        println!("   tapp-cli sign-message --private-key <KEY> --message <MSG>");
    }

    Ok(())
}

fn sign_message(
    private_key_hex: String,
    message: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Remove 0x prefix if present
    let private_key_hex = private_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if private_key_hex.len() != 64 {
        eprintln!(
            "ERROR: Private key must be 32 bytes (64 hex characters), got {}",
            private_key_hex.len()
        );
        std::process::exit(1);
    }

    let private_key = hex::decode(private_key_hex)?;
    let message_bytes = message.as_bytes();

    let signature = tapp_service::app_key::sign_message(&private_key, message_bytes)?;

    println!("✓ Message signed successfully");
    println!("  Message: {}", message);
    println!("  Signature (hex): 0x{}", hex::encode(&signature));
    println!("  Signature (base64): {}", base64::encode(&signature));

    Ok(())
}

fn verify_signature(
    public_key_hex: String,
    message: String,
    signature_hex: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Remove 0x prefix if present
    let public_key_hex = public_key_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let signature_hex = signature_hex
        .trim_start_matches("0x")
        .trim_start_matches("0X");

    if public_key_hex.len() != 128 {
        eprintln!(
            "ERROR: Public key must be 64 bytes (128 hex characters), got {}",
            public_key_hex.len()
        );
        std::process::exit(1);
    }

    let public_key = hex::decode(public_key_hex)?;
    let signature = hex::decode(signature_hex)?;
    let message_bytes = message.as_bytes();

    let is_valid = tapp_service::app_key::verify_signature(&public_key, message_bytes, &signature)?;

    if is_valid {
        println!("✓ Signature is VALID");
        println!("  Message: {}", message);
        println!("  Public Key: 0x{}", public_key_hex);
    } else {
        println!("✗ Signature is INVALID");
        println!("  Message: {}", message);
        println!("  Public Key: 0x{}", public_key_hex);
        std::process::exit(1);
    }

    Ok(())
}
