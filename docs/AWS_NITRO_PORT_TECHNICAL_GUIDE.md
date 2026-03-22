# AWS Nitro Enclave Port: Technical Guide

> **Audience**: Backend engineers who built the original Alibaba Cloud TDX version of 0G TAPP.
> You know the TDX codebase. This document explains every change made to port TAPP to AWS Nitro Enclaves.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [TEE Abstraction Layer Changes](#2-tee-abstraction-layer-changes)
3. [NSM (Nitro Secure Module) Integration](#3-nsm-nitro-secure-module-integration)
4. [Networking Architecture](#4-networking-architecture)
5. [Key Persistence (KMS Integration)](#5-key-persistence-kms-integration)
6. [Docker Container Management](#6-docker-container-management)
7. [Build System Changes](#7-build-system-changes)
8. [Configuration Changes](#8-configuration-changes)
9. [Security Hardening Applied](#9-security-hardening-applied)
10. [Deployment & Operations](#10-deployment--operations)

---

## 1. Executive Summary

### What changed and why

The original 0G TAPP runs inside an Alibaba Cloud TDX confidential VM. The port makes TAPP run inside an **AWS Nitro Enclave** -- a different TEE with a fundamentally different architecture. The core gRPC service, Docker Compose app lifecycle, key management, and measurement logic are unchanged. What changed is how the service talks to hardware, reaches the network, persists keys, and manages Docker containers.

**Key decisions:**

- A new `TeeProvider` trait abstracts all TEE-specific operations. The TDX code path is untouched; Nitro is a parallel implementation behind the same interface.
- Feature flags (`--features tdx`, `--features nitro`, `--features simulation`) select the provider at compile time. Production builds cannot combine simulation with a real provider.
- Nitro Enclaves have **no network** and **no persistent storage**. Both gaps required new subsystems: a vsock bridge for networking and KMS-backed key persistence.
- Docker commands are proxied to the parent EC2 instance over vsock because the enclave has no Docker daemon.

### TDX vs Nitro Enclaves: key architectural differences

| Aspect | Alibaba TDX | AWS Nitro Enclave |
|---|---|---|
| **Isolation model** | Confidential VM (full guest OS) | Lightweight VM carved from parent EC2 instance |
| **Network** | Standard TCP/IP | None. Only vsock to parent (CID 3) |
| **Persistent storage** | Local disk (EBS-like) | None. RAM-only, wiped on termination |
| **Attestation** | TDX Quote via `attestation-agent` crate | COSE Sign1 document via `/dev/nsm` |
| **Runtime measurements** | Hardware RTMRs (extend at any time) | PCRs locked at launch; must use software accumulator |
| **Docker** | Local Docker daemon | No daemon. Commands proxied to parent over vsock |
| **Key persistence** | Keys survive reboot (disk) | Keys lost on every restart unless backed up via KMS |
| **Attestation PKI** | Intel/Alibaba trust chain | AWS Nitro Attestation PKI (COSE Sign1) |

---

## 2. TEE Abstraction Layer Changes

All TEE-specific code is isolated in `src/tee/`. The TDX code was refactored behind a trait so that Nitro (and simulation) providers plug in without touching core logic.

### Module layout

```
src/tee/
  mod.rs          -- Module declarations, cfg-gated pub use
  provider.rs     -- TeeProvider trait definition
  types.rs        -- Shared types (TeeType, AttestationEvidence, MeasurementRegister)
  error.rs        -- TeeError enum
  factory.rs      -- create_tee_provider() factory function
  tdx.rs          -- TdxProvider (your existing code, wrapped)
  nitro.rs        -- NitroProvider + MeasurementAccumulator
  simulation.rs   -- SimulationProvider (dev/test only)
```

### The `TeeProvider` trait (`src/tee/provider.rs`)

Every TEE backend implements this trait:

```rust
#[async_trait]
pub trait TeeProvider: Send + Sync + 'static {
    async fn init(&self) -> Result<(), TeeError>;
    fn tee_type(&self) -> TeeType;
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError>;
    async fn extend_measurement(&self, register_index: u32, data: &[u8]) -> Result<(), TeeError>;
    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError>;
}
```

The rest of TAPP (`MeasurementService`, `BootService`, `TappServiceImpl`) only interact with `Arc<dyn TeeProvider>`. They never import TDX-specific or Nitro-specific types.

### `NitroProvider` vs `TdxProvider`

**TdxProvider** (`src/tee/tdx.rs`):
- Wraps the existing `attestation-agent` crate (`AttestationAgent`)
- `get_evidence()` calls `self.aa.lock().await.get_evidence(runtime_data)` which produces a TDX Quote
- `extend_measurement()` calls `self.aa.lock().await.extend_runtime_measurement()` which writes to hardware RTMRs
- `get_measurements()` returns empty (RTMRs are only readable inside the Quote)

**NitroProvider** (`src/tee/nitro.rs`):
- No external attestation agent. Talks directly to `/dev/nsm` via the `aws-nitro-enclaves-nsm-api` crate.
- `get_evidence()` generates an NSM attestation document (COSE Sign1)
- `extend_measurement()` updates the software `MeasurementAccumulator` (see below)
- `get_measurements()` returns all 4 software registers with their current SHA-384 values

### `MeasurementAccumulator`: why Nitro needs software-side measurement tracking

In TDX, you can call `extend_runtime_measurement()` at any time and the hardware RTMR is updated. In Nitro, **PCRs are locked at enclave launch** -- they reflect only the static EIF image, not runtime behavior.

To provide equivalent runtime measurement semantics, `NitroProvider` maintains a `MeasurementAccumulator`: 4 software registers, each 48 bytes (SHA-384). The extend operation is identical to hardware RTMR semantics:

```rust
// new_value = SHA384(current_value || data)
pub fn extend(&mut self, register: u32, data: &[u8]) -> Result<(), TeeError> {
    let mut hasher = Sha384::new();
    hasher.update(&self.registers[register as usize]);
    hasher.update(data);
    let result = hasher.finalize();
    self.registers[register as usize].copy_from_slice(&result);
    Ok(())
}
```

When attestation is requested, the accumulator's state is serialized into the NSM `user_data` field (max 512 bytes). The format is versioned:

```
Layout (v1): [version: 1 byte] [reg0: 48 bytes] [reg1: 48] [reg2: 48] [reg3: 48] = 193 bytes
```

The verifier can then check both the static PCRs (enclave image integrity) AND the runtime measurement registers (application behavior) from a single attestation document.

### The factory pattern (`src/tee/factory.rs`)

`create_tee_provider()` selects the provider based on config and feature flags:

1. If `config.boot.tee_type` is explicitly set (e.g., `"nitro"`), use that.
2. Otherwise, auto-detect from feature flags with priority: TDX > Nitro > Simulation.
3. If no provider feature is enabled, return an error.

### `compile_error!` guard

At the top of `factory.rs`:

```rust
#[cfg(all(feature = "simulation", feature = "nitro"))]
compile_error!("Cannot enable both 'simulation' and 'nitro' features.");

#[cfg(all(feature = "simulation", feature = "tdx"))]
compile_error!("Cannot enable both 'simulation' and 'tdx' features.");
```

This prevents building a binary that could fall back to simulation when real TEE hardware is expected. It is a compile-time safety net -- you cannot accidentally ship a simulation-capable production build.

### Conditional module compilation (`src/tee/mod.rs`)

Each provider module is only compiled when its feature is active:

```rust
#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "nitro")]
pub use nitro::NitroProvider;

#[cfg(feature = "tdx")]
pub mod tdx;
#[cfg(feature = "tdx")]
pub use tdx::TdxProvider;
```

This means the `attestation-agent` crate (and all its TDX-specific system library dependencies like `libtdx-attest`) is only pulled in for TDX builds. Nitro builds have no TDX dependencies and vice versa.

---

## 3. NSM (Nitro Secure Module) Integration

### `/dev/nsm` device and the `aws-nitro-enclaves-nsm-api` crate

Inside a Nitro Enclave, the `/dev/nsm` character device provides access to the Nitro Security Module. The `aws-nitro-enclaves-nsm-api` crate (version 0.4, declared as an optional dependency in `Cargo.toml`) wraps the ioctl interface.

The provider checks for `/dev/nsm` at init time:

```rust
async fn init(&self) -> Result<(), TeeError> {
    if !std::path::Path::new("/dev/nsm").exists() {
        return Err(TeeError::NotAvailable);
    }
    info!("Nitro provider initialized -- NSM device available");
    Ok(())
}
```

### `Request::Attestation` flow

The NSM attestation request accepts three optional fields:

```rust
let request = Request::Attestation {
    user_data: Some(user_data.to_vec().into()),  // measurement accumulator state
    nonce: Some(runtime_data.to_vec().into()),    // caller-supplied challenge
    public_key: None,                              // not used currently
};
```

- **`user_data`**: Contains the versioned measurement accumulator (193 bytes). This is the Nitro equivalent of TDX's RTMR values bound into the Quote.
- **`nonce`**: Maps to the `runtime_data` parameter from the `TeeProvider::get_evidence()` call. Callers pass a challenge here to prevent replay.
- **`public_key`**: Reserved for KMS `Recipient` use cases (the `KmsPersistence` module uses its own attestation flow).

The NSM API lifecycle:

```rust
let nsm_fd = driver::nsm_init();        // open /dev/nsm
let response = driver::nsm_process_request(nsm_fd, request);
driver::nsm_exit(nsm_fd);               // close fd
```

### COSE Sign1 document format

The NSM returns a COSE Sign1 document (RFC 8152) signed by the AWS Nitro Attestation PKI. It contains:

- **PCR0**: Hash of the enclave image (EIF). Analogous to a combination of TDX MRTD + RTMR[0].
- **PCR1**: Hash of the Linux kernel and boot ramdisk.
- **PCR2**: Hash of the application (user-space code and libraries).
- **PCR3-PCR8**: Platform-specific and empty by default.
- **user_data**: Our measurement accumulator.
- **nonce**: The caller-supplied challenge.
- **timestamp**: Set by the NSM hardware clock.
- **Certificate chain**: Roots to the AWS Nitro Attestation CA.

### How PCR0/1/2 relate to TDX RTMRs

| TDX | Nitro | What it measures |
|---|---|---|
| MRTD | PCR0 | Static image identity |
| RTMR[0] | PCR1 | Kernel/boot chain |
| RTMR[1] | PCR2 | Application code |
| RTMR[2] | `user_data` registers 0-3 | Runtime behavior (software) |
| RTMR[3] | `user_data` registers 0-3 | Runtime behavior (software) |

The key difference: TDX RTMRs can be extended at any time and their values appear directly in the hardware Quote. Nitro PCRs are frozen at launch, so runtime measurements live in `user_data` instead.

### The TOCTOU fix: holding the lock through attestation

A critical detail in `NitroProvider::get_evidence()`:

```rust
async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError> {
    // Hold the lock across the entire attestation operation
    let acc = self.accumulator.lock().map_err(|e| {
        TeeError::AttestationFailed(format!("Failed to lock accumulator: {}", e))
    })?;
    let user_data = acc.to_user_data();
    // ... generate attestation doc WITH the lock still held ...
    let raw = Self::nsm_get_attestation_doc(&user_data, runtime_data)?;
    // Lock released here
    drop(acc);
    Ok(AttestationEvidence { raw, tee_type: TeeType::Nitro, timestamp })
}
```

The `Mutex` on the accumulator is held from the moment we read the registers until the NSM attestation document is generated. Without this, a concurrent `extend_measurement()` call could mutate a register between reading user_data and generating the attestation document, producing an attestation that claims measurement values that were never actually captured in the signed document.

In TDX, the hardware handles this atomically -- the RTMR values in the Quote are a hardware snapshot. In Nitro, we must enforce this invariant in software.

---

## 4. Networking Architecture

### TDX: standard TCP/IP networking

In the TDX deployment, the enclave is a full VM with a standard network stack. The gRPC server binds to `0.0.0.0:50051` and clients connect directly over TCP.

### Nitro: NO network, only vsock

A Nitro Enclave has **zero network interfaces**. The only communication channel is **vsock** -- a socket family (AF_VSOCK) that provides a host-to-guest pipe using CID (Context ID) addressing.

Fixed CID assignments:
- **CID 3** = parent EC2 instance (always)
- **CID 5** = enclave (configured in `deploy-enclave.sh` via `--enclave-cid`)
- **CID 0xFFFFFFFF** = `VMADDR_CID_ANY` (listen on any CID, used by the enclave side)

### The vsock-to-TCP bridge in `main.rs`

The gRPC server (tonic) does not natively support vsock. Our solution: tonic listens on localhost TCP, and a bridge task shuttles bytes between vsock and TCP.

The bridge is compiled only for Nitro builds (`#[cfg(feature = "nitro")]` block in `main.rs`):

```rust
// tonic gRPC server on localhost only
let addr: std::net::SocketAddr = "127.0.0.1:50051".parse().unwrap();
let server = Server::builder()
    .layer(layer)
    .add_service(TappServiceServer::new(service))
    .serve(addr);

// vsock listener for external connections
let vsock_addr = tokio_vsock::VsockAddr::new(0xFFFFFFFF, vsock_port);
let mut vsock_listener = tokio_vsock::VsockListener::bind(vsock_addr)?;
```

For each incoming vsock connection, the bridge:
1. Validates the peer CID (must be 3 = parent)
2. Acquires a semaphore permit (bounded concurrency)
3. Opens a TCP connection to `127.0.0.1:50051`
4. Runs `tokio::io::copy_bidirectional()` between the vsock stream and TCP stream
5. Enforces a per-connection timeout

Security controls on the bridge:
- **CID validation**: Only connections from CID 3 (parent) are accepted. Any other CID is rejected and logged.
- **Connection limiting**: A `tokio::sync::Semaphore` caps concurrent bridged connections at `config.server.max_connections`.
- **Timeout**: Each bridged connection has a maximum lifetime of `config.server.request_timeout_seconds`.
- **Backoff on errors**: Consecutive vsock accept errors trigger exponential backoff (10ms, 20ms, ..., capped at 1000ms).

### socat proxy on the parent instance

External clients reach the enclave via a socat proxy running on the parent EC2 instance. Started by `deploy-enclave.sh`:

```bash
socat TCP-LISTEN:50051,reuseaddr,fork \
    VSOCK-CONNECT:5:50051
```

This bridges TCP port 50051 on the parent to vsock CID 5, port 50051 on the enclave. The AWS security group controls which external IPs can reach port 50051 on the parent.

**Full request path:**

```
Client --TCP--> Parent:50051 --socat--> vsock(CID=5, port=50051)
                                          |
                                    [enclave vsock listener]
                                          |
                                    127.0.0.1:50051 (tonic gRPC)
```

### Docker proxy over vsock (`src/docker_proxy.rs` + `scripts/docker-proxy-parent.py`)

The enclave has no Docker daemon. A dedicated vsock channel handles Docker operations.

**Enclave side** (`src/docker_proxy.rs`): A Rust client that sends JSON-RPC requests over vsock to port **50052** on the parent (CID 3). Wire format:

```
[4-byte big-endian length][JSON payload]
```

Request structure:
```rust
pub struct DockerProxyRequest {
    pub command: String,            // "compose_up", "compose_down", "compose_ps", etc.
    pub app_id: Option<String>,
    pub compose_content: Option<String>,
    pub working_dir: Option<String>,
    pub service_name: Option<String>,
    // ... other optional fields
}
```

Supported commands: `compose_up`, `compose_down`, `compose_logs`, `compose_ps`, `compose_images`, `compose_stop_service`, `compose_start_service`, `compose_is_service_running`, `inspect_digest`, `inspect_started_at`, `system_prune`.

**Parent side** (`scripts/docker-proxy-parent.py`): A Python script that listens on vsock port 50052, validates requests, and executes Docker CLI commands. Safety measures:
- **Working directory validation**: All `working_dir` values must be under `/var/lib/tapp/apps` (configurable via `--allowed-base`). Path traversal is blocked.
- **Message size limit**: Requests larger than 16 MiB are rejected.
- **Command timeout**: Docker commands time out after 300 seconds (600 for `compose_up`).

**File proxy** (port 50053): A separate vsock channel for file operations, used by the KMS key persistence system. Same wire format, but with `read_file`, `write_file`, and `file_exists` commands. Defined in `src/app_key/kms_persistence.rs`.

### Complete vsock port map

| Port | Direction | Purpose |
|---|---|---|
| 50051 | Enclave listens | gRPC (via vsock-to-TCP bridge) |
| 50052 | Parent listens | Docker command proxy |
| 50053 | Parent listens | File proxy (KMS key blob storage) |

---

## 5. Key Persistence (KMS Integration)

### The problem: TDX has persistent storage, Nitro enclaves are ephemeral

In TDX, application keys live in memory and the VM has persistent disk. The keys survive reboots because the VM does.

A Nitro Enclave's memory is wiped every time it terminates. Without a persistence mechanism, every restart generates new Ethereum keys, orphaning any funds held by the old keys. This is a **funds-loss risk**, making key persistence the most safety-critical addition in the port.

### KMS + PCR-conditioned key policy

The solution uses AWS KMS (Key Management Service) with a key policy that restricts decrypt operations to enclaves with specific PCR values:

```json
{
  "Condition": {
    "StringEqualsIgnoreCase": {
      "kms:RecipientAttestation:PCR0": "<PCR0_HEX>"
    }
  }
}
```

This means:
- Only a Nitro Enclave with the exact same image (PCR0) can decrypt key material.
- The parent EC2 instance cannot decrypt the blobs even if compromised.
- Updating the enclave image changes PCR0, so the KMS policy must be updated BEFORE the old enclave is terminated (see `docs/SAFE_UPDATE_PROCEDURE.md`).

### `src/app_key/kms_persistence.rs` flow

**`KmsPersistence`** is the persistence layer. It is optionally created based on the `[kms]` config section.

**Backup flow (encrypt and store):**

1. Get a fresh NSM attestation document (calls `NitroProvider::nsm_get_attestation_doc`)
2. Build an encryption context: `{"app_id": "<id>", "service": "tapp"}`
3. Call KMS Encrypt with the attestation document as the `Recipient` field
4. KMS returns a `CiphertextForRecipient` blob (encrypted for the enclave)
5. Write the encrypted blob to `{storage_path}/{app_id}.key.enc` on the parent via the vsock file proxy (port 50053)

**Recovery flow (read and decrypt):**

1. Read the encrypted blob from parent storage via vsock file proxy
2. Get a fresh NSM attestation document
3. Call KMS Decrypt with the blob and attestation document
4. KMS verifies PCR values, and if they match the policy, returns plaintext
5. Reconstruct the full `EthKeyPair` from the recovered 32-byte private key

The `AppKeyService` integrates this in `get_or_create_in_memory_key()`:

```
1. Check in-memory cache -> if found, return
2. If KMS persistence configured, try recovery -> if success, cache and return
3. Generate new key
4. If KMS persistence configured, back it up
5. Cache and return
```

All private key material is wrapped in `Zeroizing<Vec<u8>>` and erased from memory on drop.

### Emergency backup system (`src/update_safety.rs`)

The `UpdateSafetyChecker` provides defense-in-depth, independent of KMS:

- **`pre_update_check()`**: Enumerates all in-memory keys, checks backup status. Returns `is_safe_to_update: true` only when every key is both backed up and verified.
- **`export_emergency_backup(passphrase, path)`**: Creates a JSON file where each key is independently encrypted with AES-256-GCM, keyed via PBKDF2-HMAC-SHA256 (600,000 iterations) from a user-supplied passphrase. Each entry has its own random salt and nonce. The app_id is used as AAD to prevent ciphertext transplanting.
- **`verify_post_update_recovery(expected_app_ids)`**: After a new enclave boots, checks that all previously-known keys were recovered.
- **`decrypt_emergency_entry()`** / **`verify_emergency_backup_file()`**: Static recovery utilities that can run without a full `UpdateSafetyChecker` instance.

### Safe update procedure

See `docs/SAFE_UPDATE_PROCEDURE.md` for the full step-by-step. The critical sequence:

1. Run `pre_update_check` -- verify all keys are backed up
2. Export emergency backup -- AES-256-GCM encrypted, copy off-instance
3. Build new EIF -- note new PCR0
4. **Update KMS policy to allow BOTH old and new PCR0**
5. Terminate old enclave
6. Start new enclave
7. Verify key recovery
8. Optionally remove old PCR0 from KMS policy

---

## 6. Docker Container Management

### TDX: Docker daemon runs locally

In the TDX deployment, `DockerComposeManager` spawns `docker compose` as a child process using `tokio::process::Command`. It reads stdout/stderr in real-time, waits for the process to complete, and parses the output.

### Nitro: Docker commands proxied to parent via vsock

In the Nitro deployment, the same `DockerComposeManager` methods are used, but the Docker invocation is replaced by a vsock RPC call to the parent's Docker proxy.

This is handled with `#[cfg(feature = "nitro")]` / `#[cfg(not(feature = "nitro"))]` blocks in `src/boot/manager.rs`. Example from `deploy_compose()`:

```rust
#[cfg(feature = "nitro")]
let (all_stdout, all_stderr) = {
    let working_dir = base_path.to_string_lossy().to_string();
    let resp = crate::docker_proxy::compose_up(app_id, compose_content, &working_dir).await?;
    if !resp.success {
        return Err(/* ... */);
    }
    (resp.stdout, resp.stderr)
};

#[cfg(not(feature = "nitro"))]
let (all_stdout, all_stderr) = {
    let mut child = Command::new("docker")
        .current_dir(&base_path)
        .args(["compose", "-f", "docker-compose.yml", "up", "-d"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // ... wait for process, collect output ...
};
```

The same pattern applies to `stop_app`, `get_app_status`, `get_app_logs`, `get_container_images`, `prune_images`, and service-level operations. Every Docker CLI call has a TDX path (local subprocess) and a Nitro path (vsock proxy RPC).

Imports are also conditionally compiled:

```rust
#[cfg(not(feature = "nitro"))]
use std::process::Stdio;
#[cfg(not(feature = "nitro"))]
use tokio::process::Command;
```

### Compose content sandboxing (`src/boot/compose_validator.rs`)

This module is not Nitro-specific, but was added as part of the port's security hardening. Before any Docker Compose YAML is written to disk, it is validated and sanitized:

**Forbidden configurations:**
- Capabilities: `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `ALL`
- Host mount paths: `/var/run/docker.sock`, `/etc/`, `/root/`, `/proc/`, `/sys/`
- `privileged: true`
- `network_mode: host`
- `pid: host`

**Injected resource limits** (when not explicitly set):
- Memory: 512m
- CPUs: 1.0
- PIDs limit: 256

The validator parses the YAML, checks each service, injects missing limits, and re-serializes. The sanitized content is what gets deployed.

### The `docker_proxy` module in `lib.rs`

The `docker_proxy` module is conditionally compiled:

```rust
#[cfg(feature = "nitro")]
pub mod docker_proxy;
```

This means `docker_proxy.rs` is only included in Nitro builds, keeping TDX builds clean of vsock dependencies.

---

## 7. Build System Changes

### `Dockerfile.multi`: dual-target builds

A single Dockerfile supports both platforms:

```bash
# AWS Nitro build
docker build --build-arg TARGET=aws -f Dockerfile.multi .

# Alibaba TDX build
docker build --build-arg TARGET=alibaba -f Dockerfile.multi .
```

**Stage structure:**

| Stage | Base | Build flags |
|---|---|---|
| `builder-aws` | `amazonlinux:2023` | `cargo build --release --features nitro` |
| `builder-alibaba` | Alibaba Cloud Linux 3 | `cargo build --release --features tdx` |
| `runtime-aws` | `amazonlinux:2023` | Includes `enclave-init.sh`, config-enclave.toml |
| `runtime-alibaba` | Alibaba Cloud Linux 3 | Includes Docker, `libtdx-attest`, `tpm2-tss` |
| `final` | Selected by `runtime-${TARGET}` | Creates directories, sets ENTRYPOINT |

The AWS runtime image includes an `enclave-init.sh` script that runs as PID 1 inside the enclave:
1. Sets a restrictive PATH
2. Brings up the loopback interface (required for the vsock-to-TCP bridge)
3. Verifies `/dev/nsm` exists
4. Drops privileges to the `tapp` user
5. Execs `tapp-server`

The Alibaba runtime includes Docker and TDX attestation libraries because the TDX VM runs Docker locally and needs hardware attestation libraries.

### Feature flags: mutually exclusive in production

```toml
[features]
default = []
tdx = ["dep:attestation-agent"]
nitro = ["dep:aws-nitro-enclaves-nsm-api", "dep:tokio-vsock", "dep:reqwest"]
simulation = []
```

Dependencies pulled per feature:

| Feature | Dependencies |
|---|---|
| `tdx` | `attestation-agent` (Inclavare guest-components) |
| `nitro` | `aws-nitro-enclaves-nsm-api`, `tokio-vsock`, `reqwest` |
| `simulation` | None (pure software, no hardware deps) |

The `compile_error!` guards in `factory.rs` enforce that `simulation` cannot be combined with `nitro` or `tdx`.

### EIF (Enclave Image File) build process

After the Docker image is built, the EIF is created using the Nitro CLI:

```bash
nitro-cli build-enclave --docker-uri tapp:aws --output-file tapp.eif
```

This produces:
- `tapp.eif` -- the enclave image
- **PCR0** (hash of enclave image)
- **PCR1** (hash of kernel)
- **PCR2** (hash of application)

### PCR values and reproducible builds

PCR0 is deterministic for a given Docker image. To achieve reproducible builds:

- `SOURCE_DATE_EPOCH=0` is set during the build
- `codegen-units=1` and `link-arg=-Wl,--build-id=none` are passed to rustc
- The existing `reproducible_build/Dockerfile` for TDX uses pinned dependency versions

For the AWS build in `Dockerfile.multi`, the same reproducibility flags are applied:

```dockerfile
ENV SOURCE_DATE_EPOCH=0
RUN cargo build --release --features nitro \
    --config 'build.rustflags=["-C", "link-arg=-Wl,--build-id=none", "-C", "codegen-units=1"]'
```

Any change to the source code, dependencies, or base image will change PCR0, which invalidates existing KMS key policies.

---

## 8. Configuration Changes

### `config-enclave.toml` vs the TDX config

The Nitro enclave config (`examples/config-enclave.toml`):

```toml
[logging]
level = "info"
format = "json"

[server]
bind_address = "127.0.0.1:50051"
max_connections = 1000
request_timeout_seconds = 30
tls_enabled = false

[boot]
tee_type = "nitro"
```

Key differences from the TDX configuration:

### `bind_address`: `127.0.0.1` (Nitro) vs `0.0.0.0` (TDX)

In TDX, the gRPC server binds to `0.0.0.0:50051` to accept connections from the network.

In Nitro, the gRPC server binds to `127.0.0.1:50051` (loopback only). External traffic arrives via the vsock bridge, which connects to localhost. There is no network interface to bind to, and binding to `0.0.0.0` would be meaningless.

### `tls_enabled`: `false` (Nitro)

In a Nitro Enclave, all traffic flows through vsock, which is a direct memory-mapped channel between parent and enclave -- there is no network to eavesdrop on. TLS adds overhead without security benefit inside the enclave. TLS can still be terminated at the socat proxy on the parent if needed.

### `tee_type`: `"nitro"`

Explicitly selects the Nitro provider. Without this, the factory would auto-detect from feature flags, which also works. Being explicit improves debuggability.

### KMS config section

For Nitro deployments with key persistence, add:

```toml
[kms]
kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abcd-1234-..."
storage_path = "/opt/tapp/keys"
region = "us-east-1"
```

This section does not exist in TDX configs because TDX does not need external key persistence.

### `boot.aa_config_path`: not needed for Nitro

The `aa_config_path` field configures the attestation-agent for TDX. It defaults to `"config/attestation-agent.toml"`. For Nitro builds, this field is ignored because the `NitroProvider` does not use the attestation-agent.

---

## 9. Security Hardening Applied

A 20-agent security review was performed on the codebase. Below is a summary of every CRITICAL and HIGH finding with the fix applied.

### CRITICAL fixes

**1. TOCTOU in attestation measurement (`src/tee/nitro.rs:200-218`)**

The `get_evidence()` method holds the accumulator `Mutex` lock across the entire NSM attestation operation. Without this, `extend_measurement()` could modify registers between serializing `user_data` and generating the signed attestation document.

**2. Key zeroization (`src/app_key/mod.rs:20-38`)**

All `EthKeyPair` private key fields are wrapped in `Zeroizing<Vec<u8>>` from the `zeroize` crate. When the key pair is dropped, private key bytes are overwritten with zeros before deallocation. The `Clone` trait is intentionally not derived -- key duplication requires calling `duplicate()` explicitly to prevent uncontrolled copies of private key material. Intermediate stack copies of key material (e.g., x25519 derivation) are also zeroized:

```rust
let mut x25519_private_bytes = [0u8; 32];
x25519_private_bytes.copy_from_slice(&private_key[..32]);
let x25519_secret = x25519_dalek::StaticSecret::from(x25519_private_bytes);
x25519_private_bytes.zeroize();  // explicit stack zeroization
```

**3. GetAppSecretKey authentication fix (`src/lib.rs:371-402`)**

`GetAppSecretKey` returns raw private key material. It validates that the request originates from localhost or a same-host Docker container (`127.0.0.1`, `::1`, `172.16.0.0/12`, `10.0.0.0/8`, `192.168.0.0/16`). The remote address is extracted BEFORE consuming the request (preventing TOCTOU on the address):

```rust
let remote_addr = request.remote_addr();
// ... validate BEFORE request.into_inner()
```

In the auth layer (`src/auth_layer.rs:261`), `GetAppSecretKey` is classified as `MethodPermission::Public` -- meaning it bypasses signature auth. This is intentional: the IP-based restriction is the access control for this endpoint, and it is only reachable from inside the enclave's localhost or bridged Docker containers.

### HIGH fixes

**4. Nonce-based replay prevention (`src/nonce_manager.rs`)**

All authenticated gRPC requests include a nonce and timestamp. The `NonceManager`:
- Validates nonce format (8-64 chars, alphanumeric + hyphens/underscores)
- Rejects timestamps outside a 5-minute window
- Tracks used nonces and rejects duplicates
- Background task cleans up expired nonces every 60 seconds

The `NonceManager` is shared between the `TappServiceImpl` and the `AuthLayer` so that nonces consumed during signature verification are also tracked for replay prevention.

**5. SSRF prevention in WithdrawBalance (`src/balance_withdrawal.rs:14-26`)**

The `withdraw_balance()` function validates the RPC URL before making any outbound request:

```rust
if url_lower.contains("169.254.") || url_lower.contains("localhost")
    || url_lower.contains("127.0.0.") || url_lower.contains("[::1]")
    || url_lower.contains("0.0.0.0") || url_lower.contains("metadata")
    || url_lower.contains("10.") || url_lower.contains("172.16.")
    || url_lower.contains("192.168.")
{
    return Err(anyhow!("Invalid RPC URL: internal/private addresses not allowed"));
}
```

This blocks SSRF attacks that could target the EC2 instance metadata service (`169.254.169.254`), internal services, or the KMS endpoint.

**6. Path traversal prevention (`src/boot/manager.rs:55-59`)**

`get_app_dir()` validates `app_id` to prevent path traversal:

```rust
assert!(
    !app_id.contains("..") && !app_id.contains('/') && !app_id.contains('\\') && !app_id.is_empty(),
    "Invalid app_id: must not contain path separators or be empty"
);
```

Similarly, `KmsPersistence::blob_path()` (`src/app_key/kms_persistence.rs:310-321`) sanitizes app_id by filtering to alphanumeric, dash, and underscore characters only.

**7. Docker Compose content sandboxing (`src/boot/compose_validator.rs`)**

Prevents user-submitted Compose files from escalating privileges:
- Blocks `privileged: true`, `network_mode: host`, `pid: host`
- Blocks dangerous capabilities (SYS_ADMIN, SYS_PTRACE, NET_ADMIN, ALL)
- Blocks mounting sensitive host paths (`/var/run/docker.sock`, `/etc/`, `/proc/`, etc.)
- Injects resource limits (memory, CPU, PID limits) when not explicitly set

**8. Measurement collision prevention (`src/measurement_service.rs:37-44`)**

Measurement data uses length-prefixed format to prevent collision attacks:

```rust
let measurement_data = format!(
    "{}:{}:{}:{}:{}",
    ZGEL_DOMAIN.len(), ZGEL_DOMAIN,
    operation_name.len(), operation_name,
    data
);
```

Without length prefixes, `"op:a" + data "b:c"` would hash the same as `"op:a:b" + data "c"`.

**9. Constant-time key comparison (`src/app_key/kms_persistence.rs:683-692`)**

Backup verification uses constant-time comparison to prevent timing side-channel attacks:

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

**10. Fail-closed configuration loading (`src/main.rs:72-76`)**

If the config file fails to load, the server exits rather than falling back to insecure defaults:

```rust
Err(e) => {
    eprintln!("FATAL: Failed to load config from {}: {}", args.config, e);
    eprintln!("Refusing to start with default configuration (fail-closed).");
    std::process::exit(1);
}
```

**11. Enclave privilege dropping (`scripts/enclave-init.sh:28-35`)**

The enclave init script refuses to run the TAPP server as root:

```sh
if id tapp >/dev/null 2>&1; then
    exec runuser -u tapp -- /usr/local/bin/tapp-server ...
else
    echo "FATAL: 'tapp' user not found -- refusing to run as root."
    exit 1
fi
```

---

## 10. Deployment & Operations

### AWS infrastructure

**Instance type**: Any Nitro-capable instance with enclave support (e.g., `m5.xlarge`, `c5.2xlarge`). The enclave allocator must be enabled.

**Enclave allocator config** (`/etc/nitro_enclaves/allocator.yaml`):
- During build: 512 MiB (Docker needs host RAM)
- During run: 1536 MiB (enclave needs 1024 MiB + overhead)

The `deploy-enclave.sh` script manages this memory swapping automatically.

**Security groups**: Port 50051 (gRPC) must be open to the clients that need to reach TAPP. All other ports are internal (vsock is not IP-addressable).

**Enclave parameters** (from `deploy-enclave.sh`):
- CID: 5
- CPUs: 2
- Memory: 1024 MiB

### `deploy-enclave.sh` workflow

The deployment script (`scripts/deploy-enclave.sh`) is idempotent and safe to re-run:

1. **Remote sync**: If not running with `--local`, rsyncs the project to the EC2 instance and re-runs itself there.
2. **Preflight checks**: Verifies `docker`, `nitro-cli`, `socat`, `jq` are installed and services are running.
3. **Reduce allocator memory**: Sets allocator to 512 MiB so Docker has enough host RAM for the build.
4. **Build Docker image**: `docker build --build-arg TARGET=aws -f Dockerfile.multi -t tapp:aws .`
5. **Build EIF**: `nitro-cli build-enclave --docker-uri tapp:aws --output-file /tmp/tapp.eif` -- captures PCR values.
6. **Increase allocator memory**: Sets allocator to 1536 MiB for enclave launch.
7. **Terminate existing enclaves**: Idempotent cleanup.
8. **Launch enclave**: `nitro-cli run-enclave --eif-path /tmp/tapp.eif --cpu-count 2 --memory 1024 --enclave-cid 5`
9. **Start socat proxy**: Kills any existing socat for port 50051, starts new one.
10. **Health check**: Retries `tapp-cli get-tapp-info` up to 5 times with 3-second intervals.
11. **Summary**: Prints enclave ID, CID, PCR values, and useful diagnostic commands.

### Parent-side services

Two services must run on the parent EC2 instance alongside the enclave:

1. **socat**: Bridges TCP:50051 to vsock CID 5:50051 for gRPC traffic.
2. **docker-proxy-parent.py**: Listens on vsock port 50052 for Docker commands from the enclave.

For KMS key persistence, a third service on port 50053 handles file proxy operations. This can be the same Python script extended, or a separate daemon.

### Monitoring considerations

- **Enclave state**: `nitro-cli describe-enclaves` -- check for `"State": "RUNNING"`.
- **Enclave console**: `nitro-cli console --enclave-id <ID>` (requires debug-mode, NOT used in production).
- **gRPC health**: `tapp-cli get-tapp-info --addr http://127.0.0.1:50051`
- **socat logs**: `/var/log/tapp/socat.log`
- **Docker proxy**: stdout of `docker-proxy-parent.py`
- **Key backup status**: Call `PreUpdateCheck` via gRPC to verify all keys have valid KMS backups.

The enclave has no direct log export mechanism. Application logs are written to stdout, which is only visible via `nitro-cli console` in debug mode. For production, log aggregation should be implemented via a vsock-based log forwarder (not yet implemented).

### PerpDex deployment via TAPP

The `perpdex-tapp/` directory contains a reference deployment of PerpDex (a perpetual DEX) as a TAPP application:

- `docker-compose.yml`: Multi-service compose file (API server, settlement, price oracle, PostgreSQL)
- `configs/`: Application config files (API config, settlement config, price oracle config, DB init SQL)
- `deploy.sh`: Deployment script that calls the TAPP gRPC API to start the app
- `parent-setup.sh`: Prepares the parent EC2 instance (installs dependencies, configures Docker)

This demonstrates the end-to-end flow: a multi-container application deployed and managed inside the Nitro Enclave through the TAPP platform, with all Docker operations transparently proxied to the parent.
