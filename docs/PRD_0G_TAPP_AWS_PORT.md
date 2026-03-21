# PRD: 0G TAPP Platform Port from Alibaba Cloud TDX to AWS Nitro Enclaves

**Document Version**: 1.0
**Date**: 2026-03-20
**Author**: Bond Engineering
**Status**: Draft for Review
**Stakeholders**: 0G Foundation, Bond Engineering Leadership, Infrastructure Team

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Architecture](#2-current-architecture)
3. [Target Architecture](#3-target-architecture)
4. [Scope & Phases](#4-scope--phases)
5. [Technical Requirements](#5-technical-requirements)
6. [Migration Strategy](#6-migration-strategy)
7. [Infrastructure Requirements](#7-infrastructure-requirements)
8. [Risk Assessment](#8-risk-assessment)
9. [Effort Estimation](#9-effort-estimation)
10. [Success Criteria](#10-success-criteria)
11. [Appendix](#11-appendix)

---

## 1. Executive Summary

### 1.1 What Is This Project?

The 0G TAPP (Trusted Application Platform) is a Rust-based gRPC service that manages containerized applications within Trusted Execution Environments (TEEs). It provides cryptographic attestation, runtime measurement, and EVM-based authentication for secure compute workloads. Today, TAPP runs exclusively on Alibaba Cloud's TDX (Intel Trust Domain Extensions) infrastructure. This project ports TAPP to AWS Nitro Enclaves, enabling deployment on AWS infrastructure while maintaining the same security guarantees.

### 1.2 Why AWS?

| Driver | Detail |
|--------|--------|
| **Geographic reach** | Alibaba Cloud TDX availability is limited to China regions; AWS Nitro Enclaves are available in 20+ regions globally |
| **Ecosystem access** | Most 0G validators, node operators, and DeFi partners run on AWS |
| **Supply chain** | Alibaba Cloud Linux 3 and China-region enclave repos create a fragile, single-vendor dependency |
| **Compliance** | Western institutional partners require AWS/GCP hosting for regulatory reasons |
| **Redundancy** | Dual-TEE support (Alibaba TDX + AWS Nitro) eliminates single-cloud risk |

### 1.3 Project Scope

Port the 0G TAPP server to run on AWS Nitro Enclaves with full attestation, measurement, and gRPC API parity. Introduce a provider-based TEE abstraction layer so that future TEE backends (GCP Confidential VMs, Azure SGX) can be added without architectural changes.

### 1.4 Timeline Estimate

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 1: Build System & CI | 2 weeks | Week 2 |
| Phase 2: TEE Abstraction Layer | 3 weeks | Week 5 |
| Phase 3: AWS Nitro Attestation Provider | 3 weeks | Week 8 |
| Phase 4: State Persistence & Resilience | 2 weeks | Week 10 |
| Phase 5: Integration Testing & Hardening | 2 weeks | Week 12 |
| Phase 6: Dual-TEE Validation & Rollout | 2 weeks | Week 14 |

**Total estimated duration**: 14 weeks (3.5 months)
**Team size**: 2-3 engineers (Rust + infrastructure)

---

## 2. Current Architecture

### 2.1 System Overview

```
+------------------------------------------------------------------+
|  Alibaba Cloud ECS (TDX-enabled instance)                        |
|                                                                   |
|  +------------------------------------------------------------+  |
|  |  0G TAPP Server (Rust, Tonic gRPC on port 50051)           |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | AttestationAgent |  | MeasurementSvc   |                 |  |
|  |  | (TDX/SGX/SEV)    |  | (RTMR SHA384)    |                 |  |
|  |  +------------------+  +------------------+                 |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | AppManager       |  | AuthService      |                 |  |
|  |  | (Docker Compose) |  | (EIP-191 sigs)   |                 |  |
|  |  +------------------+  +------------------+                 |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | KeyManager       |  | NonceManager     |                 |  |
|  |  | (secp256k1/X25519)|  | (replay prevent) |                 |  |
|  |  +------------------+  +------------------+                 |  |
|  |                                                             |  |
|  |  +------------------+  +------------------+                 |  |
|  |  | TaskManager      |  | PermissionSvc    |                 |  |
|  |  | (async tracking) |  | (Owner/WL/Public)|                 |  |
|  |  +------------------+  +------------------+                 |  |
|  +------------------------------------------------------------+  |
|                                                                   |
|  /var/lib/tapp/apps/{app_id}/   <-- App artifacts on filesystem   |
+------------------------------------------------------------------+
```

### 2.2 Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust 1.91.0 |
| Async runtime | Tokio |
| gRPC framework | Tonic (with Hyper) |
| Container orchestration | Docker Compose via `tokio::process::Command` |
| Cryptography | k256 (secp256k1), sha3 (Keccak256), X25519 |
| Authentication | EIP-191 signature verification |
| TEE attestation | `attestation-agent` from `inclavare-containers/guest-components` |
| Configuration | TOML |
| Logging | tracing-subscriber (JSON/pretty + rolling file) |
| OS | Alibaba Cloud Linux 3 |

### 2.3 State Management

All runtime state is held in-memory with no database backend:

- **App registry**: Running apps, their configurations, and status
- **Task manager**: Async operation tracking (Pending -> Running -> Completed/Failed)
- **Nonce manager**: Replay attack prevention counters
- **Whitelist/Ownership**: Per-app access control lists
- **Key material**: In-memory secp256k1 + X25519 keypairs (or KBS-backed)

Filesystem persistence is limited to `/var/lib/tapp/apps/{app_id}/` for Docker Compose files, mount files, and app artifacts. All in-memory state is lost on service restart.

### 2.4 TEE-Specific Code (Alibaba TDX)

The TEE coupling points are concentrated in a small number of locations:

| File / Module | TEE Dependency | Description |
|---------------|---------------|-------------|
| `main.rs` (lines 111, 114, 117) | `AttestationAgent::new()`, `.init()`, `.get_tee_type()` | 3 `.expect()` panics if TEE unavailable |
| `attestation.rs` | `attestation-agent` crate | `get_evidence()` for remote attestation |
| `measurement.rs` | `extend_runtime_measurement()` | RTMR hash chain extensions |
| `Dockerfile` | `alibaba-cloud-linux-3` base image | China-region enclave repos |
| `Dockerfile` | `libtdx-attest-devel`, `tpm2-tss-devel`, `libsgx-dcap-quote-verify-devel` | Aliyun-only system packages |

### 2.5 Measurement Operations

The following operations are recorded in the RTMR measurement chain (SHA384):

- `start_app`
- `stop_app`
- `get_app_secret_key`
- Whitelist changes (add/remove)
- `docker_login` / `docker_logout`
- `withdraw_balance`

The `AppMeasurement` data structure is already TEE-agnostic -- it captures operation type, app ID, timestamp, and a content hash. Only the mechanism for extending these measurements into hardware registers is TEE-specific.

### 2.6 gRPC API Surface (20+ RPCs)

**Public (no auth required)**:
`GetEvidence`, `GetAppKey`, `GetAppInfo`, `GetTaskStatus`, `GetServiceStatus`, `GetAppSecretKey`, `GetTappInfo`

**Owner-only (EIP-191 signature required, must be app owner)**:
`StartApp`, `StopApp`, `AddToWhitelist`, `RemoveFromWhitelist`, `ListWhitelist`, `ListAllOwnerships`, `StopService`, `StartService`

**Whitelist (EIP-191 signature required, must be on whitelist)**:
`GetServiceLogs`, `GetAppLogs`, `GetAppOwnership`, `WithdrawBalance`, `DockerLogin`, `DockerLogout`, `PruneImages`

---

## 3. Target Architecture

### 3.1 AWS Nitro Architecture

```
+------------------------------------------------------------------+
|  AWS EC2 (Nitro Enclave-enabled instance, e.g. c6i.xlarge)       |
|                                                                   |
|  +----------------------------+  +-----------------------------+  |
|  |  Parent Instance           |  |  Nitro Enclave (EIF)        |  |
|  |                            |  |                              |  |
|  |  vsock proxy <------------>|  |  0G TAPP Server              |  |
|  |  (port 50051 <-> CID:5)   |  |  (Tonic gRPC on vsock)      |  |
|  |                            |  |                              |  |
|  |  Docker daemon             |  |  NitroAttestationProvider   |  |
|  |  (app containers)         |  |  (NSM API for attestation)   |  |
|  |                            |  |  MeasurementAccumulator     |  |
|  |  /var/lib/tapp/ (EBS)     |  |  (software PCR equivalent)   |  |
|  +----------------------------+  +-----------------------------+  |
|                                                                   |
|  Optional: DynamoDB for state persistence                         |
|  Optional: AWS KMS for key management                             |
+------------------------------------------------------------------+
```

### 3.2 Key Architectural Differences

| Aspect | Alibaba TDX | AWS Nitro |
|--------|------------|-----------|
| Attestation hardware | TDX via `attestation-agent` | NSM (Nitro Security Module) via `aws-nitro-enclaves-nsm-api` |
| Measurement registers | RTMR (runtime-extendable, SHA384) | PCR (fixed at launch, SHA384) |
| Runtime measurement | Hardware RTMR extend | Software accumulation + embed in attestation doc `user_data` (512 bytes) |
| Image format | Standard Docker image | EIF (Enclave Image Format) via `nitro-cli build-enclave` |
| Networking | Standard TCP | vsock (Virtual Socket) -- no TCP/IP inside enclave |
| Filesystem | Standard filesystem | Read-only root; no persistent storage inside enclave |
| Container orchestration | Docker Compose inside TEE | Docker Compose on parent instance, orchestrated via vsock |

### 3.3 TEE Provider Abstraction

```rust
/// Core trait that all TEE backends must implement
#[async_trait]
pub trait TeeProvider: Send + Sync {
    /// Initialize the TEE environment
    async fn init(&self) -> Result<(), TeeError>;

    /// Get the TEE type identifier (e.g., "tdx", "nitro", "simulation")
    fn tee_type(&self) -> TeeType;

    /// Generate attestation evidence
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<Vec<u8>, TeeError>;

    /// Extend a runtime measurement
    async fn extend_measurement(
        &self,
        register_index: u32,
        data: &[u8],
    ) -> Result<(), TeeError>;

    /// Get current measurement values
    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError>;
}

pub enum TeeType {
    Tdx,
    Nitro,
    Simulation, // For development/testing
}
```

### 3.4 Measurement Strategy for Nitro

Since Nitro PCRs are fixed at enclave launch and cannot be extended at runtime, we implement a software measurement accumulator:

```
Enclave Launch
  |
  v
PCR0-PCR8 locked (enclave image hash, kernel, etc.)
  |
  v
Software MeasurementAccumulator initialized
  |-- SHA384 hash chain (mirrors RTMR semantics)
  |-- Each operation: new_hash = SHA384(prev_hash || operation_data)
  |-- Current accumulated hash stored in memory
  |
  v
On GetEvidence request:
  |-- Pack accumulated measurement hash into attestation doc `user_data` (512 bytes)
  |-- NSM signs the attestation doc (including user_data)
  |-- Verifier checks: PCRs (static image integrity) + user_data (runtime behavior)
```

This provides equivalent security guarantees: the accumulated measurement is cryptographically bound to the attestation document signed by the Nitro hardware.

---

## 4. Scope & Phases

### Phase 1: Build System & CI (Weeks 1-2)

Replace the Alibaba Cloud Linux 3 build pipeline with a multi-target build system that supports both Alibaba and AWS.

**Deliverables**:
- Multi-stage Dockerfile supporting Amazon Linux 2023 and Alibaba Cloud Linux 3
- CI pipeline that builds for both targets
- EIF (Enclave Image Format) build step for Nitro
- Removal of hard dependency on China-region package repos

### Phase 2: TEE Abstraction Layer (Weeks 3-5)

Introduce a `TeeProvider` trait that decouples core TAPP logic from any specific TEE implementation.

**Deliverables**:
- `TeeProvider` trait definition
- `TdxProvider` implementation (wraps existing `attestation-agent` code)
- `SimulationProvider` implementation (for dev/test without TEE hardware)
- Refactor `main.rs` to use provider pattern (eliminate 3 `.expect()` panics)
- Refactor `attestation.rs` and `measurement.rs` to use provider trait
- Feature flags: `--features tdx`, `--features nitro`, `--features simulation`

### Phase 3: AWS Nitro Attestation Provider (Weeks 6-8)

Implement the Nitro-specific `TeeProvider` using the NSM API.

**Deliverables**:
- `NitroProvider` implementing `TeeProvider`
- `MeasurementAccumulator` (software RTMR equivalent)
- NSM attestation document generation via `aws-nitro-enclaves-nsm-api`
- vsock networking layer (replace TCP listener for enclave mode)
- Parent instance proxy (TCP 50051 <-> vsock CID:5)
- Docker orchestration bridge (enclave -> parent instance via vsock)

### Phase 4: State Persistence & Resilience (Weeks 9-10)

Address the in-memory state limitation to support enclave restarts and operational resilience.

**Deliverables**:
- Optional state persistence layer (DynamoDB or encrypted EBS)
- State snapshot/restore on enclave restart
- Graceful shutdown with state flush
- Health check endpoint for load balancer integration

### Phase 5: Integration Testing & Hardening (Weeks 11-12)

End-to-end testing on real AWS Nitro hardware.

**Deliverables**:
- Integration test suite running on Nitro-enabled EC2 instances
- Attestation verification test (generate + verify cycle)
- All 20+ gRPC RPCs tested on Nitro
- Performance benchmarks (latency, throughput)
- Security audit of the abstraction layer

### Phase 6: Dual-TEE Validation & Rollout (Weeks 13-14)

Validate that both Alibaba TDX and AWS Nitro deployments pass the same acceptance criteria.

**Deliverables**:
- Side-by-side deployment validation
- Runbook for Nitro deployment
- Monitoring and alerting setup
- Documentation updates
- Handoff to 0G Foundation operations team

---

## 5. Technical Requirements

### 5.1 Phase 1: Build System & CI

#### REQ-1.1: Multi-Target Dockerfile

**Description**: Create a Dockerfile that can target both Alibaba Cloud Linux 3 and Amazon Linux 2023.

**Acceptance Criteria**:
- `docker build --build-arg TARGET=alibaba .` produces the existing Alibaba image
- `docker build --build-arg TARGET=aws .` produces an Amazon Linux 2023 image
- Both images compile the same Rust binary with identical Cargo.lock
- No references to China-region repos when `TARGET=aws`

**Implementation Notes**:
- Replace `alibaba-cloud-linux-3` base with conditional base image selection
- For AWS target, replace `libtdx-attest-devel` with `aws-nitro-enclaves-nsm-api` (Rust crate, no system package needed)
- Remove `tpm2-tss-devel` dependency for AWS target (TPM not used in Nitro)
- Remove `libsgx-dcap-quote-verify-devel` for AWS target (SGX not used in Nitro)
- Preserve reproducible build flags: `SOURCE_DATE_EPOCH`, `--build-id=none`, single-threaded codegen

#### REQ-1.2: EIF Build Pipeline

**Description**: Add a build step that packages the AWS binary into a Nitro Enclave Image Format.

**Acceptance Criteria**:
- `nitro-cli build-enclave --docker-uri tapp:aws --output-file tapp.eif` succeeds
- EIF includes the TAPP binary, required shared libraries, and init process
- PCR0 (enclave image hash) is deterministic for the same source code
- Build produces a PCR manifest file for verification

**Implementation Notes**:
- Use `nitro-cli` (available via `aws-nitro-enclaves-cli` package)
- EIF requires a minimal Linux init system inside the enclave
- Consider using `nitro-enclaves-sdk-bootstrap` for the init process

#### REQ-1.3: CI Pipeline

**Description**: Automated build and test pipeline for both targets.

**Acceptance Criteria**:
- CI builds both Alibaba and AWS Docker images on every PR
- Rust unit tests pass for both `--features tdx` and `--features nitro`
- `--features simulation` tests pass without any TEE hardware
- Linting and formatting checks pass

### 5.2 Phase 2: TEE Abstraction Layer

#### REQ-2.1: TeeProvider Trait

**Description**: Define a trait that abstracts all TEE-specific operations.

**Acceptance Criteria**:
- Trait covers: initialization, attestation evidence generation, measurement extension, measurement retrieval, TEE type identification
- Trait is `Send + Sync + 'static` for use in async contexts
- Error types are TEE-agnostic (`TeeError` enum with provider-specific variants)
- Trait is defined in a new `tee-provider` module/crate

**Interface Specification**:
```rust
#[async_trait]
pub trait TeeProvider: Send + Sync + 'static {
    async fn init(&self) -> Result<(), TeeError>;
    fn tee_type(&self) -> TeeType;
    async fn get_evidence(&self, runtime_data: &[u8]) -> Result<AttestationEvidence, TeeError>;
    async fn extend_measurement(&self, register: u32, data: &[u8]) -> Result<(), TeeError>;
    async fn get_measurements(&self) -> Result<Vec<MeasurementRegister>, TeeError>;
}

pub struct AttestationEvidence {
    pub raw: Vec<u8>,
    pub tee_type: TeeType,
    pub timestamp: u64,
}

pub struct MeasurementRegister {
    pub index: u32,
    pub value: [u8; 48], // SHA384
    pub description: String,
}

pub enum TeeError {
    NotAvailable,
    InitializationFailed(String),
    AttestationFailed(String),
    MeasurementFailed(String),
    ProviderSpecific(Box<dyn std::error::Error + Send + Sync>),
}
```

#### REQ-2.2: TDX Provider (Wrap Existing Code)

**Description**: Move existing Alibaba TDX code behind the `TeeProvider` trait.

**Acceptance Criteria**:
- `TdxProvider` implements `TeeProvider` using existing `attestation-agent` crate
- All existing attestation and measurement behavior is preserved
- Compiled only when `--features tdx` is active
- Passes all existing integration tests

#### REQ-2.3: Simulation Provider

**Description**: A mock TEE provider for development and testing.

**Acceptance Criteria**:
- `SimulationProvider` implements `TeeProvider` with deterministic, non-cryptographic behavior
- `get_evidence()` returns a clearly-marked simulation attestation (not forgeable as real)
- `extend_measurement()` maintains a software hash chain identical to production semantics
- Compiled when `--features simulation` is active
- TAPP starts and runs all 20+ gRPC RPCs in simulation mode
- Simulation attestation documents include a `"simulation": true` field

#### REQ-2.4: Eliminate Startup Panics

**Description**: Replace the 3 `.expect()` calls in `main.rs` (lines 111, 114, 117) with graceful error handling.

**Acceptance Criteria**:
- `main.rs` no longer panics if TEE hardware is unavailable
- If TEE initialization fails and `--features simulation` is not enabled, the service exits with a clear error message (not a panic)
- If `--features simulation` is enabled, the service falls back to `SimulationProvider` with a warning log
- Error messages include actionable guidance (e.g., "TDX not available. Run with --features simulation for development, or ensure TDX hardware is configured.")

#### REQ-2.5: Feature Flag Compilation

**Description**: Use Cargo feature flags to control which TEE provider is compiled.

**Acceptance Criteria**:
- `Cargo.toml` defines features: `tdx`, `nitro`, `simulation`
- Exactly one TEE feature must be active at compile time (enforced by `cfg` checks)
- `tdx` pulls in `attestation-agent` and Alibaba-specific deps
- `nitro` pulls in `aws-nitro-enclaves-nsm-api`
- `simulation` has no TEE-specific dependencies
- Default feature is `simulation` for developer ergonomics

### 5.3 Phase 3: AWS Nitro Attestation Provider

#### REQ-3.1: NitroProvider Implementation

**Description**: Implement `TeeProvider` for AWS Nitro Enclaves using the NSM API.

**Acceptance Criteria**:
- `NitroProvider` calls NSM API via `aws-nitro-enclaves-nsm-api` crate
- `init()` verifies enclave environment (NSM device available at `/dev/nsm`)
- `get_evidence()` returns a CBOR-encoded Nitro attestation document
- `tee_type()` returns `TeeType::Nitro`
- Attestation document is verifiable using AWS Nitro attestation verification process (root cert chain)

**Crate Dependencies**:
- `aws-nitro-enclaves-nsm-api` (NSM device interface)
- `serde_cbor` (attestation document encoding)
- `aws-nitro-enclaves-attestation` (optional, for local verification)

#### REQ-3.2: Software Measurement Accumulator

**Description**: Since Nitro PCRs are locked at launch, implement a software measurement chain that provides equivalent runtime auditability.

**Acceptance Criteria**:
- `MeasurementAccumulator` maintains a SHA384 hash chain in enclave memory
- Each `extend_measurement()` call: `new = SHA384(current || register_index || data)`
- Accumulated hash is embedded in the `user_data` field (512 bytes max) of NSM attestation documents
- All 6 measured operations (start_app, stop_app, get_app_secret_key, whitelist changes, docker login/logout, withdraw_balance) produce identical measurement semantics to TDX RTMR
- A verifier can extract `user_data` from the attestation doc and verify the measurement chain

**Design Detail**:
```rust
pub struct MeasurementAccumulator {
    registers: [Sha384Hash; 4], // Mirror 4 RTMR registers
}

impl MeasurementAccumulator {
    pub fn extend(&mut self, register: u32, data: &[u8]) {
        let mut hasher = Sha384::new();
        hasher.update(&self.registers[register as usize]);
        hasher.update(data);
        self.registers[register as usize] = hasher.finalize().into();
    }

    pub fn to_user_data(&self) -> [u8; 192] {
        // Pack 4 x 48-byte registers = 192 bytes (fits in 512-byte user_data)
        let mut out = [0u8; 192];
        for (i, reg) in self.registers.iter().enumerate() {
            out[i*48..(i+1)*48].copy_from_slice(reg);
        }
        out
    }
}
```

#### REQ-3.3: vsock Networking

**Description**: Nitro Enclaves have no TCP/IP networking. Replace the TCP gRPC listener with vsock for enclave mode, with a parent-instance proxy for external access.

**Acceptance Criteria**:
- TAPP listens on vsock (CID 5, port 50051) when running inside a Nitro Enclave
- A parent-instance proxy translates TCP 50051 <-> vsock CID:5 port 50051
- Existing gRPC clients (grpcurl, application clients) work transparently via the proxy
- vsock listener is only compiled when `--features nitro` is active
- Configuration: `listen_addr` supports both `tcp://0.0.0.0:50051` and `vsock://5:50051`

**Implementation Notes**:
- Use `tokio-vsock` crate for async vsock support
- Tonic supports custom `Connected` implementations for vsock
- Parent proxy can be a simple Rust binary or `socat` for initial development
- Consider `vsock-proxy` from `aws-nitro-enclaves-cli` for the parent-side proxy

#### REQ-3.4: Docker Orchestration Bridge

**Description**: Nitro Enclaves cannot run Docker. App containers must run on the parent instance, orchestrated from the enclave via vsock.

**Acceptance Criteria**:
- Docker Compose commands are forwarded from enclave to parent instance over vsock
- Parent instance runs a Docker orchestration daemon that executes forwarded commands
- File transfers (Compose YAML, mount files) work over vsock
- App logs are streamable from parent instance to enclave over vsock
- Security: only the enclave can issue Docker commands to the bridge (authenticated channel)

**Implementation Notes**:
- Current code uses `tokio::process::Command` to shell out to `docker compose`
- Replace with a vsock-based RPC to a parent-side daemon that executes `docker compose`
- Consider a simple protobuf-based protocol for the bridge
- Bridge daemon on parent instance must verify requests come from the local enclave (vsock CID validation)

### 5.4 Phase 4: State Persistence & Resilience

#### REQ-4.1: State Persistence Layer

**Description**: Add optional state persistence so enclave restarts do not lose all runtime state.

**Acceptance Criteria**:
- App registry, ownership, and whitelist state can be persisted and restored
- Persistence is encrypted at rest (enclave-derived key or AWS KMS)
- State restore on startup is optional and configurable
- Nonce manager state is persisted to prevent replay attacks across restarts
- Task manager history is persisted for audit trail

**Storage Options** (choose one during implementation):
1. **Encrypted EBS volume** mounted on parent instance, accessed via vsock
2. **DynamoDB** accessed via vsock proxy to parent instance (then outbound HTTPS)
3. **Local encrypted file** on parent instance, accessed via vsock

Recommended: Encrypted EBS for simplicity and low latency. DynamoDB for multi-instance scenarios.

#### REQ-4.2: Graceful Shutdown

**Description**: Flush state to persistent storage on SIGTERM/SIGINT.

**Acceptance Criteria**:
- On shutdown signal, TAPP flushes all in-memory state to persistent storage
- In-flight gRPC requests are drained (configurable timeout, default 30s)
- Running app containers are NOT stopped (they run on parent instance)
- Shutdown completes within 60 seconds

#### REQ-4.3: Health Check Endpoint

**Description**: Add a health check for load balancer and orchestration integration.

**Acceptance Criteria**:
- `/health` or gRPC health check returns enclave status, TEE type, uptime, and app count
- Suitable for ALB health checks
- Returns `SERVING` / `NOT_SERVING` per gRPC health check protocol

### 5.5 Phase 5: Integration Testing & Hardening

#### REQ-5.1: End-to-End Test Suite

**Description**: Automated tests that run on real Nitro hardware.

**Acceptance Criteria**:
- All 20+ gRPC RPCs tested against a Nitro-deployed TAPP instance
- Attestation generation and verification round-trip test
- App lifecycle test: StartApp -> GetTaskStatus -> GetAppInfo -> StopApp
- Auth test: valid signature accepted, invalid signature rejected, replay rejected
- Measurement test: operations produce correct hash chain
- Tests runnable via CI on a Nitro-enabled EC2 runner

#### REQ-5.2: Performance Benchmarks

**Description**: Establish baseline performance on Nitro.

**Acceptance Criteria**:
- gRPC latency benchmarks for all RPCs (p50, p95, p99)
- Attestation generation latency < 500ms
- vsock overhead measured vs. direct TCP
- Comparison with Alibaba TDX baseline (if available)
- Results documented in benchmark report

#### REQ-5.3: Security Review

**Description**: Review the abstraction layer for security weaknesses.

**Acceptance Criteria**:
- No information leakage between TEE providers via shared state
- Simulation provider cannot be accidentally deployed in production
- Attestation documents are correctly bound to the enclave identity
- vsock bridge does not expose Docker control to unauthorized callers
- Measurement accumulator is not resettable by application code

---

## 6. Migration Strategy

### 6.1 Feature Flag Architecture

The migration uses Cargo feature flags to enable incremental development without breaking the existing Alibaba deployment.

```toml
# Cargo.toml
[features]
default = ["simulation"]
tdx = ["attestation-agent", "libtdx-attest"]
nitro = ["aws-nitro-enclaves-nsm-api", "tokio-vsock"]
simulation = []
```

```rust
// main.rs — provider selection
fn create_tee_provider(config: &Config) -> Box<dyn TeeProvider> {
    #[cfg(feature = "nitro")]
    { Box::new(NitroProvider::new(config)) }

    #[cfg(feature = "tdx")]
    { Box::new(TdxProvider::new(config)) }

    #[cfg(feature = "simulation")]
    { Box::new(SimulationProvider::new(config)) }
}
```

### 6.2 Step-by-Step Migration

```
Step 1: Branch from current main
         |
Step 2: Introduce TeeProvider trait (no behavior change)
         |-- Existing code wrapped in TdxProvider
         |-- All tests pass
         |
Step 3: Add SimulationProvider
         |-- Developers can run TAPP locally without TEE
         |-- CI runs full test suite in simulation mode
         |
Step 4: Add NitroProvider (behind feature flag)
         |-- Compiled only with --features nitro
         |-- No impact on existing Alibaba builds
         |
Step 5: Add vsock networking (behind feature flag)
         |-- TCP listener still default
         |-- vsock listener activated by config
         |
Step 6: Add Docker bridge (behind feature flag)
         |-- Local Docker still default
         |-- vsock bridge activated by config
         |
Step 7: Integration test on Nitro hardware
         |-- Deploy EIF to test enclave
         |-- Run full gRPC test suite
         |
Step 8: Dual-TEE validation
         |-- Same test suite passes on both Alibaba TDX and AWS Nitro
         |-- Attestation documents from both are verifiable
         |
Step 9: Production rollout
         |-- AWS deployment with monitoring
         |-- Alibaba deployment unchanged
```

### 6.3 Rollback Plan

Each phase is independently reversible:
- **Build system**: Revert Dockerfile changes, original Alibaba build still works
- **Abstraction layer**: `TdxProvider` is a direct wrapper of existing code; remove trait layer if needed
- **Nitro provider**: Behind feature flag; simply do not compile with `--features nitro`
- **State persistence**: Optional and configurable; disable in config to revert to in-memory only

### 6.4 Compatibility Matrix

| Feature | Alibaba TDX | AWS Nitro | Simulation |
|---------|------------|-----------|------------|
| Attestation | Hardware TDX | Hardware NSM | Software mock |
| Runtime measurement | RTMR hardware | Software accumulator | Software accumulator |
| Networking | TCP | vsock + TCP proxy | TCP |
| Docker | Local daemon | Parent instance via bridge | Local daemon |
| Key storage | In-memory / KBS | In-memory / KMS | In-memory |
| State persistence | Filesystem | Encrypted EBS / DynamoDB | Filesystem |

---

## 7. Infrastructure Requirements

### 7.1 AWS Services

| Service | Purpose | Estimated Cost (monthly) |
|---------|---------|------------------------|
| **EC2 (Nitro Enclave-enabled)** | TAPP host | $150-400 (c6i.xlarge-2xlarge) |
| **EBS** | App artifacts + state persistence | $20-50 (100GB gp3) |
| **DynamoDB** (optional) | State persistence for multi-instance | $5-25 (on-demand) |
| **KMS** (optional) | Key management | $1-5 |
| **ECR** | Container registry for EIF and app images | $10-30 |
| **CloudWatch** | Logging and monitoring | $10-30 |
| **ALB** | Load balancing gRPC traffic | $20-40 |
| **VPC** | Network isolation | $0 (included) |

**Estimated total**: $216-580/month per TAPP instance

### 7.2 EC2 Instance Selection

Nitro Enclave-capable instance types (recommended):

| Instance | vCPUs | RAM | Enclave RAM (max) | Use Case |
|----------|-------|-----|-------------------|----------|
| `c6i.xlarge` | 4 | 8 GB | 6 GB | Development/testing |
| `c6i.2xlarge` | 8 | 16 GB | 12 GB | Production (light) |
| `c6i.4xlarge` | 16 | 32 GB | 28 GB | Production (heavy) |
| `m6i.2xlarge` | 8 | 32 GB | 28 GB | Memory-intensive apps |

**Requirement**: Instance must have `enclave: true` in the Nitro Enclave allocator config.

### 7.3 Enclave Resource Allocation

```yaml
# /etc/nitro_enclaves/allocator.yaml
memory_mib: 4096    # 4 GB for enclave (TAPP + headroom)
cpu_count: 2        # 2 vCPUs dedicated to enclave
```

The enclave needs enough memory for:
- TAPP binary (~50 MB)
- Rust runtime + async tasks (~200 MB)
- In-memory state (~100 MB)
- Measurement accumulator (~1 MB)
- Headroom for spikes (~3.6 GB)

### 7.4 Networking Architecture

```
Internet
    |
    v
ALB (TCP/gRPC passthrough, port 50051)
    |
    v
EC2 Parent Instance (Security Group: allow 50051 from ALB only)
    |
    v
vsock-proxy (TCP 50051 <-> vsock CID:5 port 50051)
    |
    v
Nitro Enclave (TAPP listening on vsock)
```

### 7.5 Security Configuration

- **Security Group**: Inbound 50051 from ALB only, no SSH to parent (use SSM)
- **IAM Role**: EC2 instance role with permissions for ECR pull, CloudWatch logs, DynamoDB (if used), KMS (if used)
- **Enclave isolation**: No network access from enclave except vsock to parent
- **Secrets**: Never on parent instance filesystem; passed via vsock from Secrets Manager or embedded in EIF

---

## 8. Risk Assessment

### 8.1 Technical Risks

| # | Risk | Severity | Likelihood | Mitigation |
|---|------|----------|-----------|------------|
| R1 | **Nitro PCR immutability breaks runtime measurement semantics** | High | Confirmed | Software measurement accumulator embedded in attestation doc `user_data`. Verifiers must be updated to check `user_data` field. |
| R2 | **vsock latency impacts gRPC performance** | Medium | Medium | Benchmark early (Phase 3). vsock is kernel-level, typically <1ms overhead. If unacceptable, batch Docker bridge calls. |
| R3 | **Docker bridge introduces new attack surface** | High | Medium | Authenticate bridge channel (enclave-only vsock CID). Whitelist allowed Docker commands. Run bridge daemon with minimal permissions. |
| R4 | **EIF build reproducibility differs from Docker** | Medium | Medium | Pin EIF toolchain version. Compare PCR0 across builds. Document exact build environment. |
| R5 | **`attestation-agent` crate has undocumented Alibaba-specific behavior** | Medium | Low | Wrap completely behind trait; do not rely on internal behavior. Integration test both providers against the same test suite. |
| R6 | **Nitro Enclave memory limits constrain TAPP** | Medium | Low | Profile memory usage. TAPP is lightweight (~350 MB). Allocate 4 GB enclave, monitor with CloudWatch custom metrics. |
| R7 | **In-memory state loss on enclave crash** | High | Medium | Phase 4 state persistence addresses this. For Phase 3, document that state is volatile (same as current Alibaba behavior). |
| R8 | **Verifier ecosystem not ready for dual-TEE attestation docs** | Medium | Medium | Provide verification libraries and documentation for both TDX and Nitro attestation formats. Ship verifier SDK with TAPP. |

### 8.2 Organizational Risks

| # | Risk | Severity | Likelihood | Mitigation |
|---|------|----------|-----------|------------|
| R9 | **0G Foundation changes TAPP upstream during port** | Medium | High | Rebase weekly. Abstraction layer minimizes merge conflicts since core changes are additive. |
| R10 | **AWS Nitro Enclave API changes** | Low | Low | Pin `aws-nitro-enclaves-nsm-api` version. NSM API is stable and versioned. |
| R11 | **Team unfamiliar with Nitro Enclaves** | Medium | Medium | Allocate 1 week ramp-up. AWS provides Nitro Enclaves workshop and documentation. Use simulation mode for initial development. |

---

## 9. Effort Estimation

### 9.1 Per-Phase Breakdown

| Phase | Tasks | Engineer-Weeks | Engineers | Calendar Weeks |
|-------|-------|---------------|-----------|---------------|
| **Phase 1: Build System** | Multi-target Dockerfile, EIF pipeline, CI | 3 | 1 | 2 |
| **Phase 2: TEE Abstraction** | Trait design, TdxProvider, SimulationProvider, main.rs refactor, feature flags | 5 | 2 | 3 |
| **Phase 3: Nitro Provider** | NitroProvider, MeasurementAccumulator, vsock networking, Docker bridge | 6 | 2 | 3 |
| **Phase 4: State Persistence** | Persistence layer, graceful shutdown, health check | 3 | 1-2 | 2 |
| **Phase 5: Integration Test** | E2E tests, benchmarks, security review | 4 | 2 | 2 |
| **Phase 6: Dual-TEE Rollout** | Validation, runbook, monitoring, docs | 3 | 1-2 | 2 |
| **Total** | | **24 engineer-weeks** | 2-3 | **14 weeks** |

### 9.2 Effort by Skill Area

| Skill Area | Engineer-Weeks | Notes |
|-----------|---------------|-------|
| Rust systems programming | 14 | Trait design, providers, vsock, bridge |
| Infrastructure / DevOps | 5 | Dockerfile, EIF, CI, EC2 setup, monitoring |
| Security / Cryptography | 3 | Attestation verification, measurement design, security review |
| Testing / QA | 2 | Integration tests, benchmarks |

### 9.3 Dependencies & Blockers

| Dependency | Required By | Lead Time |
|-----------|------------|-----------|
| AWS account with Nitro Enclave access | Phase 3 | 1-2 days |
| Nitro-enabled EC2 instance (at least c6i.xlarge) | Phase 3 | 1 day (on-demand) |
| `aws-nitro-enclaves-cli` toolchain installed on build machine | Phase 1 | 1 hour |
| Access to 0G TAPP source repository | Phase 1 | Immediate (assumed) |
| 0G Foundation review of trait design | Phase 2 | 1 week (schedule early) |

---

## 10. Success Criteria

### 10.1 Minimum Viable Port (Phase 3 Complete)

- [ ] TAPP binary compiles with `--features nitro` on Amazon Linux 2023
- [ ] EIF builds successfully and produces deterministic PCR0
- [ ] TAPP starts inside a Nitro Enclave and listens on vsock
- [ ] All 20+ gRPC RPCs are accessible via the TCP-to-vsock proxy
- [ ] `GetEvidence` returns a valid Nitro attestation document with measurement data in `user_data`
- [ ] `StartApp` deploys a Docker Compose application on the parent instance via the bridge
- [ ] EIP-191 authentication works identically to TDX deployment
- [ ] Existing `--features tdx` build is unaffected (no regressions)

### 10.2 Production Ready (Phase 6 Complete)

- [ ] All MVP criteria met
- [ ] State persists across enclave restarts
- [ ] Graceful shutdown flushes state in <60 seconds
- [ ] Health check endpoint returns correct status
- [ ] gRPC latency p95 < 100ms for non-attestation RPCs
- [ ] Attestation generation latency p95 < 500ms
- [ ] Integration test suite passes on Nitro hardware in CI
- [ ] Same test suite passes on both TDX and Nitro
- [ ] Deployment runbook reviewed and tested by operations team
- [ ] Monitoring dashboards operational (CloudWatch)
- [ ] Security review completed with no critical findings
- [ ] 0G Foundation sign-off on attestation document format

### 10.3 Stretch Goals

- [ ] Multi-instance TAPP with shared state (DynamoDB)
- [ ] Automated enclave health recovery (restart on crash)
- [ ] GCP Confidential VM provider stub (trait implementation placeholder)
- [ ] Verifier SDK published as a crate for attestation consumers

---

## 11. Appendix

### A. Dependency Inventory

#### A.1 Current TEE-Specific Dependencies (to be replaced/abstracted)

| Dependency | Type | Alibaba TDX | AWS Nitro Replacement |
|-----------|------|------------|----------------------|
| `attestation-agent` | Rust crate | Required | Not needed (use `aws-nitro-enclaves-nsm-api`) |
| `libtdx-attest-devel` | System package (RPM) | Required | Not needed |
| `tpm2-tss-devel` | System package (RPM) | Required | Not needed |
| `libsgx-dcap-quote-verify-devel` | System package (RPM) | Required | Not needed |
| `alibaba-cloud-linux-3` | Docker base image | Required | Replace with `amazonlinux:2023` |

#### A.2 New AWS-Specific Dependencies

| Dependency | Type | Version | Purpose |
|-----------|------|---------|---------|
| `aws-nitro-enclaves-nsm-api` | Rust crate | latest stable | NSM device interface for attestation |
| `tokio-vsock` | Rust crate | latest stable | Async vsock support for enclave networking |
| `serde_cbor` | Rust crate | latest stable | CBOR encoding for attestation documents |
| `aws-nitro-enclaves-cli` | System tool | latest stable | EIF build toolchain |
| `vsock-proxy` | System tool | latest stable | TCP-to-vsock proxy on parent instance |
| `amazonlinux:2023` | Docker base image | latest | Build environment base |

#### A.3 Portable Dependencies (No Changes Needed)

All 663 Cargo packages minus the 5 TEE-specific ones are fully portable. Key portable dependencies:

| Category | Crates |
|---------|--------|
| gRPC | `tonic`, `prost`, `hyper`, `tower` |
| Async | `tokio`, `futures`, `async-trait` |
| Crypto | `k256`, `sha3`, `sha2`, `x25519-dalek`, `rand` |
| Serialization | `serde`, `serde_json`, `toml` |
| Logging | `tracing`, `tracing-subscriber`, `tracing-appender` |
| Docker | (none -- uses `tokio::process::Command` to shell out) |

### B. gRPC API Reference

```protobuf
service TappService {
    // Public RPCs
    rpc GetEvidence(GetEvidenceRequest) returns (GetEvidenceResponse);
    rpc GetAppKey(GetAppKeyRequest) returns (GetAppKeyResponse);
    rpc GetAppInfo(GetAppInfoRequest) returns (GetAppInfoResponse);
    rpc GetTaskStatus(GetTaskStatusRequest) returns (GetTaskStatusResponse);
    rpc GetServiceStatus(GetServiceStatusRequest) returns (GetServiceStatusResponse);
    rpc GetAppSecretKey(GetAppSecretKeyRequest) returns (GetAppSecretKeyResponse);
    rpc GetTappInfo(GetTappInfoRequest) returns (GetTappInfoResponse);

    // Owner-only RPCs
    rpc StartApp(StartAppRequest) returns (StartAppResponse);
    rpc StopApp(StopAppRequest) returns (StopAppResponse);
    rpc AddToWhitelist(AddToWhitelistRequest) returns (AddToWhitelistResponse);
    rpc RemoveFromWhitelist(RemoveFromWhitelistRequest) returns (RemoveFromWhitelistResponse);
    rpc ListWhitelist(ListWhitelistRequest) returns (ListWhitelistResponse);
    rpc ListAllOwnerships(ListAllOwnershipsRequest) returns (ListAllOwnershipsResponse);
    rpc StopService(StopServiceRequest) returns (StopServiceResponse);
    rpc StartService(StartServiceRequest) returns (StartServiceResponse);

    // Whitelist RPCs
    rpc GetServiceLogs(GetServiceLogsRequest) returns (GetServiceLogsResponse);
    rpc GetAppLogs(GetAppLogsRequest) returns (GetAppLogsResponse);
    rpc GetAppOwnership(GetAppOwnershipRequest) returns (GetAppOwnershipResponse);
    rpc WithdrawBalance(WithdrawBalanceRequest) returns (WithdrawBalanceResponse);
    rpc DockerLogin(DockerLoginRequest) returns (DockerLoginResponse);
    rpc DockerLogout(DockerLogoutRequest) returns (DockerLogoutResponse);
    rpc PruneImages(PruneImagesRequest) returns (PruneImagesResponse);
}
```

### C. Configuration Mapping

| Current Config (TOML) | Purpose | AWS Change Required |
|-----------------------|---------|-------------------|
| `listen_addr = "0.0.0.0:50051"` | gRPC bind address | Change to `vsock://5:50051` for enclave mode |
| `app_data_dir = "/var/lib/tapp/apps"` | App artifacts path | Path on parent instance, accessed via vsock bridge |
| `log_dir = "/var/log/tapp"` | Log output directory | Inside enclave for enclave logs; parent for app logs |
| `tee_type = "tdx"` | TEE provider selection | Add `"nitro"` and `"simulation"` options |
| `docker_compose_cmd = "docker compose"` | Docker command | Forwarded via vsock bridge in enclave mode |
| (new) `vsock_cid = 5` | Enclave CID | New config for Nitro mode |
| (new) `bridge_port = 50052` | Docker bridge port | New config for vsock Docker bridge |
| (new) `state_persistence = "none"` | State backend | Options: `"none"`, `"ebs"`, `"dynamodb"` |
| (new) `aws_region = "us-east-1"` | AWS region | For DynamoDB/KMS if used |

### D. Measurement Operation Map

| Operation | Current (TDX) | Target (Nitro) | Register |
|-----------|--------------|----------------|----------|
| `start_app` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `stop_app` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `get_app_secret_key` | RTMR extend (register 3) | Accumulator extend (register 3) | 3 |
| `whitelist_add` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `whitelist_remove` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `docker_login` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `docker_logout` | RTMR extend (register 2) | Accumulator extend (register 2) | 2 |
| `withdraw_balance` | RTMR extend (register 3) | Accumulator extend (register 3) | 3 |

### E. Nitro Enclave Lifecycle Commands

```bash
# Build EIF from Docker image
nitro-cli build-enclave \
    --docker-uri tapp:aws \
    --output-file tapp.eif

# Run enclave
nitro-cli run-enclave \
    --eif-path tapp.eif \
    --cpu-count 2 \
    --memory 4096 \
    --enclave-cid 5

# Check enclave status
nitro-cli describe-enclaves

# View enclave console (debug mode only)
nitro-cli console --enclave-id <id>

# Terminate enclave
nitro-cli terminate-enclave --enclave-id <id>

# Start vsock proxy on parent instance
vsock-proxy 50051 5 50051 &
```

### F. Open Questions for 0G Foundation

1. **Attestation document format**: Will the 0G verifier ecosystem accept Nitro attestation documents with runtime measurements in `user_data`, or is a format change needed in the verification protocol?
2. **KBS (Key Broker Service) integration**: Does the existing KBS support Nitro attestation, or does it need a Nitro verification path?
3. **Upstream merge strategy**: Should the Nitro provider be contributed back to the main TAPP repo, or maintained as a Bond fork?
4. **Multi-TEE attestation registry**: Should there be a registry that maps enclave identity (PCR values / RTMR values) to operator identity across both TEE types?
5. **Minimum supported Nitro instance types**: Any constraints on enclave memory/CPU allocation?

---

*Document prepared for 0G Foundation and Bond Engineering Leadership review. For questions, contact the Bond Infrastructure team.*
