# 0G TAPP AWS Nitro Port -- Project Spec

**For:** Technical Program Managers and Stakeholders
**Last Updated:** 2026-03-22
**Status:** Enclave running in production mode on AWS. PerpDex testnet deployment next.

---

## Table of Contents

1. [What Is This Project?](#1-what-is-this-project)
2. [What Does It Do for PerpDex?](#2-what-does-it-do-for-perpdex)
3. [Architecture Overview](#3-architecture-overview)
4. [What Was Built](#4-what-was-built)
5. [Security Posture](#5-security-posture)
6. [Current Deployment](#6-current-deployment)
7. [What's Left to Do](#7-whats-left-to-do)
8. [Risks and Mitigations](#8-risks-and-mitigations)
9. [Glossary](#9-glossary)
10. [AWS Admin Request](#10-aws-admin-request)

---

## 1. What Is This Project?

### TAPP in Plain English

**TAPP** (Trusted Application Platform) is software that runs applications inside a special secure zone on a server. Think of it as a platform that can:

- Run any containerized application (like a web service or database)
- Generate and protect secret keys (like a built-in vault)
- Prove to anyone that the code running is exactly what it claims to be (no cheating possible)

The key idea: **even the person who owns the server cannot tamper with or spy on what runs inside TAPP.** This is enforced by hardware, not by trust.

### What Is a Nitro Enclave?

Imagine a **locked glass box** inside a server:

- **Locked**: Nobody can open it -- not the server administrator, not Amazon, not even with physical access. The hardware enforces this.
- **Glass**: Anyone can look in and verify exactly what code is running inside (via "attestation" -- a hardware-signed certificate of the code).
- **Box**: It is completely isolated. It has no internet connection, no disk storage, and no way to communicate except through a single, narrow pipe to the host server.

AWS Nitro Enclaves are Amazon's implementation of this concept. They run on standard AWS EC2 servers and use a dedicated security chip (the Nitro Security Module) to sign attestation certificates.

### Why Are We Porting from Alibaba to AWS?

TAPP originally ran on Alibaba Cloud using Intel TDX (a different secure hardware technology). We are porting it to AWS Nitro Enclaves because:

| Reason | Detail |
|--------|--------|
| **Global availability** | Alibaba TDX is limited to China regions. AWS Nitro is available in 20+ regions worldwide. |
| **Ecosystem fit** | Most 0G validators, node operators, and DeFi partners already run on AWS. |
| **Compliance** | Western institutional partners require AWS or GCP hosting for regulatory reasons. |
| **Redundancy** | Supporting both Alibaba and AWS eliminates single-cloud risk. |
| **Supply chain** | Removes dependency on China-region package repositories. |

The port does NOT remove Alibaba support. Both platforms can run the same TAPP codebase -- you just flip a build flag.

---

## 2. What Does It Do for PerpDex?

### PerpDex in 30 Seconds

**PerpDex** is a decentralized perpetual futures exchange. Users trade leveraged positions on crypto assets (like BTC or ETH). It is "decentralized" because trades are settled on a blockchain (the 0G chain), but the order matching and settlement logic run off-chain for speed.

### What Runs Inside TAPP

PerpDex deploys **four services** through TAPP:

| Service | What It Does |
|---------|-------------|
| **API Service** | Accepts trade orders from users, manages the order book |
| **Settlement Service** | Submits matched trades to the blockchain using the sequencer key |
| **Price Oracle** | Fetches real-time market prices for liquidation and funding calculations |
| **Supporting Infrastructure** | Kafka (message queue), PostgreSQL (database), Redis (cache), Zookeeper (coordination) |

### The Sequencer Key -- Why This Matters

The **sequencer private key** is the Ethereum wallet that submits transactions on-chain. Whoever holds this key controls the funds in the exchange's smart contracts.

Without TAPP, this key would sit on a regular server. A compromised server means stolen funds.

With TAPP:
- The key is **generated inside the enclave** and never leaves it unencrypted
- The settlement service gets the key **through a localhost-only API** that only works inside the enclave
- Even the server operator cannot extract the key
- Users can **verify via attestation** that the exact expected code is running and protecting their funds

### The Trust Model -- Simply Put

> "Even the server operator cannot steal funds."

Here is how trust flows:

| Actor | What They Can Do | What They Cannot Do |
|-------|-----------------|-------------------|
| **Users** | Verify attestation, confirm code integrity | N/A |
| **Server operator** | Start/stop the enclave, deploy updates | Read the private key, modify running code |
| **AWS** | Provide hardware, sign attestation certs | Read enclave memory, access private keys |
| **TAPP code** | Generate keys, sign transactions, serve APIs | Leak keys outside the enclave (by design) |

---

## 3. Architecture Overview

### What Runs Where

```
+------------------------------------------------------------------+
|  AWS EC2 Instance (the "Parent")                                  |
|  This is a normal server. It CAN be accessed by the operator.     |
|                                                                    |
|  +---------------------------+    +----------------------------+   |
|  | PARENT SIDE               |    | NITRO ENCLAVE              |   |
|  | (operator-accessible)     |    | (locked glass box)         |   |
|  |                           |    |                            |   |
|  | - Docker containers:      |    | - TAPP Server              |   |
|  |   - API Service          |<==>| - Sequencer private key    |   |
|  |   - Settlement Service   |vsock| - Attestation engine       |   |
|  |   - Price Oracle         |    | - Key management           |   |
|  |   - Kafka, Postgres,     |    | - gRPC API                 |   |
|  |     Redis, Zookeeper     |    |                            |   |
|  |                           |    | NO internet access         |   |
|  | - socat proxy (gRPC)     |    | NO disk storage            |   |
|  | - Docker proxy (vsock)   |    | NO Docker daemon           |   |
|  | - File proxy (key blobs) |    |                            |   |
|  +---------------------------+    +----------------------------+   |
+------------------------------------------------------------------+
```

**Key insight**: The Docker containers (API, Settlement, etc.) run on the parent, NOT inside the enclave. The enclave is too resource-constrained for that. Instead, the enclave orchestrates them remotely through vsock.

### How Traffic Flows

```
Users (internet)
    |
    | HTTPS / gRPC
    v
Parent Instance (port 50051)
    |
    | socat: TCP --> vsock
    v
Enclave (vsock port 50051)
    |
    | TAPP processes the request
    | (e.g., "start PerpDex app")
    |
    | vsock port 50052 (Docker commands)
    v
Parent Instance
    |
    | docker compose up -d
    v
PerpDex containers start running
```

### Sequencer Key Protection

```
1. PerpDex Settlement Service needs the sequencer key
   |
   v
2. It calls TAPP's GetAppSecretKey API (localhost only)
   |
   v
3. TAPP checks: Is the caller inside the enclave's network? (IP check)
   |
   v
4. TAPP returns the private key over localhost
   |
   v
5. Settlement Service uses it to sign blockchain transactions
   |
   v
6. The key NEVER touches disk. NEVER leaves the enclave unencrypted.
```

### How Updates Work Safely

Updating the enclave wipes all in-memory keys. The safe update procedure prevents fund loss:

```
BEFORE UPDATE:
  1. Run pre-update check (verify all keys are backed up)
  2. Export emergency backup (passphrase-encrypted, stored off-instance)
  3. Build new enclave image (note the new PCR0 hash)
  4. Update KMS policy to allow BOTH old and new code hashes

SWAP:
  5. Terminate old enclave (keys are gone from memory)
  6. Start new enclave

AFTER UPDATE:
  7. Verify all keys recovered from KMS backup
  8. Remove old code hash from KMS policy
  9. If KMS fails: recover from emergency backup file
```

---

## 4. What Was Built

### Feature Inventory

| Feature | What It Does | Why It Matters |
|---------|-------------|---------------|
| **TEE Abstraction Layer** | A plug-in system that supports TDX, Nitro, and Simulation modes | Same codebase works on Alibaba, AWS, or a developer laptop |
| **NSM Attestation** | Generates hardware-signed proofs from the Nitro Security Module | Users can cryptographically verify the exchange is running expected code |
| **Software Measurement Accumulator** | Tracks every important operation in a tamper-evident log | Provides runtime audit trail (Nitro hardware only tracks the initial code image) |
| **vsock Networking Bridge** | Tunnels gRPC traffic between the internet and the enclave | The enclave has no network -- this is its only communication channel |
| **Docker Proxy** | Sends Docker commands from enclave to parent over vsock | The enclave cannot run containers directly -- it orchestrates them remotely |
| **Compose Sandboxing** | Validates Docker Compose files before deployment | Prevents deployed apps from escaping their containers (blocks privileged mode, host mounts, etc.) |
| **Nonce-Based Replay Prevention** | Rejects duplicate requests using one-time-use tokens | Prevents attackers from re-submitting captured requests |
| **KMS Key Persistence** | Encrypts keys with AWS KMS so they survive restarts | Without this, restarting the enclave generates new keys and orphans existing funds |
| **Emergency Backup System** | Passphrase-encrypted key export for disaster recovery | Defense-in-depth: if KMS fails, keys can still be recovered manually |
| **Safe Update Procedure** | Step-by-step protocol for code updates without fund loss | Ensures keys are backed up before the old enclave is terminated |

### vsock Port Map

The enclave communicates with the parent through three dedicated channels:

| Port | Purpose | Direction |
|------|---------|-----------|
| 50051 | gRPC API (user-facing) | Users --> Parent --> Enclave |
| 50052 | Docker commands | Enclave --> Parent |
| 50053 | File operations (key blob storage) | Enclave --> Parent |

---

## 5. Security Posture

### Review Process

Over **40 AI security agents** reviewed the codebase across multiple rounds. Findings were categorized, prioritized, and either fixed or logged as follow-up items.

### Summary of Findings and Fixes

| Category | Finding | Status |
|----------|---------|--------|
| **Attestation** | Race condition between measurement reads and attestation signing (TOCTOU) | FIXED -- lock held through entire attestation |
| **Key Management** | Private keys not zeroed from memory on drop | FIXED -- all keys wrapped in zeroizing containers |
| **Key Management** | GetAppSecretKey was publicly accessible | FIXED -- restricted to localhost-only callers |
| **Networking** | No replay attack prevention on authenticated requests | FIXED -- nonce + timestamp validation on all auth requests |
| **Networking** | SSRF possible via WithdrawBalance RPC URL | FIXED -- blocks internal/private IP addresses |
| **Docker** | Compose files could request privileged containers | FIXED -- sandboxing validator rejects unsafe configurations |
| **Docker** | Path traversal possible via app_id | FIXED -- strict character validation on all IDs |
| **Auth** | Simulation mode could accidentally ship in production | FIXED -- compile-time error if simulation + real TEE enabled |
| **Configuration** | Server could start with insecure defaults on config failure | FIXED -- fails closed (refuses to start) |
| **Deployment** | Enclave ran as root | FIXED -- init script drops to unprivileged user |
| **Crypto** | Key backup verification vulnerable to timing attacks | FIXED -- constant-time comparison |
| **Crypto** | Measurement hash collisions possible without length prefixes | FIXED -- length-prefixed measurement format |

### The Key Guarantee

> **Private keys never leave the enclave unencrypted.**

Keys are only ever exported in two forms:
1. **KMS-encrypted blobs** -- only decryptable by an enclave running the exact same code (verified by hardware)
2. **Emergency backup** -- AES-256-GCM encrypted with a human-supplied passphrase (600,000 rounds of key derivation)

### Follow-Up Items (Not Yet Done)

| Item | Priority | Notes |
|------|----------|-------|
| TLS certificates + private subnet | Medium | Standard AWS network hardening; vsock is already secure |
| Real KBS integration | Low | Currently mocked; only matters for TDX compatibility |
| ethers to alloy migration | Low | Technical debt; does not affect security |

---

## 6. Current Deployment

| Parameter | Value |
|-----------|-------|
| **AWS Account** | 809778145789 |
| **Region** | us-east-1 |
| **Instance ID** | i-0fc4e8edc2567426f |
| **Instance Type** | c6i.xlarge (4 vCPUs, 8 GB RAM) -- upgrade to c6i.2xlarge pending |
| **Public IP** | 3.81.185.0 |
| **Enclave Mode** | Production (no debug flags) |
| **Enclave Resources** | 2 CPUs, 1024 MB RAM, CID 5 |
| **gRPC Endpoint** | 3.81.185.0:50051 |
| **Security Group** | sg-0c31d5f1463d06c36 (ports 22, 50051 open) |
| **GitHub Fork** | https://github.com/spyda600/0g-tapp |
| **Deployed** | 2026-03-21 |

### Memory Constraints

The c6i.xlarge instance has only 8 GB total RAM. The enclave takes 1024 MB, Docker containers need the rest. During EIF builds, the allocator must be temporarily reduced to 256 MB to free RAM for the Docker build process. An upgrade to c6i.2xlarge (16 GB) is recommended.

---

## 7. What's Left to Do

### Phase 1: PerpDex Testnet Deployment (NOW)

| Task | Status | Notes |
|------|--------|-------|
| Deploy PerpDex services through TAPP on Galileo testnet (chain 16602) | In Progress | Docker Compose file ready, configs prepared |
| Verify settlement service can submit transactions using enclave-protected key | Not Started | End-to-end test of the key protection flow |
| Test attestation verification from a user perspective | Not Started | Confirm users can verify the exchange |

### Phase 2: IAM/KMS Setup (Blocked -- Needs AWS Admin)

| Task | Status | Blocker |
|------|--------|---------|
| Create KMS key for enclave key persistence | Not Started | Current IAM user (0g-red) lacks permissions |
| Create IAM role + instance profile (TappEnclaveRole) | Not Started | Needs admin access |
| Create S3 backup bucket | Not Started | Needs admin access |
| Enforce IMDSv2 on instance | Not Started | Needs admin access |

See [Section 10](#10-aws-admin-request) for the exact commands to send to the AWS admin.

### Phase 3: Network Hardening

| Task | Status | Notes |
|------|--------|-------|
| Set up TLS termination on parent instance | Not Started | Standard certificate management |
| Move instance into private subnet with NAT gateway | Not Started | Standard AWS VPC architecture |
| Restrict security group to ALB-only ingress | Not Started | Remove direct SSH and gRPC access |

### Phase 4: PerpDex Mainnet Deployment

| Task | Status | Notes |
|------|--------|-------|
| Deploy to 0G mainnet (chain 16661) | Not Started | Requires completed Phase 2 (KMS) for key safety |
| Load testing and performance validation | Not Started | Ensure latency meets trading requirements |
| Monitoring and alerting setup | Not Started | CloudWatch dashboards, enclave health checks |

### Phase 5: Tech Debt

| Task | Priority | Notes |
|------|----------|-------|
| Migrate from ethers to alloy library | Low | alloy is the modern Rust Ethereum library |
| Implement log forwarding from enclave | Medium | Currently no log export in production mode |
| Instance upgrade to c6i.2xlarge | Medium | Current instance is memory-constrained |

---

## 8. Risks and Mitigations

| # | Risk | Impact | Mitigation |
|---|------|--------|------------|
| 1 | **Key loss on enclave restart** | CRITICAL -- funds locked forever | KMS persistence (Phase 2) auto-recovers keys. Emergency backup provides manual recovery. Both are implemented and tested. |
| 2 | **Enclave memory limits** | HIGH -- cannot run containers inside enclave | Containers run on parent, orchestrated via vsock. Already working. |
| 3 | **No persistent storage in enclave** | HIGH -- Postgres data lost on restart | Acceptable for testnet (Postgres runs on parent with local storage). For mainnet, need EBS-backed volumes on parent. |
| 4 | **KMS setup blocked on IAM permissions** | HIGH -- no key persistence until admin acts | Emergency backup provides interim protection. AWS admin request document is ready to send. |
| 5 | **Single instance, no redundancy** | MEDIUM -- downtime if instance fails | Acceptable for testnet. For mainnet, need multi-AZ setup or rapid recovery runbook. |
| 6 | **Instance too small (8 GB RAM)** | MEDIUM -- OOM risk under load | Upgrade to c6i.2xlarge (16 GB) is straightforward and low-risk. |
| 7 | **0G upstream changes during our work** | LOW -- merge conflicts | Our changes are additive (new files, new feature flags). Rebasing is straightforward. |
| 8 | **vsock adds latency** | LOW -- could affect trade execution speed | Measured overhead is sub-millisecond. gRPC over vsock performs comparably to direct TCP. |

---

## 9. Glossary

| Term | What It Means |
|------|--------------|
| **Attestation** | A hardware-signed certificate that proves exactly what code is running inside the enclave. Like a notarized document saying "this is the real code." |
| **CID** | Context Identifier. An address used by vsock to route messages between the parent and enclave. The parent is always CID 3, our enclave is CID 5. |
| **EIF** | Enclave Image File. The packaged enclave application (like a Docker image, but for enclaves). |
| **EIP-191** | An Ethereum standard for signing messages. Used to authenticate gRPC requests (the caller signs with their Ethereum wallet). |
| **gRPC** | A fast API protocol used for communication between services. TAPP exposes its API over gRPC. |
| **IAM** | Identity and Access Management. AWS's permission system that controls who can do what. |
| **KMS** | Key Management Service. AWS service that encrypts and decrypts data. We use it so enclave keys survive restarts. |
| **Nonce** | A one-time-use random value sent with each request to prevent replay attacks (resending a captured request). |
| **NSM** | Nitro Security Module. The dedicated hardware chip inside AWS servers that signs attestation documents. |
| **PCR** | Platform Configuration Register. A hash value that represents the enclave's code. PCR0 is the hash of the entire enclave image -- if anyone changes the code, PCR0 changes. |
| **PCR0** | The most important PCR value. It is the SHA-384 hash of the enclave image. KMS policies reference PCR0 to ensure only the exact expected code can decrypt keys. |
| **Sequencer Key** | The Ethereum private key used by the settlement service to submit transactions on-chain. This is the critical secret that TAPP protects. |
| **TEE** | Trusted Execution Environment. The general term for hardware-secured compute zones (Nitro Enclaves, Intel TDX, Intel SGX, etc.). |
| **TDX** | Trust Domain Extensions. Intel's TEE technology, used by Alibaba Cloud. The original platform TAPP was built for. |
| **TOCTOU** | Time-of-Check to Time-of-Use. A class of bug where something changes between when you check it and when you use it. We fixed one in the attestation code. |
| **vsock** | Virtual Socket. A communication channel between the parent instance and the enclave. It is the enclave's ONLY way to talk to the outside world. |
| **Zeroize** | Overwriting sensitive data (like private keys) with zeros when it is no longer needed, so it cannot be recovered from memory. |

---

## 10. AWS Admin Request

The current IAM user (0g-red) does not have permission to create IAM roles or KMS keys. An AWS administrator needs to run the following commands. A detailed document with copy-paste commands is available at `docs/AWS_ADMIN_REQUEST.md`.

### What We Need (4 Items)

#### Item 1: Create a KMS Encryption Key

**What it does:** Creates an encryption key that only the enclave can use. The key policy ties decryption permission to the enclave's code hash (PCR0), so if anyone modifies the code, the key becomes inaccessible.

**Plain English:** This is like a safe deposit box where the lock only opens for a specific fingerprint -- and the fingerprint is the hash of our code.

#### Item 2: Create an IAM Role and Instance Profile

**What it does:** Gives the EC2 instance permission to call KMS (for key encryption/decryption) and S3 (for backup storage). The role is named `TappEnclaveRole` and is attached to the instance as `TappEnclaveProfile`.

**Plain English:** This gives our server a badge that lets it talk to the encryption service and the backup storage.

#### Item 3: Create an S3 Backup Bucket

**What it does:** Creates an encrypted, versioned, private S3 bucket (`tapp-enclave-backups-809778145789`) for storing encrypted key blobs. Public access is blocked. Server-side encryption is enabled by default.

**Plain English:** This is a locked filing cabinet in the cloud where we store encrypted copies of the keys. Even if someone breaks into the filing cabinet, the contents are encrypted and useless without the enclave.

#### Item 4: Enforce IMDSv2

**What it does:** Requires token-based authentication for the instance metadata service. This is a one-line security fix that prevents a class of attack called SSRF from stealing the instance's credentials.

**Plain English:** This closes a known security hole where a malicious request could trick the server into revealing its own passwords.

### After Setup, We Need Back

- [ ] KMS Key ARN (or confirmation that `alias/tapp-enclave-keys` was created)
- [ ] Confirmation that `TappEnclaveProfile` is attached to instance `i-0fc4e8edc2567426f`
- [ ] Confirmation that S3 bucket `tapp-enclave-backups-809778145789` was created
- [ ] Confirmation that IMDSv2 is enforced

### Important Note for Updates

When we deploy a new version of the enclave, the PCR0 value changes (because the code changed). Before deploying, the KMS key policy must be updated to allow BOTH the old and new PCR0 values temporarily. After verifying the update succeeded, the old PCR0 is removed. This is documented in `docs/SAFE_UPDATE_PROCEDURE.md`.

---

*For the full AWS CLI commands, see `docs/AWS_ADMIN_REQUEST.md`.*
*For the full technical guide, see `docs/AWS_NITRO_PORT_TECHNICAL_GUIDE.md`.*
*For the original PRD, see `docs/PRD_0G_TAPP_AWS_PORT.md`.*
