# 🔥 Sentinel402

> **Autonomous AI Security Agent with Cryptographic x402 Micropayments on Casper Network**

**Sentinel402** is a production-ready, AI-powered smart contract security scanner and auditor built for **Casper & Odra** contracts. It addresses the lack of fast, cost-effective, and automated audits in the Casper ecosystem. By integrating the **x402 protocol** (HTTP 402 Payment Required), it allows machine-to-machine micropayments, enabling developers and autonomous AI agents to purchase smart contract audits on-demand, paying strictly per scan.

Sentinel402 was developed for the **Casper Agentic Buildathon 2026** on [DoraHacks](https://dorahacks.io/hackathon/casper-agentic-buildathon).

---

## 🚀 Key Features

*   **⚡ Automated Static Analysis:** 8 specialized security detectors targeting Casper-specific and generic Rust smart contract vulnerabilities (Missing authorizations, Mapping overwrites, Unsafe purse transfers, Reentrancy, Arithmetic overflows).
*   **🧠 Local AI-Powered Explanations:** Incorporates a local, privacy-preserving LLM (Ollama with `gemma4` or fallback) to dissect and explain security findings directly in the dashboard, avoiding expensive API key requirements.
*   **💳 Cryptographic x402 Micropayments:** Fully functional HTTP 402 protocol flow. The client requests a scan, gets a payment challenge, and pays via signature/deploy.
*   **🦊 Casper Wallet Integration:** Built-in support for the Casper Wallet browser extension. Users can connect their wallets, sign the scan challenge cryptographically, and submit the signature for real-time backend verification.
*   **🛡️ On-Chain Proof (Odra Contract):** Audit metadata (audit ID, contract hash, risk score, findings count, and timestamp) is permanently recorded on-chain in the Casper Testnet using our custom `AuditRegistry` Odra contract.
*   **🖥️ Premium Glassmorphic UI:** A state-of-the-art dark-themed front-end dashboard built with vanilla HTML/JS/CSS, leveraging smooth micro-animations, real-time status tracking, and offline history persistence.

---

## ⚙️ Architecture

```
                 +--------------------------------------------+
                 |              Frontend Dashboard            |
                 +----------------------+---------------------+
                                        | (1) POST /api/scan (No Payment)
                                        v
                 +----------------------+---------------------+
                 |           Sentinel402 API Server           |
                 |               (Rust + Axum)                |
                 +----------------------+---------------------+
                                        | (2) HTTP 402 Payment Required
                                        v
                 +----------------------+---------------------+
                 |             Casper Wallet Sign             |
                 |            (scan:<contract_hash>)          |
                 +----------------------+---------------------+
                                        | (3) POST /api/scan (With Signature & PubKey)
                                        v
                 +----------------------+---------------------+
                 |        Backend Cryptographic Verify         |
                 +----------------------+---------------------+
                                        | (4) Run Static Audit & Local LLM Explanation
                                        v
                 +----------------------+---------------------+
                 |        AuditRegistry Smart Contract        |
                 |                (Casper WASM)               |
                 +----------------------+---------------------+
                                        | (5) Emit Deploy Hash
                                        v
                 +----------------------+---------------------+
                 |          Frontend Dashboard Render         |
                 +--------------------------------------------+
```

---

## 🛡️ Casper/Odra Security Detectors

Sentinel402's Rust analysis engine scans smart contracts using the following rule-based detectors:

| ID | Detector | Severity | Target Vulnerability |
|:---|:---|:---:|:---|
| **S402-001** | **Unprotected State Mutation** | **HIGH** | Public entrypoint modifies state variables without check guards (`only_owner`, `assert_role`). |
| **S402-002** | **Unchecked Mapping Overwrite** | **CRITICAL** | A direct write to a contract `Mapping` via `.set()` without validation, enabling key-overwrite exploits. |
| **S402-003** | **Unsafe Purse Transfer** | **HIGH** | Calling `transfer_from_purse_to_account` without checking the `TransferResult` or unwrapping. |
| **S402-004** | **Reentrancy via Contract Call** | **HIGH** | Triggering an external contract call via `call_contract` before updating local storage keys (CEI violation). |
| **S402-005** | **Unchecked Unwrap** | **MEDIUM** | Using raw `.unwrap()` inside contract code, causing the contract execution to panic and lock up. |
| **S402-006** | **Arithmetic Overflow** | **MEDIUM** | Standard mathematical operators (`+`, `*`) on `U256` without `checked_add` or `checked_mul`. |
| **S402-007** | **CEP-18 Compliance** | **LOW** | Missing critical CEP-18 token standard methods (e.g., implementing `transfer` but missing `approve`). |
| **S402-008** | **Hardcoded Storage Key** | **LOW** | Using hardcoded strings inside `runtime::put_key`, which reduces contract upgradability. |

---

## 🛠️ Project Structure

```
sentinel402/
├── contracts/                     # Casper Smart Contracts (Odra 2.8)
│   └── audit-registry/
│       ├── src/lib.rs             # AuditRegistry Contract (owner-gated)
│       ├── bin/build_contract.rs  # WASM Build Entrypoint
│       ├── wasm/
│       │   └── AuditRegistry.wasm # Compiled Casper WASM Target
│       ├── Odra.toml              # Odra configuration
│       └── deploy.ps1             # Casper Testnet Deployment Script
├── server/                        # API Server (Rust + Axum)
│   └── src/
│       ├── main.rs                # Routes & API Entrypoint
│       ├── engine.rs              # Static Analysis Engine (8 Detectors)
│       ├── llm.rs                 # Local Ollama LLM Connection Interface
│       ├── report.rs              # Report Aggregator & Audit SHA-256 ID Generator
│       ├── x402.rs                # x402 Micropayment & Cryptographic Verify Logic
│       └── casper_rpc.rs          # Casper RPC client & Simulated Sandbox proof
├── frontend/                      # Web Dashboard UI
│   ├── index.html                 # Main interface structure
│   ├── app.js                     # Casper Wallet connection, Signatures, and UI renders
│   └── style.css                  # Premium Glassmorphic Stylesheet
├── package.json                   # JS helper dependencies
├── deploy.js                      # Casper JS SDK Deploy Helper script
└── README.md
```

---

## ⚡ Quick Start & Run Instructions

### 1. Build and Test Smart Contract (Odra)
To compile the smart contract and execute the unit tests, you must have Rust nightly installed. Run inside the contract subdirectory to automatically pick up the nightly toolchain config:

```bash
cd contracts/audit-registry
# Run unit tests (4/4 passing, includes Owner checks, records, panic assertions)
cargo test

# Build WASM binary
cargo odra build
```

### 2. Configure and Run Backend Server (Axum)
Ensure you have [Ollama](https://ollama.com/) running locally for AI-powered explanations:

```bash
# Pull the model (Ollama must be running)
ollama pull gemma4

# Start the Axum server
cd ../../
cargo run -p sentinel402-server
```

The server will spin up at `http://localhost:3402`.

### 3. Open Dashboard
Simply navigate your browser to:
👉 **[http://localhost:3402](http://localhost:3402)**

---

## 💳 Testing the Payment Flow

When running the security scan:
1. Paste contract code into the input area and click **⚡ Scan for Vulnerabilities**.
2. A modal dialog will appear asking for **HTTP 402 Payment Required**.
3. **Casper Wallet (Real Signature):** If you have Casper Wallet installed, connect it, and click **Sign & Pay**. This signs the challenge `scan:<contract_hash>` cryptographically. The backend verifies the signature using `casper_types::crypto::verify` and unlocks the audit report.
4. **Mock Fallback (Simulation):** If Casper Wallet is not detected, click **Simulate Agent Payment**. It runs a mock delay, returns a verified proof, logs a simulated deploy hash on the dashboard, and links to a real live transaction on CSPR.live for demonstrative purposes.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
