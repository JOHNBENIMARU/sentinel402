use casper_types::{
    bytesrepr::ToBytes,
    crypto::SecretKey,
    Deploy, DeployHash, DeployHeader, ExecutableDeployItem,
    Digest, PublicKey, RuntimeArgs, TimeDiff, Timestamp, U512,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// On-chain record returned to the frontend.
#[derive(Serialize, Deserialize, Clone)]
pub struct OnChainRecord {
    pub deploy_hash: String,
    pub audit_id: String,
    pub contract_hash: String,
    pub risk_score: String,
    pub total_findings: u32,
    pub timestamp: u64,
    pub explorer_url: String,
    pub simulated: bool,
}

/// RPC configuration
fn get_rpc_url() -> String {
    std::env::var("CASPER_RPC_URL")
        .unwrap_or_else(|_| "http://65.109.89.88:7777/rpc".to_string())
}

fn get_chain_name() -> String {
    std::env::var("CASPER_CHAIN_NAME").unwrap_or_else(|_| "casper-test".to_string())
}

fn get_contract_hash() -> String {
    std::env::var("AUDIT_REGISTRY_HASH").unwrap_or_else(|_| {
        "hash-bae5400f5c800ca983a2cee8abf05d1645ee00f8998952d5ae3f16712754f0f6".to_string()
    })
}

fn get_key_path() -> String {
    std::env::var("CASPER_SECRET_KEY")
        .unwrap_or_else(|_| "contracts/audit-registry/keys/secret_key.pem".to_string())
}

// ─── Deploy Construction (Pure Rust) ────────────────────────────────

/// Load Ed25519 secret key from PEM file.
fn load_secret_key(path: &str) -> Result<SecretKey, String> {
    let pem_content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read key file {}: {}", path, e))?;

    // Extract raw key bytes from PEM
    let key_b64: String = pem_content
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();

    let der_bytes = base64_decode(&key_b64)
        .map_err(|e| format!("Failed to decode base64 key: {}", e))?;

    // Ed25519 private key is the last 32 bytes of DER-encoded key,
    // or the first 32 bytes if raw seed format
    let key_bytes = if der_bytes.len() >= 48 {
        // PKCS#8 DER: skip ASN.1 header, seed is at offset 16 for 48-byte keys
        &der_bytes[der_bytes.len() - 32..]
    } else if der_bytes.len() == 32 {
        &der_bytes[..]
    } else {
        return Err(format!("Unexpected key length: {} bytes", der_bytes.len()));
    };

    SecretKey::ed25519_from_bytes(key_bytes)
        .map_err(|e| format!("Failed to construct Ed25519 key: {:?}", e))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decoder (no external dependency needed)
    let clean: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in clean.bytes() {
        if c == b'=' { break; }
        let val = alphabet.iter().position(|&x| x == c)
            .ok_or_else(|| format!("Invalid base64 char: {}", c as char))? as u32;
        acc = (acc << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(buf)
}

/// Build a signed Deploy that calls `record_audit` on the AuditRegistry contract.
fn build_audit_deploy(
    secret_key: &SecretKey,
    contract_hash_hex: &str,
    audit_id: &str,
    risk_score: &str,
    total_findings: u32,
) -> Result<Deploy, String> {
    let public_key = PublicKey::from(secret_key);
    let chain_name = get_chain_name();
    let timestamp = Timestamp::now();
    let ttl = TimeDiff::from_seconds(1800); // 30 min

    // Payment: standard payment of 3 CSPR (3_000_000_000 motes)
    let payment_args = {
        let mut args = RuntimeArgs::new();
        args.insert("amount", U512::from(3_000_000_000u64))
            .map_err(|e| format!("Failed to insert payment amount: {:?}", e))?;
        args
    };
    let payment = ExecutableDeployItem::ModuleBytes {
        module_bytes: casper_types::bytesrepr::Bytes::new(),
        args: payment_args,
    };

    // Session: call record_audit on AuditRegistry
    // Parse contract hash (strip "hash-" prefix if present)
    let clean_hash = contract_hash_hex
        .strip_prefix("hash-")
        .unwrap_or(contract_hash_hex);
    let contract_hash_bytes: [u8; 32] = hex::decode(clean_hash)
        .map_err(|e| format!("Invalid contract hash hex: {}", e))?
        .try_into()
        .map_err(|_| "Contract hash must be 32 bytes".to_string())?;
    let contract_hash = casper_types::AddressableEntityHash::new(contract_hash_bytes);

    let session_args = {
        let mut args = RuntimeArgs::new();
        args.insert("audit_id", audit_id.to_string())
            .map_err(|e| format!("Failed to insert audit_id: {:?}", e))?;
        args.insert("risk_score", risk_score.to_string())
            .map_err(|e| format!("Failed to insert risk_score: {:?}", e))?;
        args.insert("total_findings", total_findings)
            .map_err(|e| format!("Failed to insert total_findings: {:?}", e))?;
        args
    };

    let session = ExecutableDeployItem::StoredContractByHash {
        hash: contract_hash.into(),
        entry_point: "record_audit".to_string(),
        args: session_args,
    };

    // Serialize body and compute body_hash
    let serialized_body = {
        let mut buf = Vec::new();
        payment
            .write_bytes(&mut buf)
            .map_err(|e| format!("Failed to serialize payment: {:?}", e))?;
        session
            .write_bytes(&mut buf)
            .map_err(|e| format!("Failed to serialize session: {:?}", e))?;
        buf
    };
    let body_hash = Digest::hash(serialized_body);

    // Build header
    let header = DeployHeader::new(
        public_key,
        timestamp,
        ttl,
        1, // gas_price tolerance
        body_hash,
        vec![], // no dependencies (Casper 2.0 doesn't support them)
        chain_name,
    );

    // Compute deploy hash from serialized header
    let serialized_header = header
        .to_bytes()
        .map_err(|e| format!("Failed to serialize header: {:?}", e))?;
    let deploy_hash = DeployHash::new(Digest::hash(serialized_header));

    // Build & sign
    let mut deploy = Deploy::new(deploy_hash, header, payment, session);
    deploy.sign(secret_key);

    Ok(deploy)
}

// ─── JSON-RPC Submission ────────────────────────────────────────────

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

/// Submit a signed Deploy to Casper Testnet via JSON-RPC.
async fn submit_deploy(deploy: &Deploy) -> Result<String, String> {
    let rpc_url = get_rpc_url();
    let client = Client::new();

    let deploy_json = serde_json::to_value(deploy)
        .map_err(|e| format!("Failed to serialize deploy: {}", e))?;

    let rpc_req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "account_put_deploy".to_string(),
        params: serde_json::json!({ "deploy": deploy_json }),
        id: 1,
    };

    let resp = client
        .post(&rpc_url)
        .json(&rpc_req)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let body = resp
        .json::<RpcResponse>()
        .await
        .map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    if let Some(error) = body.error {
        return Err(format!("RPC error: {}", error));
    }

    if let Some(result) = body.result {
        let hash = result
            .get("deploy_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}", result));
        return Ok(hash);
    }

    Err("Empty RPC response".to_string())
}

// ─── Public API ─────────────────────────────────────────────────────

/// Record an audit result on-chain by constructing, signing, and submitting
/// a Deploy to the AuditRegistry contract on Casper Testnet.
///
/// Falls back to simulated mode if:
/// - Secret key file is missing
/// - RPC node is unreachable
/// - Deploy submission fails
pub async fn record_audit_on_chain(
    audit_id: &str,
    contract_hash: &str,
    risk_score: &str,
    total_findings: u32,
) -> Result<OnChainRecord, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let key_path = get_key_path();
    let registry_hash = get_contract_hash();

    // Try real on-chain submission
    if Path::new(&key_path).exists() {
        match try_real_deploy(&key_path, &registry_hash, audit_id, risk_score, total_findings).await
        {
            Ok(deploy_hash) => {
                println!(
                    "🔥 ON-CHAIN: Real deploy submitted! Hash: {}",
                    deploy_hash
                );
                return Ok(OnChainRecord {
                    deploy_hash: deploy_hash.clone(),
                    audit_id: audit_id.to_string(),
                    contract_hash: contract_hash.to_string(),
                    risk_score: risk_score.to_string(),
                    total_findings,
                    timestamp,
                    explorer_url: format!("https://testnet.cspr.live/deploy/{}", deploy_hash),
                    simulated: false,
                });
            }
            Err(e) => {
                println!("⚠️ ON-CHAIN: Real deploy failed ({}), falling back to simulation.", e);
            }
        }
    } else {
        println!(
            "⚠️ ON-CHAIN: Secret key not found at '{}', using simulation.",
            key_path
        );
    }

    // Fallback: simulated deploy hash
    let deploy_hash = {
        use sha2::{Digest as Sha2Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(audit_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..32])
    };

    println!(
        "📝 SIMULATED on-chain record: audit={}, risk={}, findings={}, deploy={}",
        audit_id,
        risk_score,
        total_findings,
        &deploy_hash[..16]
    );

    Ok(OnChainRecord {
        deploy_hash: deploy_hash.clone(),
        audit_id: audit_id.to_string(),
        contract_hash: contract_hash.to_string(),
        risk_score: risk_score.to_string(),
        total_findings,
        timestamp,
        explorer_url: format!("https://testnet.cspr.live/deploy/{}", deploy_hash),
        simulated: true,
    })
}

async fn try_real_deploy(
    key_path: &str,
    registry_hash: &str,
    audit_id: &str,
    risk_score: &str,
    total_findings: u32,
) -> Result<String, String> {
    let secret_key = load_secret_key(key_path)?;
    let deploy = build_audit_deploy(&secret_key, registry_hash, audit_id, risk_score, total_findings)?;

    // Validate deploy integrity before submission
    deploy
        .has_valid_hash()
        .map_err(|e| format!("Deploy hash validation failed: {:?}", e))?;

    let deploy_hash_hex = hex::encode(deploy.hash().inner());
    println!(
        "🔑 Deploy constructed & signed. Hash: {}, submitting to {}...",
        &deploy_hash_hex[..16],
        get_rpc_url()
    );

    submit_deploy(&deploy).await
}
