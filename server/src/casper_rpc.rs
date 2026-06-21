use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Casper RPC integration for recording audit results on-chain.
/// In production, this calls the Casper JSON-RPC API to invoke
/// the AuditRegistry contract's `record_audit` entry point.

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

/// Record an audit result on-chain by calling the AuditRegistry contract.
/// For the hackathon MVP, this generates a deterministic mock deploy hash
/// and returns it. In production, it would:
/// 1. Build a Deploy with session args (audit_id, contract_hash, risk_score, etc.)
/// 2. Sign it with the server's secret key
/// 3. Submit via `account_put_deploy` RPC
/// 4. Return the real deploy hash
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

    // Generate deterministic deploy hash from audit data
    let deploy_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(audit_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..32])
    };

    // In production: call Casper RPC here
    // let rpc_url = std::env::var("CASPER_RPC_URL")
    //     .unwrap_or_else(|_| "https://rpc.testnet.casperlabs.io/rpc".to_string());
    // let registry_hash = std::env::var("AUDIT_REGISTRY_HASH").expect("AUDIT_REGISTRY_HASH required");
    // ... build deploy, sign, submit ...

    println!(
        "📝 On-chain record: audit={}, risk={}, findings={}, deploy={}",
        audit_id, risk_score, total_findings, &deploy_hash[..16]
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
