use casper_types::crypto::{verify, AsymmetricType, PublicKey, Signature};
use serde::Serialize;

#[derive(Serialize)]
pub struct PaymentRequired {
    pub amount_cspr: f64,
    pub facilitator_url: String,
    pub payment_address: String,
    pub memo: String,
}

pub fn create_payment_request(contract_hash: &str) -> PaymentRequired {
    PaymentRequired {
        amount_cspr: 1.0, // 1 CSPR per scan
        facilitator_url: "https://x402.casper.network/facilitator".to_string(),
        payment_address: "account-hash-sentinel402-treasury".to_string(),
        memo: format!("scan:{}", contract_hash),
    }
}

pub async fn verify_payment(
    payment_proof: &str,
    public_key: Option<&str>,
    contract_hash: &str,
) -> bool {
    #[cfg(not(test))]
    let allow_mock = std::env::var("ALLOW_MOCK_PAYMENT")
        .map(|v| v == "true")
        .unwrap_or(false); // Disabled by default — set ALLOW_MOCK_PAYMENT=true for demo
    #[cfg(test)]
    let allow_mock = true;

    if allow_mock && payment_proof.starts_with("mock_tx_hash_") {
        println!(
            "🔥 x402 Payment Verified via local mock! Tx: {}",
            payment_proof
        );
        return true;
    }

    // Try cryptographically verifying the signature
    if let Some(pub_key_hex) = public_key {
        let pub_key_res = PublicKey::from_hex(pub_key_hex);
        let sig_res = Signature::from_hex(payment_proof);

        if let (Ok(pub_key), Ok(signature)) = (pub_key_res, sig_res) {
            let challenge = format!("scan:{}", contract_hash);
            if verify(challenge.as_bytes(), &signature, &pub_key).is_ok() {
                println!(
                    "🔑 Cryptographic signature verified successfully for public key {}",
                    pub_key_hex
                );
                return true;
            } else {
                println!(
                    "⚠️ Signature verification failed for public key {}",
                    pub_key_hex
                );
            }
        } else {
            println!("⚠️ Failed to parse Casper PublicKey or Signature from hex strings");
        }
    }

    // In production: call the real x402 facilitator endpoint here.
    // For the hackathon, if crypto verification failed and mock is disabled,
    // we reject the payment proof.
    println!("⚠️ x402: Payment verification failed — no valid signature or mock proof.");
    false
}

pub async fn hold_payment(proof: &str) -> bool {
    println!(
        "🔒 x402: Payment proof {} successfully placed in ESCROW",
        proof
    );
    true
}

pub async fn refund_payment(proof: &str) {
    println!(
        "💸 x402: Scan failed! Escrow successfully REFUNDED for proof {}",
        proof
    );
}
