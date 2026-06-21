use reqwest::Client;
use serde::{Deserialize, Serialize};

/// LLM integration via Ollama (local) for explaining security findings.
/// Includes response validation to filter out hallucinations and garbage.

const OLLAMA_URL: &str = "http://localhost:11434/api/generate";
const MAX_RESPONSE_LEN: usize = 2000;
const MIN_RESPONSE_LEN: usize = 30;

fn get_model() -> String {
    std::env::var("LLM_MODEL").unwrap_or_else(|_| "gemma4".to_string())
}

#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    response: String,
}

// ─── Validation Layer ───────────────────────────────────────────────

/// Quality gate for LLM responses. Returns None if the response is garbage.
fn validate_response(response: &str, stage: ValidationStage) -> Option<String> {
    let trimmed = response.trim();

    // Gate 1: Length bounds
    if trimmed.len() < MIN_RESPONSE_LEN {
        println!("⚠️ LLM Validator: Response too short ({} chars), rejecting.", trimmed.len());
        return None;
    }
    if trimmed.len() > MAX_RESPONSE_LEN {
        // Truncate, don't reject — model was verbose but potentially useful
        let truncated = safe_truncate(trimmed, MAX_RESPONSE_LEN);
        println!("⚠️ LLM Validator: Response truncated from {} to {} chars.", trimmed.len(), MAX_RESPONSE_LEN);
        return validate_content(&truncated, stage);
    }

    validate_content(trimmed, stage)
}

fn validate_content(text: &str, stage: ValidationStage) -> Option<String> {
    let lower = text.to_lowercase();

    // Gate 2: Hallucination detection — reject responses that are clearly off-topic
    const HALLUCINATION_MARKERS: &[&str] = &[
        "as an ai language model",
        "i cannot help",
        "i'm sorry, but",
        "i don't have access",
        "let me know if you",
        "sure! here's",
        "certainly! let me",
        "happy to help",
    ];
    for marker in HALLUCINATION_MARKERS {
        if lower.contains(marker) {
            println!("⚠️ LLM Validator: Hallucination marker detected: '{}'", marker);
            return None;
        }
    }

    // Gate 3: Relevance check — must contain security-related terms
    const SECURITY_TERMS: &[&str] = &[
        "vulnerab", "attack", "exploit", "danger", "risk", "unauthor",
        "overwrite", "caller", "permission", "access", "guard", "check",
        "fix", "mitigat", "prevent", "assert", "valid", "safe", "unsafe",
        "malicious", "inject", "overflow", "panic", "revert", "reentr",
        "state", "mutation", "mapping", "contract", "function",
    ];
    let relevance_score: usize = SECURITY_TERMS
        .iter()
        .filter(|term| lower.contains(*term))
        .count();

    let min_relevance = match stage {
        ValidationStage::Scout => 1,      // Souei can be exploratory
        ValidationStage::Evaluator => 2,  // Raphael must be more focused
        ValidationStage::Final => 3,      // Benimaru's verdict must be precise
    };

    if relevance_score < min_relevance {
        println!(
            "⚠️ LLM Validator: Low relevance score ({}/{} terms) for {:?} stage, rejecting.",
            relevance_score, min_relevance, stage
        );
        return None;
    }

    // Gate 4: Final stage must contain structured output markers
    if matches!(stage, ValidationStage::Final) {
        let has_structure = lower.contains("dangerous")
            || lower.contains("attack")
            || lower.contains("fix")
            || lower.contains("false positive")
            || lower.contains("scenario");

        if !has_structure {
            println!("⚠️ LLM Validator: Final verdict lacks required structure (Why/Attack/Fix).");
            return None;
        }
    }

    Some(text.to_string())
}

#[derive(Debug, Clone, Copy)]
enum ValidationStage {
    Scout,
    Evaluator,
    Final,
}

fn safe_truncate(s: &str, max_bytes: usize) -> String {
    if max_bytes >= s.len() {
        return s.to_string();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}…", &s[..boundary])
}

// ─── Fallback Logic (Great Sage) ────────────────────────────────────

fn get_fallback(finding_title: &str) -> String {
    match finding_title {
        t if t.contains("Unprotected State Mutation") => {
            "Why dangerous: Unauthorized users can mutate global state variables.\nAttack scenario: Attacker calls the function to overwrite admin settings or contract owner.\nFix: Add caller authorization checks using env::caller() or AccessControl assertions.".to_string()
        }
        t if t.contains("Unchecked Mapping overwrite") => {
            "Why dangerous: Users can overwrite other accounts' mapping keys directly.\nAttack scenario: Attacker calls the method with target user address, erasing or overwriting their balance.\nFix: Restrict mapping sets to the caller address or add require/assert gates.".to_string()
        }
        t if t.contains("Unsafe purse transfer") => {
            "Why dangerous: Failed CSPR transfers silently continue execution with incorrect balances.\nAttack scenario: Attacker triggers a transfer that fails but the contract proceeds as if it succeeded.\nFix: Always handle TransferResult with .unwrap_or_revert() or match expression.".to_string()
        }
        t if t.contains("reentrancy") => {
            "Why dangerous: External call before state update allows recursive re-entry into the contract.\nAttack scenario: Malicious contract re-enters during callback to drain funds or corrupt state.\nFix: Apply Checks-Effects-Interactions (CEI) pattern — update state before making external calls.".to_string()
        }
        t if t.contains("unwrap()") => {
            "Why dangerous: unwrap() causes an immediate panic (trap) if the value is None or Err.\nAttack scenario: Attacker provides malformed input that triggers None, crashing the entire contract.\nFix: Use unwrap_or_revert_with(ApiError) or match/if-let for graceful error handling.".to_string()
        }
        t if t.contains("overflow") => {
            "Why dangerous: Arithmetic overflow on U256 can wrap around silently, producing incorrect values.\nAttack scenario: Attacker supplies extreme values to cause overflow in token balances or prices.\nFix: Use checked_add() / checked_mul() and revert on overflow.".to_string()
        }
        t if t.contains("Hardcoded storage key") => {
            "Why dangerous: Hardcoded key names prevent safe contract upgrades and create naming collisions.\nAttack scenario: Upgraded contract accidentally overwrites critical state by reusing the same key.\nFix: Use constants or configurable key names derived from contract version or namespace.".to_string()
        }
        t if t.contains("CEP-18") => {
            "Why dangerous: Missing approve() breaks composability — other contracts cannot spend tokens on behalf of users.\nAttack scenario: DEX or marketplace integration fails because allowance mechanism is absent.\nFix: Implement the full CEP-18 interface including approve(), transfer_from(), and allowance().".to_string()
        }
        _ => {
            "Why dangerous: Potential logic flaw in smart contract execution.\nAttack scenario: Exploit of unchecked state changes or unsafe calls.\nFix: Add assertion checks and validate function call permissions.".to_string()
        }
    }
}

// ─── Core LLM Call ──────────────────────────────────────────────────

async fn call_ollama(client: &Client, model: &str, prompt: &str) -> Option<String> {
    let request = OllamaRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
    };

    match client
        .post(OLLAMA_URL)
        .json(&request)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(body) = resp.json::<OllamaResponse>().await {
                let text = body.response.trim().to_string();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            } else {
                None
            }
        }
        Err(e) => {
            println!("⚠️ LLM: Ollama request failed: {}", e);
            None
        }
    }
}

/// Validated call: sends prompt to Ollama and validates the response.
/// Returns None if Ollama is down OR if the response fails validation.
async fn call_ollama_validated(
    client: &Client,
    model: &str,
    prompt: &str,
    stage: ValidationStage,
) -> Option<String> {
    let raw = call_ollama(client, model, prompt).await?;
    validate_response(&raw, stage)
}

// ─── Public API ─────────────────────────────────────────────────────

/// Generate AI explanation for a security finding using a 3-agent Tempest Quorum
/// with validation at each stage. Falls back to Great Sage if any stage fails.
pub async fn explain_finding(
    finding_title: &str,
    finding_description: &str,
    severity: &str,
    source_snippet: &str,
) -> Option<String> {
    let client = Client::new();
    let model = get_model();
    let fallback = get_fallback(finding_title);

    // Agent 1: Souei (Shadow Scout) — reconnaissance & analysis
    let prompt1 = format!(
        "You are Souei, the Shadow Scout of Tempest. Conduct a silent reconnaissance on this potential smart contract vulnerability.\nFinding: {}\nDescription: {}\nCode:\n{}",
        finding_title, finding_description, source_snippet
    );
    let resp1 = match call_ollama_validated(&client, &model, &prompt1, ValidationStage::Scout).await
    {
        Some(r) => {
            println!("✅ LLM: Souei (Scout) passed validation.");
            r
        }
        None => {
            println!("⚠️ LLM: Souei (Scout) failed validation, using Great Sage fallback.");
            return Some(fallback);
        }
    };

    // Agent 2: Wisdom King Raphael (Great Sage) — deep rules evaluation
    let prompt2 = format!(
        "You are Wisdom King Raphael (Great Sage). Evaluate this finding and Souei's shadow analysis: '{}'. Does this violate Casper/Odra smart contract safety conventions?\nFinding: {}\nCode:\n{}",
        resp1, finding_title, source_snippet
    );
    let resp2 =
        match call_ollama_validated(&client, &model, &prompt2, ValidationStage::Evaluator).await {
            Some(r) => {
                println!("✅ LLM: Raphael (Evaluator) passed validation.");
                r
            }
            None => {
                println!(
                    "⚠️ LLM: Raphael (Evaluator) failed validation, using Great Sage fallback."
                );
                return Some(fallback);
            }
        };

    // Agent 3: Chief Auditor (Benimaru — Flame Commander)
    let prompt3 = format!(
        r#"You are Benimaru, the Flame Commander and Chief General of Tempest. Review:
1. Souei's scouting analysis: {resp1}
2. Wisdom King Raphael's rule evaluation: {resp2}
3. Original Threat level: {title} ({severity})
4. Code Context:
```
{code}
```

Issue the final combat tactical verdict. Explain:
- Why this is dangerous (1 sentence)
- Attack scenario (1 sentence)
- How to fix it (1-2 sentences)
If the previous agents concluded it is a false positive, write "FALSE POSITIVE" and explain why. Be extremely technical, concise, and direct."#,
        resp1 = resp1,
        resp2 = resp2,
        title = finding_title,
        severity = severity,
        code = source_snippet
    );

    match call_ollama_validated(&client, &model, &prompt3, ValidationStage::Final).await {
        Some(verdict) => {
            println!("✅ LLM: Benimaru (Final Verdict) passed validation.");
            Some(verdict)
        }
        None => {
            println!("⚠️ LLM: Benimaru (Final Verdict) failed validation, using Great Sage fallback.");
            Some(fallback)
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rejects_too_short() {
        assert!(validate_response("ok", ValidationStage::Final).is_none());
    }

    #[test]
    fn test_validate_rejects_hallucination() {
        let garbage = "As an AI language model, I cannot help with security audits but here's a poem about cats.";
        assert!(validate_response(garbage, ValidationStage::Final).is_none());
    }

    #[test]
    fn test_validate_rejects_irrelevant() {
        let off_topic = "The weather today in Tokyo is sunny with occasional clouds and temperatures reaching 28 degrees celsius which is quite pleasant for this time of year.";
        assert!(validate_response(off_topic, ValidationStage::Final).is_none());
    }

    #[test]
    fn test_validate_accepts_good_response() {
        let good = "Why dangerous: Unauthorized users can exploit the unprotected function to overwrite contract state.\nAttack scenario: Attacker calls update_balance() with arbitrary address to drain funds.\nFix: Add access control check using self.env().caller() assertion.";
        let result = validate_response(good, ValidationStage::Final);
        assert!(result.is_some(), "Should accept well-structured security response");
    }

    #[test]
    fn test_validate_scout_is_lenient() {
        let vague = "This function modifies state without any visible access control mechanism.";
        let result = validate_response(vague, ValidationStage::Scout);
        assert!(result.is_some(), "Scout stage should be lenient");
    }

    #[test]
    fn test_validate_truncates_long_response() {
        let long = "A ".repeat(2000);
        let result = validate_response(&long, ValidationStage::Scout);
        // Should be truncated or rejected, not panic
        assert!(result.is_none() || result.unwrap().len() <= MAX_RESPONSE_LEN + 10);
    }

    #[test]
    fn test_fallback_covers_all_detectors() {
        let cases = vec![
            "Unprotected State Mutation",
            "Unchecked Mapping overwrite on 'balances'",
            "Unsafe purse transfer",
            "Potential reentrancy via runtime::call_contract",
            "Unchecked unwrap() may panic",
            "Potential arithmetic overflow on U256",
            "Hardcoded storage key",
            "CEP-18 Non-compliance: Missing approve",
            "Some Unknown Future Detector",
        ];
        for title in cases {
            let fb = get_fallback(title);
            assert!(fb.contains("Why dangerous"), "Fallback for '{}' must contain 'Why dangerous'", title);
            assert!(fb.contains("Attack scenario"), "Fallback for '{}' must contain 'Attack scenario'", title);
            assert!(fb.contains("Fix:"), "Fallback for '{}' must contain 'Fix:'", title);
        }
    }
}
