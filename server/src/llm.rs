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

    // Gate 3: Relevance check
    let relevance_score = if matches!(stage, ValidationStage::Defender) {
        const DEFENSE_TERMS: &[&str] = &[
            "safe", "false positive", "check", "guard", "assert",
            "protect", "prevent", "restrict", "valid", "role", "require",
            "not vulnerable", "secure", "impossible", "cannot"
        ];
        DEFENSE_TERMS.iter().filter(|term| lower.contains(*term)).count()
    } else {
        const SECURITY_TERMS: &[&str] = &[
            "vulnerab", "attack", "exploit", "danger", "risk", "unauthor",
            "overwrite", "caller", "permission", "access", "guard", "check",
            "fix", "mitigat", "prevent", "assert", "valid", "safe", "unsafe",
            "malicious", "inject", "overflow", "panic", "revert", "reentr",
            "state", "mutation", "mapping", "contract", "function",
        ];
        SECURITY_TERMS.iter().filter(|term| lower.contains(*term)).count()
    };

    let min_relevance = match stage {
        ValidationStage::Attacker => 2,
        ValidationStage::Defender => 1,
        ValidationStage::Final => 2,
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum ValidationStage {
    Attacker,
    Defender,
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

// ─── Reasoning Extraction (Model-Agnostic) ──────────────────────────

/// Extract and separate reasoning blocks from the model response.
/// Supports multiple formats:
/// - Qwen3: <think>...</think>
/// - DeepSeek: <reasoning>...</reasoning>
/// - Generic: content between markers is stripped, clean answer returned
///
/// This is model-agnostic: if no thinking tags are found, the full
/// response is returned unchanged. Works with gemma4, hermes, qwen3, etc.
fn extract_reasoning(raw: &str) -> (Option<String>, String) {
    let mut reasoning = None;
    let mut clean = raw.to_string();

    // Try <think>...</think> (Qwen3)
    if let Some(start) = clean.find("<think>") {
        if let Some(end) = clean.find("</think>") {
            let think_content = clean[start + 7..end].trim().to_string();
            if !think_content.is_empty() {
                reasoning = Some(think_content);
            }
            clean = format!("{}{}", &clean[..start], &clean[end + 8..]).trim().to_string();
        }
    }

    // Try <reasoning>...</reasoning> (DeepSeek)
    if reasoning.is_none() {
        if let Some(start) = clean.find("<reasoning>") {
            if let Some(end) = clean.find("</reasoning>") {
                let think_content = clean[start + 11..end].trim().to_string();
                if !think_content.is_empty() {
                    reasoning = Some(think_content);
                }
                clean = format!("{}{}", &clean[..start], &clean[end + 12..]).trim().to_string();
            }
        }
    }

    // If after extraction the clean text is empty, use reasoning as response
    if clean.is_empty() {
        if let Some(ref r) = reasoning {
            clean = r.clone();
        }
    }

    (reasoning, clean)
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
                let raw = body.response.trim().to_string();
                if raw.is_empty() {
                    return None;
                }
                // Post-process: extract reasoning, return clean answer
                let (reasoning, clean) = extract_reasoning(&raw);
                if let Some(ref thought) = reasoning {
                    println!("🧠 LLM: Model used chain-of-thought ({} chars reasoning)", thought.len());
                }
                Some(clean)
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

/// Generate AI explanation for a security finding using a Crucible Swarm (Attacker vs Defender -> Judge)
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

    // Phase 1: Parallel adversarial reconnaissance
    let prompt_attacker = format!(
        "You are an Attacker (Red Team). Your goal is to exploit this smart contract.\n\nThink like a hacker. Identify how to bypass protections and write a detailed Attack Chain.\n\nFinding: {}\nDescription: {}\nCode:\n{}",
        finding_title, finding_description, source_snippet
    );
    let prompt_defender = format!(
        "You are a Defender (Blue Team). Your goal is to prove this contract is SAFE and the finding is a False Positive.\n\nAnalyze the code for protective measures (e.g. asserts, role checks, data flow constraints) that prevent the attack.\n\nFinding: {}\nDescription: {}\nCode:\n{}",
        finding_title, finding_description, source_snippet
    );

    // Launch both agents in parallel
    let (attacker_result, defender_result) = tokio::join!(
        call_ollama_validated(&client, &model, &prompt_attacker, ValidationStage::Attacker),
        call_ollama_validated(&client, &model, &prompt_defender, ValidationStage::Defender),
    );

    let resp_attacker = match attacker_result {
        Some(r) => {
            println!("✅ LLM: Attacker Agent passed validation.");
            r
        }
        None => {
            println!("⚠️ LLM: Attacker Agent failed validation, using fallback.");
            "Attack failed to generate.".to_string()
        }
    };

    let resp_defender = match defender_result {
        Some(r) => {
            println!("✅ LLM: Defender Agent passed validation.");
            r
        }
        None => {
            println!("⚠️ LLM: Defender Agent failed validation.");
            "No valid defense found.".to_string()
        }
    };

    // Agent 3: Judge (Arbiter)
    let exploit_matches = crate::exploits::search_exploits(source_snippet);
    let exploit_ctx = crate::exploits::format_exploit_context(&exploit_matches);
    if !exploit_matches.is_empty() {
        println!("🗃️ Exploit DB: {} known patterns matched", exploit_matches.len());
    }

    let prompt_judge = format!(
        r#"You are the Judge Arbiter. Review the arguments from the Attacker and the Defender, then deliver a final verdict.

Attacker (Red Team): {resp1}
Defender (Blue Team): {resp2}
Threat: {title} ({severity})
Code:
```
{code}
```
{exploits}
Think step by step. If the Defender's arguments are stronger and the code is safe, respond with EXACTLY: "FALSE POSITIVE" and explain why in one sentence.
If the Attacker's exploit is valid, respond in EXACTLY this format:
Why dangerous: (1 sentence)
Attack scenario: (1 sentence)
Fix: (1-2 sentences)"#,
        resp1 = resp_attacker,
        resp2 = resp_defender,
        title = finding_title,
        severity = severity,
        code = source_snippet,
        exploits = exploit_ctx
    );

    match call_ollama_validated(&client, &model, &prompt_judge, ValidationStage::Final).await {
        Some(verdict) => {
            println!("✅ LLM: Judge Agent passed validation.");
            Some(verdict)
        }
        None => {
            println!("⚠️ LLM: Judge Agent failed validation, using Great Sage fallback.");
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
    fn test_validate_attacker_is_lenient() {
        let vague = "This function modifies state without any visible access control mechanism.";
        let result = validate_response(vague, ValidationStage::Attacker);
        assert!(result.is_some(), "Attacker stage should be lenient");
    }

    #[test]
    fn test_validate_defender() {
        let defense = "This is a false positive because there is a require check protecting the function.";
        let result = validate_response(defense, ValidationStage::Defender);
        assert!(result.is_some(), "Defender stage should accept defense terms");
    }

    #[test]
    fn test_validate_truncates_long_response() {
        let long = "A ".repeat(2000);
        let result = validate_response(&long, ValidationStage::Attacker);
        // Should be truncated or rejected, not panic
        assert!(result.is_none() || result.unwrap().len() <= MAX_RESPONSE_LEN + 10);
    }

    #[test]
    fn test_crucible_conflict_handling() {
        // Test edge cases where responses are borderline or conflicting
        let weak_attack = "This might be bad if the stars align, but I don't know.";
        let result_attack = validate_response(weak_attack, ValidationStage::Attacker);
        assert!(result_attack.is_none(), "Weak attack lacking security terms should be rejected");

        let strong_defense = "This is a false positive. The contract is safe because it has a require guard.";
        let result_defense = validate_response(strong_defense, ValidationStage::Defender);
        assert!(result_defense.is_some(), "Strong defense should be accepted by Defender");

        let conflicted_judge = "As an AI language model, I cannot decide. It might be dangerous or safe.";
        let result_judge = validate_response(conflicted_judge, ValidationStage::Final);
        assert!(result_judge.is_none(), "Judge hallucination or lack of structure should be rejected");
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

    #[test]
    fn test_extract_reasoning_qwen3_think() {
        let input = "<think>Let me analyze this code for vulnerabilities...</think>Why dangerous: The function lacks access control.";
        let (reasoning, clean) = extract_reasoning(input);
        assert!(reasoning.is_some(), "Should extract Qwen3 think block");
        assert!(reasoning.unwrap().contains("analyze this code"));
        assert!(clean.contains("Why dangerous"));
        assert!(!clean.contains("<think>"), "Clean output must not contain think tags");
    }

    #[test]
    fn test_extract_reasoning_deepseek() {
        let input = "<reasoning>Checking access patterns...</reasoning>This is vulnerable because the state can be mutated.";
        let (reasoning, clean) = extract_reasoning(input);
        assert!(reasoning.is_some(), "Should extract DeepSeek reasoning block");
        assert!(!clean.contains("<reasoning>"));
    }

    #[test]
    fn test_extract_reasoning_passthrough() {
        let input = "Why dangerous: Unauthorized access.\nAttack scenario: Direct call.\nFix: Add guard.";
        let (reasoning, clean) = extract_reasoning(input);
        assert!(reasoning.is_none(), "No reasoning tags = no extraction");
        assert_eq!(clean, input, "Clean output should be identical to input");
    }

    #[test]
    fn test_extract_reasoning_only_think_block() {
        let input = "<think>The vulnerability is real because there are no access checks on set_balance.</think>";
        let (reasoning, clean) = extract_reasoning(input);
        assert!(reasoning.is_some());
        assert!(!clean.is_empty(), "If only think block, use it as response");
    }
}
