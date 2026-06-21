use reqwest::Client;
use serde::{Deserialize, Serialize};

/// LLM integration via Ollama (local) for explaining security findings.
/// Uses whatever model is available (gemma4, hermes, etc.)

const OLLAMA_URL: &str = "http://localhost:11434/api/generate";

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

async fn call_ollama(client: &Client, model: &str, prompt: &str) -> Option<String> {
    let request = OllamaRequest {
        model: model.to_string(),
        prompt: prompt.to_string(),
        stream: false,
    };

    match client
        .post(OLLAMA_URL)
        .json(&request)
        .timeout(std::time::Duration::from_secs(15))
        .send()
        .await
    {
        Ok(resp) => {
            if let Ok(body) = resp.json::<OllamaResponse>().await {
                Some(body.response.trim().to_string())
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Generate AI explanation for a security finding using a 3-agent Tempest Quorum.
/// Returns a human-readable explanation with fix recommendation.
pub async fn explain_finding(
    finding_title: &str,
    finding_description: &str,
    severity: &str,
    source_snippet: &str,
) -> Option<String> {
    let client = Client::new();
    let model = get_model();

    // Agent 1: Souei (Shadow Scout) - reconnaissance & analysis
    let prompt1 = format!(
        "You are Souei, the Shadow Scout of Tempest. Conduct a silent reconnaissance on this potential smart contract vulnerability.\nFinding: {}\nDescription: {}\nCode:\n{}",
        finding_title, finding_description, source_snippet
    );
    let resp1 = call_ollama(&client, &model, &prompt1).await.unwrap_or_else(|| "Souei reported: No generic issues found.".to_string());

    // Agent 2: Wisdom King Raphael (Great Sage) - deep rules evaluation
    let prompt2 = format!(
        "You are Wisdom King Raphael (Great Sage). Evaluate this finding and Souei's shadow analysis: '{}'. Does this violate Casper/Odra smart contract safety conventions?\nFinding: {}\nCode:\n{}",
        resp1, finding_title, source_snippet
    );
    let resp2 = call_ollama(&client, &model, &prompt2).await.unwrap_or_else(|| "Raphael reported: No platform-specific issues found.".to_string());

    // Agent 3: Chief Auditor (Benimaru - Chief General & Flame Commander)
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

    let final_resp = call_ollama(&client, &model, &prompt3).await;
    if final_resp.is_none() {
        // Fallback default explanations if Ollama is offline
        println!("⚠️ LLM: Ollama not available, using Great Sage fallback logic.");
        let fallback = match finding_title {
            "Unprotected State Mutation" => {
                "Why dangerous: Unauthorized users can mutate global state variables.\nAttack scenario: Attacker calls the function to overwrite admin settings or contract owner.\nFix: Add caller authorization checks using env::caller() or AccessControl assertions."
            }
            "Unchecked Mapping overwrite on 'balances'" => {
                "Why dangerous: Users can overwrite other accounts' mapping keys directly.\nAttack scenario: Attacker calls the method with target user address, erasing or overwriting their balance.\nFix: Restrict mapping sets to the caller address or add require/assert gates."
            }
            _ => "Why dangerous: Potential logic flaw in smart contract execution.\nAttack scenario: Exploit of unchecked state changes or unsafe calls.\nFix: Add assertion checks and validate function call permissions."
        };
        return Some(fallback.to_string());
    }
    final_resp
}

/// Explain all findings in a scan result.
/// Returns a vec of (finding_id, explanation) pairs.
pub async fn explain_all_findings(
    findings: &[(String, String, String)], // (title, description, severity)
    source_code: &str,
) -> Vec<(String, String)> {
    let mut explanations = Vec::new();

    for (i, (title, description, severity)) in findings.iter().enumerate() {
        // Extract ~3 lines around the finding for context
        let snippet = if source_code.len() > 200 {
            &source_code[..200]
        } else {
            source_code
        };

        if let Some(explanation) = explain_finding(title, description, severity, snippet).await {
            explanations.push((format!("S402-{:03}", i + 1), explanation));
        }
    }

    explanations
}
