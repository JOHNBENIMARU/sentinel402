use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

mod ast;
mod badge;
mod casper_rpc;
mod engine;
mod exploits;
mod llm;
mod mcp;
mod report;
mod taint;
mod x402;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--mcp" {
        mcp::run_stdio_mcp().await;
        return;
    }

    println!("🔥 Sentinel402 starting...");
    let model = std::env::var("LLM_MODEL").unwrap_or_else(|_| "gemma4".to_string());
    println!("🧠 LLM backend: Ollama ({}) at localhost:11434", model);

    // Create dynamic audits storage directory
    let _ = std::fs::create_dir_all("data/audits");

    let app = Router::new()
        .route("/api/scan", post(scan_contract))
        .route("/api/health", get(health))
        .route("/api/badge/{audit_id}", get(get_badge))
        .route("/api/report/{audit_id}", get(get_report))
        .fallback_service(ServeDir::new("frontend"))
        .layer(CorsLayer::permissive())
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024)); // 512KB for contract source

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3402").await.unwrap();
    println!("🔥 Listening on http://localhost:3402");
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "Sentinel402 🔥 operational"
}

use axum::extract::Path;

async fn get_badge(Path(audit_id): Path<String>) -> impl IntoResponse {
    let sanitized_id = audit_id
        .replace("..", "")
        .replace("/", "")
        .replace("\\", "");
    let path = format!("data/audits/{}.json", sanitized_id);
    let risk_score = if let Ok(content) = tokio::fs::read_to_string(&path).await {
        let val: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
        val.get("summary")
            .and_then(|s| s.get("risk_score"))
            .and_then(|r| r.as_str())
            .unwrap_or("UNKNOWN")
            .to_string()
    } else {
        "UNKNOWN".to_string()
    };

    let svg = badge::generate_badge(&risk_score);
    ([("Content-Type", "image/svg+xml")], svg)
}

async fn get_report(Path(audit_id): Path<String>) -> impl IntoResponse {
    let sanitized_id = audit_id
        .replace("..", "")
        .replace("/", "")
        .replace("\\", "");
    let path = format!("data/audits/{}.json", sanitized_id);
    if let Ok(content) = tokio::fs::read_to_string(&path).await {
        let val: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
        (StatusCode::OK, Json(val)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Report not found"})),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
struct ScanRequest {
    contract_hash: String,
    source_code: Option<String>,
    payment_proof: Option<String>,
    public_key: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    status: String,
    audit_id: String,
    findings: Vec<report::Finding>,
    summary: report::Summary,
    on_chain: Option<casper_rpc::OnChainRecord>,
}

async fn scan_contract(Json(req): Json<ScanRequest>) -> impl IntoResponse {
    // x402 Protocol: check for payment proof
    if req.payment_proof.is_none() {
        let payment_req = x402::create_payment_request(&req.contract_hash);
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::to_value(payment_req).unwrap()),
        )
            .into_response();
    }

    let proof = req.payment_proof.unwrap();
    let pub_key = req.public_key.as_deref();
    if !x402::verify_payment(&proof, pub_key, &req.contract_hash).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid payment proof"})),
        )
            .into_response();
    }

    // Escrow: Hold payment in escrow before processing
    if !x402::hold_payment(&proof).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to hold payment in escrow"})),
        )
            .into_response();
    }

    // Payment verified — run security scan
    let source = req.source_code.unwrap_or_default();

    // Security Guard: Prevent DoS by limiting source code size to 100KB
    if source.len() > 100_000 {
        x402::refund_payment(&proof).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Source code size exceeds limit of 100KB"})),
        )
            .into_response();
    }


    let mut findings = engine::analyze(&source);
    let summary = report::summarize(&findings);
    let audit_id = report::generate_audit_id(&req.contract_hash, &findings);

    // AI Enhancement: use local LLM (Ollama/gemma4) to explain findings
    // Security Guard: Limit to max 5 explanations to prevent API block/DoS
    println!("🧠 Running AI analysis on {} findings...", findings.len());
    let source_lines: Vec<&str> = source.lines().collect();
    let mut explanations_generated = 0;
    for finding in findings.iter_mut() {
        if explanations_generated >= 5 {
            break;
        }
        if finding.severity == report::Severity::Critical
            || finding.severity == report::Severity::High
            || finding.severity == report::Severity::Medium
        {
            // Extract code snippet around the actual finding line (±7 lines)
            let snippet = if finding.line > 0 && finding.line <= source_lines.len() {
                let start = finding.line.saturating_sub(7);
                let end = (finding.line + 7).min(source_lines.len());
                source_lines[start..end].join("\n")
            } else {
                // Fallback: first 300 bytes
                let end = safe_char_boundary(&source, 300);
                source[..end].to_string()
            };
            finding.ai_explanation = llm::explain_finding(
                &finding.title,
                &finding.description,
                &finding.severity.to_string(),
                &snippet,
            )
            .await;
            explanations_generated += 1;
        }
    }

    // Record on-chain via Casper RPC
    let on_chain = casper_rpc::record_audit_on_chain(
        &audit_id,
        &req.contract_hash,
        &summary.risk_score.to_string(),
        summary.total_findings as u32,
    )
    .await
    .ok();

    let response = ScanResponse {
        status: "completed".to_string(),
        audit_id: audit_id.clone(),
        findings,
        summary,
        on_chain,
    };

    // Save report to disk for badges and detail queries
    let report_path = format!("data/audits/{}.json", audit_id);
    if let Ok(json_str) = serde_json::to_string(&response) {
        let _ = tokio::fs::write(&report_path, json_str).await;
    }

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
        .into_response()
}

/// Find the largest valid char boundary at or before `max_bytes`.
fn safe_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    boundary
}
