use crate::engine;
use crate::report;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Run the server in stdio MCP mode
pub async fn run_stdio_mcp() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_mcp_loop(stdin.lock(), stdout.lock()).await;
}

/// Generic MCP loop for standard or test stream I/O
pub async fn run_mcp_loop<R: BufRead, W: Write>(reader: R, mut writer: W) {
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(_) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32700, "message": "Parse error" },
                    "id": null
                });
                let _ = writeln!(writer, "{}", err_resp.to_string());
                let _ = writer.flush();
                continue;
            }
        };

        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = request.get("id").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "sentinel402-mcp",
                            "version": "0.1.0"
                        }
                    }
                });
                let _ = writeln!(writer, "{}", response.to_string());
            }
            "tools/list" => {
                let response = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "sentinel402_audit",
                                "description": "Scan a Casper/Odra smart contract source code for security vulnerabilities",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "source_code": {
                                            "type": "string",
                                            "description": "Rust source code of the Casper/Odra smart contract"
                                        },
                                        "contract_hash": {
                                            "type": "string",
                                            "description": "Optional contract hash identifier"
                                        }
                                    },
                                    "required": ["source_code"]
                                }
                            }
                        ]
                    }
                });
                let _ = writeln!(writer, "{}", response.to_string());
            }
            "tools/call" => {
                let params = request.get("params");
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("");
                let arguments = params.and_then(|p| p.get("arguments"));

                if name == "sentinel402_audit" {
                    if let Some(args) = arguments {
                        let source_code = args
                            .get("source_code")
                            .and_then(|s| s.as_str())
                            .unwrap_or("");
                        let contract_hash = args
                            .get("contract_hash")
                            .and_then(|c| c.as_str())
                            .unwrap_or("unknown-mcp");

                        let findings = engine::analyze(source_code);
                        let summary = report::summarize(&findings);
                        let audit_id = report::generate_audit_id(contract_hash, &findings);

                        let mut result_text = format!(
                            "Sentinel402 Audit Report\nAudit ID: {}\nStatus: {}\nTotal Findings: {}\n\n",
                            audit_id, summary.risk_score, summary.total_findings
                        );

                        for finding in &findings {
                            result_text.push_str(&format!(
                                "- [{}] Line {}: {} - {}\n",
                                finding.severity, finding.line, finding.title, finding.description
                            ));
                        }

                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": result_text
                                    }
                                ]
                            }
                        });
                        let _ = writeln!(writer, "{}", response.to_string());
                    } else {
                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32602, "message": "Invalid params" }
                        });
                        let _ = writeln!(writer, "{}", response.to_string());
                    }
                } else {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "Method not found" }
                    });
                    let _ = writeln!(writer, "{}", response.to_string());
                }
            }
            _ => {
                if id != Value::Null {
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "Method not found" }
                    });
                    let _ = writeln!(writer, "{}", response.to_string());
                }
            }
        }
        let _ = writer.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_mcp_initialize() {
        let input = "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":1}\n";
        let reader = Cursor::new(input.as_bytes());
        let mut writer = Vec::new();

        run_mcp_loop(reader, &mut writer).await;

        let output_str = String::from_utf8(writer).unwrap();
        let response: Value = serde_json::from_str(&output_str).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["serverInfo"]["name"], "sentinel402-mcp");
    }

    #[tokio::test]
    async fn test_mcp_tools_list() {
        let input = "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":2}\n";
        let reader = Cursor::new(input.as_bytes());
        let mut writer = Vec::new();

        run_mcp_loop(reader, &mut writer).await;

        let output_str = String::from_utf8(writer).unwrap();
        let response: Value = serde_json::from_str(&output_str).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 2);
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools[0]["name"], "sentinel402_audit");
    }

    #[tokio::test]
    async fn test_mcp_tools_call_audit() {
        let code = "pub fn set_owner(&mut self) { self.owner.set(x); }";
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "sentinel402_audit",
                "arguments": {
                    "source_code": code,
                    "contract_hash": "test-hash-123"
                }
            },
            "id": 3
        });
        let input = format!("{}\n", request.to_string());
        let reader = Cursor::new(input.as_bytes());
        let mut writer = Vec::new();

        run_mcp_loop(reader, &mut writer).await;

        let output_str = String::from_utf8(writer).unwrap();
        let response: Value = serde_json::from_str(&output_str).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 3);
        let content = response["result"]["content"].as_array().unwrap();
        let text = content[0]["text"].as_str().unwrap();
        assert!(text.contains("Sentinel402 Audit Report"));
        assert!(text.contains("Unprotected State Mutation"));
    }
}
