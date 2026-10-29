//! Model Context Protocol (MCP) Server for AgentMMU (Rust Native).
//!
//! Provides stdio JSON-RPC MCP server interface to plug AgentMMU directly
//! into Google Antigravity, Claude Code, Cursor, and OpenHands.

use crate::AgentMMU;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

pub struct MCPServer {
    mmu: AgentMMU,
}

impl MCPServer {
    pub fn new() -> io::Result<Self> {
        // Resilient fallback: Try local workspace, then ~/.agent_mmu, then in-memory
        let mmu = AgentMMU::new(".", "default_session", "")
            .or_else(|_| {
                if let Ok(home) = std::env::var("HOME") {
                    let home_path = std::path::PathBuf::from(home);
                    AgentMMU::new(&home_path, "default_session", "")
                } else {
                    AgentMMU::new_in_memory("default_session", "")
                }
            })
            .or_else(|_| AgentMMU::new_in_memory("default_session", ""))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(Self { mmu })
    }

    pub fn get_tools(&self) -> Value {
        json!([
            {
                "name": "mmu_get_state",
                "description": "Fetch current deterministic state ledger, active constraints, verified facts, and memory metrics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "mmu_sieve_output",
                "description": "Sieve raw test/compiler logs (PyTest, Cargo, NPM, tracebacks) to reduce tokens by 85%-98% before context entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "stdout": {"type": "string", "description": "Raw stdout from command"},
                        "stderr": {"type": "string", "description": "Raw stderr from command"},
                        "exit_code": {"type": "integer", "description": "Command exit code"},
                        "command": {"type": "string", "description": "Command executed"}
                    },
                    "required": ["stdout"]
                }
            },
            {
                "name": "mmu_page_in_evidence",
                "description": "Search historical virtual swap space (SQLite FTS5) for past errors, flags, or interactions without bloating context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query terms"},
                        "limit": {"type": "integer", "description": "Max results to return (default 3)"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "mmu_record_fact",
                "description": "Empirically record a verified fact into the deterministic working state ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fact": {"type": "string", "description": "Verified fact to store"}
                    },
                    "required": ["fact"]
                }
            },
            {
                "name": "mmu_add_constraint",
                "description": "Register a permanent negative constraint or prohibited anti-pattern to prevent amnesia or circular loops.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule": {"type": "string", "description": "Constraint rule or prohibited pattern"},
                        "is_dead_end": {"type": "boolean", "description": "True if recording a refuted hypothesis/dead-end"}
                    },
                    "required": ["rule"]
                }
            },
            {
                "name": "mmu_audit_trajectory",
                "description": "Forensically audit an agent execution trajectory (JSONL) against Tier-4 SWE benchmark standards (SQS score, Ghost Actions, Masked Errors, Circular Loops).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "trajectory_path": {"type": "string", "description": "Path to trajectory JSONL file"}
                    },
                    "required": ["trajectory_path"]
                }
            },
            {
                "name": "mmu_scan_skill",
                "description": "Scan an AI agent skill (SKILL.md), tool script, or configuration for security vulnerabilities, prompt injection, and credential exfiltration (NVIDIA SkillSpector-aligned).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path": {"type": "string", "description": "Path to skill file or directory"}
                    },
                    "required": ["target_path"]
                }
            }
        ])
    }

    pub fn handle_tool_call(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "mmu_get_state" => {
                let ledger = self.mmu.ledger.to_json().map_err(|e| e.to_string())?;
                let metrics = self.mmu.get_metrics().map_err(|e| e.to_string())?;
                Ok(json!({
                    "ledger": ledger,
                    "metrics": metrics,
                }))
            }
            "mmu_sieve_output" => {
                let stdout = args.get("stdout").and_then(|v| v.as_str()).unwrap_or("");
                let stderr = args.get("stderr").and_then(|v| v.as_str()).unwrap_or("");
                let exit_code = args.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
                let command = args.get("command").and_then(|v| v.as_str()).unwrap_or("");

                let res = self.mmu.process_tool_output(
                    "bash",
                    stdout,
                    stderr,
                    exit_code,
                    command,
                    None,
                    None,
                    None,
                ).map_err(|e| e.to_string())?;

                Ok(json!(res))
            }
            "mmu_page_in_evidence" => {
                let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("");
                let limit = (args.get("limit").and_then(|v| v.as_u64()).unwrap_or(3) as usize).clamp(1, 50);
                let ev = self.mmu.page_in_evidence(query, limit).map_err(|e| e.to_string())?;
                Ok(json!(ev))
            }
            "mmu_record_fact" => {
                let fact = args.get("fact").and_then(|v| v.as_str()).unwrap_or("");
                self.mmu.ledger.add_fact(fact).map_err(|e| e.to_string())?;
                Ok(json!({"status": "SUCCESS", "fact_recorded": fact}))
            }
            "mmu_add_constraint" => {
                let rule = args.get("rule").and_then(|v| v.as_str()).unwrap_or("");
                let is_dead_end = args.get("is_dead_end").and_then(|v| v.as_bool()).unwrap_or(false);
                if is_dead_end {
                    self.mmu.ledger.add_dead_end(rule, "").map_err(|e| e.to_string())?;
                } else {
                    self.mmu.ledger.add_constraint(rule, true).map_err(|e| e.to_string())?;
                }
                Ok(json!({"status": "SUCCESS", "rule_registered": rule}))
            }
            "mmu_audit_trajectory" => {
                let path = args.get("trajectory_path").and_then(|v| v.as_str()).unwrap_or("");
                let auditor = crate::TrajectoryAuditor::new();
                let report = auditor.audit_file(path).map_err(|e| format!("Failed to audit trajectory: {}", e))?;
                Ok(json!(report))
            }
            "mmu_scan_skill" => {
                let path = args.get("target_path").and_then(|v| v.as_str()).unwrap_or("");
                let scanner = crate::SkillSpectre::new();
                let report = scanner.scan_target(path).map_err(|e| format!("Failed to scan skill: {}", e))?;
                Ok(json!(report))
            }
            _ => Err(format!("Unknown tool: {}", name)),
        }
    }

    pub fn run_stdio(&mut self) -> io::Result<()> {
        let stdin = io::stdin();
        let mut stdout = io::stdout();

        for line in stdin.lock().lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let req: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => {
                    let err_resp = json!({
                        "jsonrpc": "2.0",
                        "id": Value::Null,
                        "error": { "code": -32700, "message": "Parse error: Invalid JSON payload" }
                    });
                    let _ = writeln!(stdout, "{}", serde_json::to_string(&err_resp)?);
                    let _ = stdout.flush();
                    continue;
                }
            };

            let req_id = req.get("id").cloned();
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let params = req.get("params").cloned().unwrap_or(json!({}));

            // JSON-RPC 2.0 & MCP Specification Invariant:
            // Notifications do NOT have an id and the server MUST NOT send a response.
            if req_id.is_none() || method.starts_with("notifications/") || method == "initialized" {
                continue;
            }

            let resp = match method {
                "initialize" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": { "name": "agent-mmu", "version": env!("CARGO_PKG_VERSION") },
                        "capabilities": {
                            "tools": { "listChanged": false },
                            "prompts": { "listChanged": false },
                            "resources": { "listChanged": false }
                        }
                    }
                }),
                "tools/list" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": { "tools": self.get_tools() }
                }),
                "tools/call" => {
                    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                    match self.handle_tool_call(name, &arguments) {
                        Ok(res) => json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": serde_json::to_string_pretty(&res).unwrap_or_default()
                                }],
                                "isError": false
                            }
                        }),
                        Err(err) => json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "content": [{
                                    "type": "text",
                                    "text": format!("Error executing tool '{}': {}", name, err)
                                }],
                                "isError": true
                            }
                        }),
                    }
                }
                "prompts/list" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": { "prompts": [] }
                }),
                "resources/list" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": { "resources": [] }
                }),
                "resources/templates/list" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": { "resourceTemplates": [] }
                }),
                "logging/setLevel" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {}
                }),
                "ping" => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {}
                }),
                _ => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": { "code": -32601, "message": format!("Method '{}' not found", method) }
                }),
            };

            writeln!(stdout, "{}", serde_json::to_string(&resp)?)?;
            stdout.flush()?;
        }

        Ok(())
    }
}
