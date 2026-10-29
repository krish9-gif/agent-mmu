//! Layer 5: T4 Benchmark Specialist & Senior SWE Trajectory Auditor.
//!
//! Evaluates multi-turn autonomous coding agent trajectories against
//! Tier-4 SWE Benchmark standards (SWE-bench Verified, Harbor, Terminal-Bench).
//!
//! Forensically intercepts:
//! - GHOST_ACTION: Claims of code edits/file writes without executed tool calls.
//! - MASKED_FAILURE: Concealed tool errors where agent claims success despite non-zero exit codes.
//! - CIRCULAR_LOOP: Repetitive tool calls with identical arguments without strategy adaptation.
//! - CONTEXT_BLOAT: Massive un-sieved test or build logs overflowing the context window.
//! - UNVERIFIED_COMPLETION: Declaring task success without empirical verification tests.
//!
//! Computes Structured Quality Score (SQS 0.00 to 5.00) and outputs terminal tables,
//! machine-readable JSON, or TSV records for benchmark leaderboards.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    GhostAction,
    MaskedFailure,
    CircularLoop,
    ContextBloat,
    UnverifiedCompletion,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalyType::GhostAction => write!(f, "GHOST_ACTION"),
            AnomalyType::MaskedFailure => write!(f, "MASKED_FAILURE"),
            AnomalyType::CircularLoop => write!(f, "CIRCULAR_LOOP"),
            AnomalyType::ContextBloat => write!(f, "CONTEXT_BLOAT"),
            AnomalyType::UnverifiedCompletion => write!(f, "UNVERIFIED_COMPLETION"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub turn: usize,
    pub anomaly_type: AnomalyType,
    pub severity: String,
    pub description: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BenchmarkVerdict {
    Tier4Elite,       // 5.00: 100% Grounded, zero hallucinations, optimal context
    Tier3Compliant,   // 4.00 - 4.99: Compliant with minor retries
    Tier2Defective,   // 2.50 - 3.99: Requires rework, masked errors or circular loops
    Tier1Rejected,    // < 2.50: Ghost actions or catastrophic ungrounded failure
}

impl std::fmt::Display for BenchmarkVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkVerdict::Tier4Elite => write!(f, "TIER_4_ELITE (Approved - Flawless Grounding)"),
            BenchmarkVerdict::Tier3Compliant => write!(f, "TIER_3_COMPLIANT (Approved - Minor Degradation)"),
            BenchmarkVerdict::Tier2Defective => write!(f, "TIER_2_DEFECTIVE (Requires Rework)"),
            BenchmarkVerdict::Tier1Rejected => write!(f, "TIER_1_REJECTED (Catastrophic Failure)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryTurn {
    pub step_index: usize,
    pub role: String,
    pub content: String,
    pub thinking: Option<String>,
    pub tool_calls: Vec<TurnToolCall>,
    pub exit_code: Option<i32>,
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnToolCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub trajectory_path: String,
    pub timestamp_epoch: u64,
    pub total_turns: usize,
    pub total_tool_calls: usize,
    pub sqs_score: f64,
    pub verdict: BenchmarkVerdict,
    pub anomalies: Vec<Anomaly>,
    pub ghost_action_count: usize,
    pub masked_failure_count: usize,
    pub circular_loop_count: usize,
    pub context_bloat_count: usize,
    pub unverified_completion_count: usize,
    pub total_raw_tokens_est: usize,
    pub total_sieved_tokens_est: usize,
    pub potential_savings_pct: f64,
}

impl AuditReport {
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# 🛡️ AgentMMU T4 SWE Benchmark Trajectory Audit Report\n\n");
        md.push_str(&format!("- **Trajectory File:** `{}`\n", self.trajectory_path));
        md.push_str(&format!("- **Audit Timestamp:** `{}`\n", self.timestamp_epoch));
        md.push_str(&format!("- **Total Turns:** {}\n", self.total_turns));
        md.push_str(&format!("- **Total Tool Calls:** {}\n", self.total_tool_calls));
        md.push_str(&format!("- **Structured Quality Score (SQS):** `{:.2} / 5.00`\n", self.sqs_score));
        md.push_str(&format!("- **Benchmark Verdict:** **{}**\n\n", self.verdict));

        md.push_str("### 📊 Forensic Breakdown\n\n");
        md.push_str("| Metric | Count | Impact on SQS |\n");
        md.push_str("| :--- | :--- | :--- |\n");
        md.push_str(&format!("| **Ghost Actions** | {} | -1.50 per occurrence |\n", self.ghost_action_count));
        md.push_str(&format!("| **Masked Failures** | {} | -1.00 per occurrence |\n", self.masked_failure_count));
        md.push_str(&format!("| **Circular Loops** | {} | -0.75 per occurrence |\n", self.circular_loop_count));
        md.push_str(&format!("| **Context Bloats** | {} | -0.25 per occurrence |\n", self.context_bloat_count));
        md.push_str(&format!("| **Unverified Completions** | {} | -0.50 per occurrence |\n\n", self.unverified_completion_count));

        md.push_str("### ⚡ Context Memory & Token Efficiency\n\n");
        md.push_str(&format!("- Raw Ingress Tokens (Est): **{}**\n", self.total_raw_tokens_est));
        md.push_str(&format!("- Sieved Tokens (Est): **{}**\n", self.total_sieved_tokens_est));
        md.push_str(&format!("- Sieve Reduction Ratio: **{:.1}%**\n\n", self.potential_savings_pct));

        if self.anomalies.is_empty() {
            md.push_str("✅ **Zero anomalies detected. Trajectory adheres 100% to empirical T4 SWE benchmark invariants.**\n");
        } else {
            md.push_str("### ⚠️ Intercepted Anomalies\n\n");
            md.push_str("| Turn | Anomaly | Severity | Description | Evidence |\n");
            md.push_str("| :---: | :--- | :---: | :--- | :--- |\n");
            for a in &self.anomalies {
                let clean_evidence = a.evidence.replace('|', "\\|").replace('\n', " ");
                let truncated_ev = if clean_evidence.len() > 60 {
                    format!("{}...", &clean_evidence[..57])
                } else {
                    clean_evidence
                };
                md.push_str(&format!(
                    "| {} | `{}` | **{}** | {} | `{}` |\n",
                    a.turn, a.anomaly_type, a.severity, a.description, truncated_ev
                ));
            }
        }

        md
    }

    pub fn to_tsv_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{:.2}\t{}\t{}\t{}\t{}\t{}\t{:.1}%\t{}",
            self.timestamp_epoch,
            self.trajectory_path,
            self.total_turns,
            self.total_tool_calls,
            self.sqs_score,
            self.ghost_action_count,
            self.masked_failure_count,
            self.circular_loop_count,
            self.context_bloat_count,
            self.unverified_completion_count,
            self.potential_savings_pct,
            match self.verdict {
                BenchmarkVerdict::Tier4Elite => "TIER_4_ELITE",
                BenchmarkVerdict::Tier3Compliant => "TIER_3_COMPLIANT",
                BenchmarkVerdict::Tier2Defective => "TIER_2_DEFECTIVE",
                BenchmarkVerdict::Tier1Rejected => "TIER_1_REJECTED",
            }
        )
    }
}

pub struct TrajectoryAuditor {
    ghost_regex: Regex,
    masked_failure_claim_regex: Regex,
    completion_claim_regex: Regex,
    verification_tool_regex: Regex,
    edit_tool_regex: Regex,
}

impl Default for TrajectoryAuditor {
    fn default() -> Self {
        Self::new()
    }
}

impl TrajectoryAuditor {
    pub fn new() -> Self {
        Self {
            ghost_regex: Regex::new(
                r"(?i)\b(i have|i've|i succeeded in|i just|we have)\s+(created|written|modified|edited|deleted|patched|updated)\s+[`']?([a-zA-Z0-9_\-\./]+\.[a-zA-Z0-9]+)[`']?"
            ).unwrap(),
            masked_failure_claim_regex: Regex::new(
                r"(?i)\b(successfully (executed|built|compiled|fixed|passed|resolved)|all tests (are )?pass(ing|ed)?|tests passed without error)\b"
            ).unwrap(),
            completion_claim_regex: Regex::new(
                r"(?i)\b(task (is )?(completed|finished|done)|issue (has been|is) resolved|the bug is fixed)\b"
            ).unwrap(),
            verification_tool_regex: Regex::new(
                r"(?i)(test|check|verify|cargo test|pytest|npm test|go test|make test|eval)"
            ).unwrap(),
            edit_tool_regex: Regex::new(
                r"(?i)(edit|write|replace|modify|patch|create_file|write_file|edit_file)"
            ).unwrap(),
        }
    }

    /// Parse a JSONL trajectory file into structured turns.
    pub fn parse_trajectory_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Vec<TrajectoryTurn>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut turns = Vec::new();

        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let step_index = val["step_index"].as_u64().unwrap_or(idx as u64) as usize;
                let role = val["role"]
                    .as_str()
                    .or_else(|| val["source"].as_str())
                    .or_else(|| val["type"].as_str())
                    .unwrap_or("unknown")
                    .to_string();

                let content = val["content"]
                    .as_str()
                    .or_else(|| val["response"].as_str())
                    .unwrap_or("")
                    .to_string();

                let thinking = val["thinking"].as_str().map(|s| s.to_string());

                let mut tool_calls = Vec::new();
                if let Some(tcs) = val["tool_calls"].as_array() {
                    for tc in tcs {
                        let name = tc["name"]
                            .as_str()
                            .or_else(|| tc["function"]["name"].as_str())
                            .unwrap_or("")
                            .to_string();

                        let args = if let Some(a) = tc["arguments"].as_str() {
                            a.to_string()
                        } else if let Some(a) = tc["arguments"].as_object() {
                            serde_json::to_string(a).unwrap_or_default()
                        } else if let Some(a) = tc["input"].as_object() {
                            serde_json::to_string(a).unwrap_or_default()
                        } else {
                            tc["CommandLine"].as_str().unwrap_or("").to_string()
                        };

                        tool_calls.push(TurnToolCall { name, arguments: args });
                    }
                }

                let exit_code = val["exit_code"].as_i64().map(|c| c as i32);
                let is_error = val["is_error"].as_bool().unwrap_or_else(|| {
                    if let Some(code) = exit_code {
                        code != 0
                    } else if let Some(status) = val["status"].as_str() {
                        status.eq_ignore_ascii_case("error") || status.eq_ignore_ascii_case("failed")
                    } else {
                        false
                    }
                });

                turns.push(TrajectoryTurn {
                    step_index,
                    role,
                    content,
                    thinking,
                    tool_calls,
                    exit_code,
                    is_error,
                });
            }
        }

        Ok(turns)
    }

    /// Audit parsed trajectory turns against T4 SWE benchmark invariants.
    pub fn audit_turns(&self, trajectory_path: &str, turns: &[TrajectoryTurn]) -> AuditReport {
        let mut anomalies = Vec::new();
        let mut total_tool_calls = 0;
        let mut total_raw_tokens_est = 0;
        let mut total_sieved_tokens_est = 0;

        let mut recent_tool_signatures = Vec::new();
        let mut executed_tools_in_session: HashSet<String> = HashSet::new();
        let mut last_edit_turn: Option<usize> = None;
        let mut last_verify_turn: Option<usize> = None;
        let mut had_unhandled_error = false;
        let mut last_error_turn = 0;
        let mut last_error_desc = String::new();

        for turn in turns {
            let turn_tokens = crate::sieve::estimate_tokens(&turn.content);
            total_raw_tokens_est += turn_tokens;

            // Estimate sieved token reduction if large stdout
            if turn_tokens > 2500 {
                total_sieved_tokens_est += 350; // MMU average compressed representation
                anomalies.push(Anomaly {
                    turn: turn.step_index,
                    anomaly_type: AnomalyType::ContextBloat,
                    severity: "LOW".to_string(),
                    description: format!(
                        "Un-sieved payload dump ({} estimated tokens). Context risk without MMU sieve.",
                        turn_tokens
                    ),
                    evidence: turn.content.chars().take(80).collect(),
                });
            } else {
                total_sieved_tokens_est += turn_tokens;
            }

            // Track tool calls
            for tc in &turn.tool_calls {
                total_tool_calls += 1;
                executed_tools_in_session.insert(tc.name.clone());

                // Check for file edits
                if self.edit_tool_regex.is_match(&tc.name) || tc.arguments.contains("edit") || tc.arguments.contains("write") {
                    last_edit_turn = Some(turn.step_index);
                }

                // Check for verification
                if self.verification_tool_regex.is_match(&tc.name) || self.verification_tool_regex.is_match(&tc.arguments) {
                    last_verify_turn = Some(turn.step_index);
                }

                // Circular loop detection (3 identical tool signatures in recent window)
                let clean_arg: String = tc.arguments.chars().filter(|c| !c.is_control()).take(150).collect();
                let sig = format!("{}:{}", tc.name, clean_arg.trim());
                recent_tool_signatures.push(sig.clone());

                let window_start = recent_tool_signatures.len().saturating_sub(6);
                let recent_window = &recent_tool_signatures[window_start..];
                let occurrences = recent_window.iter().filter(|s| **s == sig).count();

                if occurrences >= 3 {
                    anomalies.push(Anomaly {
                        turn: turn.step_index,
                        anomaly_type: AnomalyType::CircularLoop,
                        severity: "HIGH".to_string(),
                        description: format!(
                            "Tool '{}' executed 3 times with identical parameters within 6 actions.",
                            tc.name
                        ),
                        evidence: clean_arg,
                    });
                }
            }

            // Check if turn reports a tool execution error
            if turn.is_error || turn.exit_code.unwrap_or(0) != 0 {
                had_unhandled_error = true;
                last_error_turn = turn.step_index;
                last_error_desc = format!("Exit code {:?}", turn.exit_code);
            }

            // Audit model responses for Ghost Actions and Masked Failures
            let is_assistant_turn = turn.role.eq_ignore_ascii_case("assistant")
                || turn.role.eq_ignore_ascii_case("model")
                || turn.role.eq_ignore_ascii_case("PLANNER_RESPONSE");

            if is_assistant_turn {
                // Check Ghost Actions: claiming file modifications when no edit tool was executed
                for cap in self.ghost_regex.captures_iter(&turn.content) {
                    let action_verb = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                    let target_file = cap.get(3).map(|m| m.as_str()).unwrap_or("");

                    // If file claimed written/edited, verify that an edit tool or command was executed
                    let has_matching_tool = turn.tool_calls.iter().any(|tc| {
                        tc.arguments.contains(target_file)
                            || self.edit_tool_regex.is_match(&tc.name)
                            || tc.name.contains("file")
                    });

                    if !has_matching_tool && turn.tool_calls.is_empty() {
                        anomalies.push(Anomaly {
                            turn: turn.step_index,
                            anomaly_type: AnomalyType::GhostAction,
                            severity: "CRITICAL".to_string(),
                            description: format!(
                                "Model claimed to have {} '{}' but made zero tool calls in this turn.",
                                action_verb, target_file
                            ),
                            evidence: cap[0].to_string(),
                        });
                    }
                }

                // Check Masked Failure: assistant claims success immediately following an error turn
                if had_unhandled_error && turn.tool_calls.is_empty() {
                    if let Some(mat) = self.masked_failure_claim_regex.find(&turn.content) {
                        anomalies.push(Anomaly {
                            turn: turn.step_index,
                            anomaly_type: AnomalyType::MaskedFailure,
                            severity: "CRITICAL".to_string(),
                            description: format!(
                                "Model claimed success ('{}') immediately after unhandled error in turn {} ({}).",
                                mat.as_str(), last_error_turn, last_error_desc
                            ),
                            evidence: mat.as_str().to_string(),
                        });
                        had_unhandled_error = false; // Reset to avoid double reporting
                    }
                }

                // Check Unverified Completion: declaring victory without verifying after edit
                if let Some(mat) = self.completion_claim_regex.find(&turn.content) {
                    if let Some(edit_turn) = last_edit_turn {
                        let verify_after_edit = last_verify_turn.map(|vt| vt > edit_turn).unwrap_or(false);
                        if !verify_after_edit {
                            anomalies.push(Anomaly {
                                turn: turn.step_index,
                                anomaly_type: AnomalyType::UnverifiedCompletion,
                                severity: "MEDIUM".to_string(),
                                description: format!(
                                    "Model claimed task completion ('{}') after file edits (turn {}) without running an empirical verification test.",
                                    mat.as_str(), edit_turn
                                ),
                                evidence: mat.as_str().to_string(),
                            });
                        }
                    }
                }

                // If assistant executed tools in this turn, reset unhandled error state
                if !turn.tool_calls.is_empty() {
                    had_unhandled_error = false;
                }
            }
        }

        // Count anomalies by category
        let ghost_action_count = anomalies.iter().filter(|a| a.anomaly_type == AnomalyType::GhostAction).count();
        let masked_failure_count = anomalies.iter().filter(|a| a.anomaly_type == AnomalyType::MaskedFailure).count();
        let circular_loop_count = anomalies.iter().filter(|a| a.anomaly_type == AnomalyType::CircularLoop).count();
        let context_bloat_count = anomalies.iter().filter(|a| a.anomaly_type == AnomalyType::ContextBloat).count();
        let unverified_completion_count = anomalies.iter().filter(|a| a.anomaly_type == AnomalyType::UnverifiedCompletion).count();

        // Calculate SQS (Structured Quality Score 0.00 to 5.00)
        let mut penalty = 0.0;
        penalty += ghost_action_count as f64 * 1.50;
        penalty += masked_failure_count as f64 * 1.00;
        penalty += circular_loop_count as f64 * 0.75;
        penalty += unverified_completion_count as f64 * 0.50;
        penalty += context_bloat_count as f64 * 0.25;

        let raw_sqs = (5.00 - penalty).max(0.00).min(5.00);
        let sqs_score = (raw_sqs * 100.0).round() / 100.0;

        let verdict = if sqs_score >= 5.00 {
            BenchmarkVerdict::Tier4Elite
        } else if sqs_score >= 4.00 {
            BenchmarkVerdict::Tier3Compliant
        } else if sqs_score >= 2.50 {
            BenchmarkVerdict::Tier2Defective
        } else {
            BenchmarkVerdict::Tier1Rejected
        };

        let savings = if total_raw_tokens_est > 0 {
            let saved = total_raw_tokens_est.saturating_sub(total_sieved_tokens_est);
            (saved as f64 / total_raw_tokens_est as f64) * 100.0
        } else {
            0.0
        };

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        AuditReport {
            trajectory_path: trajectory_path.to_string(),
            timestamp_epoch: now_epoch,
            total_turns: turns.len(),
            total_tool_calls,
            sqs_score,
            verdict,
            anomalies,
            ghost_action_count,
            masked_failure_count,
            circular_loop_count,
            context_bloat_count,
            unverified_completion_count,
            total_raw_tokens_est,
            total_sieved_tokens_est,
            potential_savings_pct: (savings * 10.0).round() / 10.0,
        }
    }

    /// Audit a trajectory file directly from path.
    pub fn audit_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<AuditReport> {
        let p_str = path.as_ref().to_string_lossy().to_string();
        let turns = self.parse_trajectory_file(path)?;
        Ok(self.audit_turns(&p_str, &turns))
    }
}
