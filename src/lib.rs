//! AgentMMU: Deterministic Memory Management Unit & Virtual Context Kernel (Rust Native).
//!
//! Author: Krish Joshi (@krish9-gif)
//! License: Apache-2.0

pub mod evaluator;
pub mod gatekeeper;
pub mod kernel;
pub mod ledger;
pub mod mcp;
pub mod pager;
pub mod sieve;
pub mod spectre;

use std::path::{Path, PathBuf};
use rusqlite::Result;
use serde::{Deserialize, Serialize};

pub use evaluator::{
    Anomaly, AnomalyType, AuditReport, BenchmarkVerdict, TrajectoryAuditor, TrajectoryTurn,
    TurnToolCall,
};
pub use gatekeeper::{CryptographicGatekeeper, FileSnapshot};
pub use kernel::InvariantKernel;
pub use ledger::StateLedger;
pub use mcp::MCPServer;
pub use pager::{ContextPager, PagedEvidence, PagerStats};
pub use sieve::{ASTIngressSieve, SieveResult, estimate_tokens};
pub use spectre::{
    ScanFinding, ScanReport, ScanVerdict, SkillSpectre, VulnerabilityCategory,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessOutputResult {
    pub sieved_text: String,
    pub tokens_saved: usize,
    pub reduction_pct: f64,
    pub trap_message: String,
    pub has_trap: bool,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MMUMetrics {
    pub turn: i64,
    pub total_raw_tokens: usize,
    pub total_sieved_tokens: usize,
    pub tokens_saved: usize,
    pub reduction_pct: f64,
    pub current_working_tokens: usize,
    pub estimated_cache_hit_pct: f64,
    pub epistemic_traps_intercepted: usize,
    pub swapped_pages: i64,
    pub swapped_bytes: i64,
}

pub struct AgentMMU {
    pub workspace_dir: PathBuf,
    pub session_id: String,
    pub kernel: InvariantKernel,
    pub ledger: StateLedger,
    pub pager: ContextPager,
    pub gatekeeper: CryptographicGatekeeper,

    pub total_raw_tokens: usize,
    pub total_sieved_tokens: usize,
    pub epistemic_traps_intercepted: usize,
}

impl AgentMMU {
    pub fn new<P: AsRef<Path>>(workspace_dir: P, session_id: &str, objective: &str) -> Result<Self> {
        let ws = workspace_dir.as_ref().to_path_buf();
        let mmu_dir = ws.join(".agent_mmu");
        let _ = std::fs::create_dir_all(&mmu_dir);

        // Security check: Sanitize session_id to prevent path traversal outside .agent_mmu
        let safe_session: String = session_id
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        let clean_session = if safe_session.is_empty() { "default_session" } else { &safe_session };

        let db_path = mmu_dir.join(format!("mmu_{}.db", clean_session));
        let db_str = db_path.to_str().unwrap_or(":memory:");

        let kernel = InvariantKernel::default();
        let ledger = StateLedger::new_file(db_str, clean_session, objective)?;
        let pager = ContextPager::new_file(db_str, clean_session)?;
        let gatekeeper = CryptographicGatekeeper::new(&ws);

        Ok(Self {
            workspace_dir: ws,
            session_id: clean_session.to_string(),
            kernel,
            ledger,
            pager,
            gatekeeper,
            total_raw_tokens: 0,
            total_sieved_tokens: 0,
            epistemic_traps_intercepted: 0,
        })
    }

    pub fn new_in_memory(session_id: &str, objective: &str) -> Result<Self> {
        let kernel = InvariantKernel::default();
        let ledger = StateLedger::new_in_memory(session_id, objective)?;
        let pager = ContextPager::new_in_memory(session_id)?;
        let gatekeeper = CryptographicGatekeeper::new(".");

        Ok(Self {
            workspace_dir: PathBuf::from("."),
            session_id: session_id.to_string(),
            kernel,
            ledger,
            pager,
            gatekeeper,
            total_raw_tokens: 0,
            total_sieved_tokens: 0,
            epistemic_traps_intercepted: 0,
        })
    }

    pub fn advance_turn(&mut self) -> Result<i64> {
        self.ledger.advance_turn()
    }

    pub fn process_tool_output(
        &mut self,
        tool_name: &str,
        stdout: &str,
        stderr: &str,
        exit_code: i32,
        command: &str,
        target_file: Option<&Path>,
        pre_snapshot: Option<&FileSnapshot>,
        file_operation: Option<&str>,
    ) -> Result<ProcessOutputResult> {
        let turn = self.ledger.get_turn()?;

        // 1. Sieve through Layer 2 (AST Ingress Sieve)
        let sieve_res = ASTIngressSieve::sieve(stdout, stderr, exit_code, command, 1500);
        self.total_raw_tokens += sieve_res.original_tokens;
        self.total_sieved_tokens += sieve_res.sieved_tokens;

        // 2. Circular loop check (Layer 4)
        let (is_loop, loop_msg) = self.gatekeeper.check_circular_loop(
            tool_name,
            if command.is_empty() { stdout } else { command },
            exit_code,
        );
        if is_loop {
            self.epistemic_traps_intercepted += 1;
            let _ = self.ledger.add_dead_end(
                &format!("Circular retry of '{}'", if command.is_empty() { tool_name } else { command }),
                &loop_msg,
            );
        }

        // 3. Cryptographic Invariant Verification (Layer 4)
        let mut trap_message = String::new();
        if let (Some(fpath), Some(pre), Some(op)) = (target_file, pre_snapshot, file_operation) {
            let (is_valid, reason, post_snap) = self.gatekeeper.verify_file_mutation(fpath, pre, op);
            if !is_valid {
                self.epistemic_traps_intercepted += 1;
                trap_message = reason;
            } else if let Some(post) = post_snap {
                let status = match op {
                    "create" | "write" => "created",
                    "delete" => "deleted",
                    _ => "modified",
                };
                let path_str = fpath.to_str().unwrap_or("");
                let _ = self.ledger.record_dirty_file(
                    path_str,
                    post.inode as i64,
                    &pre.sha256,
                    &post.sha256,
                    status,
                );
            }
        }

        // 4. Masked Failure Verification
        if exit_code != 0 {
            let (is_exec_valid, _) = self.gatekeeper.verify_execution_outcome(
                if command.is_empty() { tool_name } else { command },
                exit_code,
                false,
            );
            let _ = is_exec_valid;
        }

        // 5. Page out to Layer 3 (Episodic Swap via SQLite FTS5)
        let mut raw_full = stdout.to_string();
        if !stderr.is_empty() {
            raw_full.push('\n');
            raw_full.push_str(stderr);
        }
        let _ = self.pager.page_out(
            turn,
            "tool",
            &raw_full,
            tool_name,
            &sieve_res.sieved_text,
        );

        let has_trap = !trap_message.is_empty() || is_loop;

        Ok(ProcessOutputResult {
            sieved_text: sieve_res.sieved_text,
            tokens_saved: sieve_res.tokens_saved,
            reduction_pct: sieve_res.reduction_pct,
            trap_message,
            has_trap,
            exit_code,
        })
    }

    pub fn page_in_evidence(&self, query: &str, limit: usize) -> Result<Vec<PagedEvidence>> {
        self.pager.page_in_evidence(query, limit, 400)
    }

    pub fn render_prompt_frame(&self, active_slice: &str, user_message: &str) -> Result<String> {
        let ledger_md = self.ledger.render_markdown(1200)?;
        Ok(self.kernel.assemble_prompt_frame(&ledger_md, active_slice, user_message))
    }

    pub fn get_metrics(&self) -> Result<MMUMetrics> {
        let turn = self.ledger.get_turn()?;
        let p_stats = self.pager.stats()?;
        let saved = self.total_raw_tokens.saturating_sub(self.total_sieved_tokens);
        let reduction = if self.total_raw_tokens > 0 {
            (saved as f64 / self.total_raw_tokens as f64) * 100.0
        } else {
            0.0
        };

        let current_prompt = self.render_prompt_frame("", "")?;
        let prompt_tokens = estimate_tokens(&current_prompt);
        let kernel_tokens = estimate_tokens(&self.kernel.prefix_text);
        let cache_hit = if prompt_tokens > 0 {
            (kernel_tokens as f64 / prompt_tokens as f64) * 100.0
        } else {
            0.0
        };

        Ok(MMUMetrics {
            turn,
            total_raw_tokens: self.total_raw_tokens,
            total_sieved_tokens: self.total_sieved_tokens,
            tokens_saved: saved,
            reduction_pct: (reduction * 100.0).round() / 100.0,
            current_working_tokens: prompt_tokens,
            estimated_cache_hit_pct: (cache_hit * 100.0).round() / 100.0,
            epistemic_traps_intercepted: self.epistemic_traps_intercepted,
            swapped_pages: p_stats.total_pages,
            swapped_bytes: p_stats.raw_bytes,
        })
    }
}
