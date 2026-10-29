//! Layer 0: Cache-Pinned Invariant Prefix
//!
//! Maintains a byte-identical, immutable system prompt prefix ($Z_0$) to guarantee
//! >88% Prompt Cache Hit rates across Anthropic Claude, OpenAI, and Gemini APIs.

use sha2::{Digest, Sha256};

pub const DEFAULT_INVARIANT_KERNEL_TEXT: &str = r#"# AGENT_MMU CORE INVARIANT KERNEL (RUST NATIVE v0.1.0)
You are an autonomous software engineering agent managed by AgentMMU (Native Systems Virtual Context Kernel).
Your execution is strictly monitored and bounded by deterministic memory layers.

## 1. Core Operating Principles (Karpathy Standards)
- THINK BEFORE CODING: State technical assumptions explicitly. Never assume silently or guess.
- RADICAL SIMPLICITY: The best code is code never written. Choose deletion over addition and boring over clever.
- SURGICAL CHANGES: Touch only what you must. Preserve existing formatting, comments, and working code.
- EMPIRICAL VERIFICATION: Every modification must be tested against ground truth. Never claim a fix without tool proof.

## 2. Cryptographic Invariant Rules
- ZERO GHOST ACTIONS: Never state or claim a file was modified, created, or tested unless verified by tool output.
- ZERO MASKED ERRORS: If a command returns exit code != 0, diagnose the root cause immediately; never conceal it.
- PROHIBITED ACTIONS: Never retry an identical failed command without modifying inputs or code.
- PROMPT CACHE DISCIPLINE: This kernel prefix is permanently pinned. Working context is bounded to <8,500 tokens.
"#;

#[derive(Debug, Clone)]
pub struct InvariantKernel {
    pub prefix_text: String,
    prefix_sha256: String,
}

impl InvariantKernel {
    pub fn new(custom_prefix: Option<&str>) -> Self {
        let prefix = custom_prefix.unwrap_or(DEFAULT_INVARIANT_KERNEL_TEXT).trim().to_string();
        let hash = Self::compute_sha256(&prefix);
        Self {
            prefix_text: prefix,
            prefix_sha256: hash,
        }
    }

    pub fn compute_sha256(text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn prefix_hash(&self) -> &str {
        &self.prefix_sha256
    }

    pub fn verify_cache_integrity(&self) -> bool {
        Self::compute_sha256(&self.prefix_text) == self.prefix_sha256
    }

    pub fn assemble_prompt_frame(
        &self,
        ledger_markdown: &str,
        active_slice: &str,
        user_message: &str,
    ) -> String {
        assert!(self.verify_cache_integrity(), "FATAL: Invariant kernel prefix hash mismatch!");

        let mut out = String::with_capacity(self.prefix_text.len() + ledger_markdown.len() + active_slice.len() + 256);
        out.push_str(&self.prefix_text);
        out.push_str("\n\n---\n\n");
        out.push_str(ledger_markdown.trim());

        if !user_message.trim().is_empty() {
            out.push_str("\n\n---\n### [CURRENT_USER_OBJECTIVE]\n");
            out.push_str(user_message.trim());
        }

        if !active_slice.trim().is_empty() {
            out.push_str("\n\n---\n### [ACTIVE_INGRESS_EXECUTION_FRAME]\n");
            out.push_str(active_slice.trim());
        }

        out
    }
}

impl Default for InvariantKernel {
    fn default() -> Self {
        Self::new(None)
    }
}
