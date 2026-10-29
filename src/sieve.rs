//! Layer 2: AST Ingress Sieve
//!
//! Syntactic CLI output compressor for test runners, compilers, and shell commands.
//! Reduces raw CLI logs by 85%–98% before tokens enter the prompt buffer.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_ansi_regex() -> &'static Regex {
    ANSI_REGEX.get_or_init(|| {
        Regex::new(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])").expect("Valid ANSI regex")
    })
}

pub fn strip_ansi(text: &str) -> String {
    get_ansi_regex().replace_all(text, "").into_owned()
}

pub fn clean_progress_bars(text: &str) -> String {
    let mut lines = Vec::new();
    for raw_line in text.lines() {
        if raw_line.contains('\r') {
            let parts: Vec<&str> = raw_line.split('\r').filter(|p| !p.trim().is_empty()).collect();
            let line = parts.last().copied().unwrap_or("");
            lines.push(line.to_string());
        } else {
            lines.push(raw_line.to_string());
        }
    }
    lines.join("\n")
}

pub fn safe_slice_head(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

pub fn safe_slice_tail(s: &str, tail_bytes: usize) -> &str {
    if tail_bytes >= s.len() {
        return s;
    }
    let mut idx = s.len().saturating_sub(tail_bytes);
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    &s[idx..]
}

pub fn estimate_tokens(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    (text.len() + 3) / 4
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SieveResult {
    pub sieved_text: String,
    pub original_tokens: usize,
    pub sieved_tokens: usize,
    pub tokens_saved: usize,
    pub reduction_pct: f64,
    pub is_compressed: bool,
}

pub struct ASTIngressSieve;

impl ASTIngressSieve {
    pub fn sieve(
        stdout: &str,
        stderr: &str,
        exit_code: i32,
        command: &str,
        max_output_tokens: usize,
    ) -> SieveResult {
        let mut raw_combined = stdout.to_string();
        if !stderr.is_empty() {
            if !raw_combined.is_empty() {
                raw_combined.push('\n');
            }
            raw_combined.push_str(stderr);
        }

        let orig_tokens = estimate_tokens(&raw_combined);

        // CodeRabbit / Ponytail guard: Prevent ReDoS and memory bloat on massive 10MB+ logs
        const MAX_INGRESS_CHARS: usize = 250_000;
        let bounded_raw = if raw_combined.len() > MAX_INGRESS_CHARS {
            let head = safe_slice_head(&raw_combined, 40_000);
            let tail = safe_slice_tail(&raw_combined, 160_000);
            format!("{}\n\n[... Large output pre-sieved to avoid memory blowup ...]\n\n{}", head, tail)
        } else {
            raw_combined
        };

        let cleaned = clean_progress_bars(&strip_ansi(&bounded_raw)).trim().to_string();

        if cleaned.is_empty() {
            let msg = if exit_code == 0 {
                "[Empty output, exit code 0]".to_string()
            } else {
                format!("[Empty output, exit code {}]", exit_code)
            };
            return SieveResult {
                sieved_text: msg,
                original_tokens: orig_tokens,
                sieved_tokens: 10,
                tokens_saved: 0,
                reduction_pct: 0.0,
                is_compressed: false,
            };
        }

        let cmd_lower = command.to_lowercase();
        let text_lower = cleaned.to_lowercase();

        let mut compressed = if cmd_lower.contains("pytest")
            || text_lower.contains("test session starts")
            || text_lower.contains("= failures =")
        {
            Self::sieve_pytest(&cleaned, exit_code)
        } else if cmd_lower.contains("cargo")
            || cmd_lower.contains("rustc")
            || text_lower.contains("error[e")
        {
            Self::sieve_cargo(&cleaned, exit_code)
        } else if cmd_lower.contains("npm")
            || cmd_lower.contains("yarn")
            || cmd_lower.contains("vitest")
            || text_lower.contains("jest")
        {
            Self::sieve_jest(&cleaned, exit_code)
        } else if text_lower.contains("traceback (most recent call last):") {
            Self::sieve_python_traceback(&cleaned, exit_code)
        } else if cmd_lower.contains("git diff") || text_lower.contains("diff --git") {
            Self::sieve_git_diff(&cleaned)
        } else {
            Self::sieve_generic(&cleaned)
        };

        let mut sieved_tokens = estimate_tokens(&compressed);
        if sieved_tokens > max_output_tokens {
            compressed = Self::truncate_middle(&compressed, max_output_tokens);
            sieved_tokens = estimate_tokens(&compressed);
        }

        let saved = orig_tokens.saturating_sub(sieved_tokens);
        let reduction = if orig_tokens > 0 {
            (saved as f64 / orig_tokens as f64) * 100.0
        } else {
            0.0
        };

        SieveResult {
            sieved_text: compressed,
            original_tokens: orig_tokens,
            sieved_tokens,
            tokens_saved: saved,
            reduction_pct: (reduction * 100.0).round() / 100.0,
            is_compressed: orig_tokens > sieved_tokens,
        }
    }

    fn sieve_pytest(text: &str, exit_code: i32) -> String {
        if exit_code == 0 && !text.to_lowercase().contains("= failures =") {
            for line in text.lines() {
                if line.starts_with("====") && (line.contains("passed") || line.contains("failed")) {
                    return format!("[PyTest: ALL TESTS PASSED]\n{}", line.trim());
                }
            }
            return "[PyTest: All tests passed successfully]".to_string();
        }

        let mut retained = vec!["[PyTest Execution Failure - Sieved Output]".to_string()];
        let mut in_failure = false;
        let mut in_short_summary = false;

        for line in text.lines() {
            if line.starts_with("____") && line.ends_with("____") {
                retained.push(format!("\n{}", line.trim_matches(|c| c == '_' || c == ' ')));
                in_failure = true;
                continue;
            }
            if line.starts_with("==== FAILURES ====") {
                in_failure = true;
                continue;
            }
            if line.starts_with("==== short test summary info ====") {
                in_short_summary = true;
                in_failure = false;
                retained.push(format!("\n{}", line));
                continue;
            }
            if line.starts_with("====") && (line.contains("passed") || line.contains("failed")) {
                retained.push(line.to_string());
                in_short_summary = false;
                in_failure = false;
                continue;
            }

            if in_short_summary {
                if !line.trim().is_empty() {
                    retained.push(line.to_string());
                }
                continue;
            }

            if in_failure {
                if line.contains('>')
                    || line.contains("E   ")
                    || line.contains("AssertionError")
                    || line.contains("Error:")
                    || line.ends_with(".py:")
                {
                    retained.push(line.to_string());
                }
            }
        }

        retained.join("\n")
    }

    fn sieve_cargo(text: &str, exit_code: i32) -> String {
        if exit_code == 0 {
            return "[Cargo: Build/Check Succeeded]".to_string();
        }

        let mut retained = vec!["[Cargo Compiler Errors - Sieved Output]".to_string()];
        let mut capture_next = 0;

        for line in text.lines() {
            if line.contains("error[") || line.starts_with("error:") {
                retained.push(format!("\n{}", line));
                capture_next = 3;
                continue;
            }
            if line.contains(" --> ") {
                retained.push(line.to_string());
                capture_next = 2;
                continue;
            }
            if capture_next > 0 {
                retained.push(line.to_string());
                capture_next -= 1;
            }
        }

        retained.join("\n")
    }

    fn sieve_jest(text: &str, exit_code: i32) -> String {
        if exit_code == 0 {
            return "[Jest/Vitest: All Tests Passed]".to_string();
        }

        let mut retained = vec!["[Jest/Vitest Failure - Sieved Output]".to_string()];
        let mut capture = false;

        for line in text.lines() {
            if line.contains("FAIL ") || line.contains("● ") {
                retained.push(format!("\n{}", line));
                capture = true;
                continue;
            }
            if line.contains("Tests:") || line.contains("Suites:") {
                retained.push(line.to_string());
                continue;
            }
            if capture {
                if line.contains("Expected:") || line.contains("Received:") || line.contains("at ") {
                    retained.push(line.to_string());
                    if line.contains("at ") {
                        capture = false;
                    }
                }
            }
        }

        retained.join("\n")
    }

    fn sieve_python_traceback(text: &str, _exit_code: i32) -> String {
        let mut retained = vec!["[Python Traceback - Sieved Output]".to_string()];
        for line in text.lines() {
            if line.contains("site-packages") && line.contains("File ") {
                continue;
            }
            if line.contains("Traceback ")
                || line.contains("File \"")
                || line.contains("Error:")
                || line.contains("Exception:")
            {
                retained.push(line.to_string());
            }
        }
        retained.join("\n")
    }

    fn sieve_git_diff(text: &str) -> String {
        let mut retained = vec!["[Git Diff - Compact Sieve]".to_string()];
        for line in text.lines() {
            if line.starts_with("diff --git")
                || line.starts_with("--- ")
                || line.starts_with("+++ ")
                || line.starts_with("@@")
                || line.starts_with('+')
                || line.starts_with('-')
            {
                retained.push(line.to_string());
            }
        }
        retained.join("\n")
    }

    fn sieve_generic(text: &str) -> String {
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.len() <= 25 {
            return text.to_string();
        }

        let head = &lines[..10];
        let tail = &lines[lines.len() - 15..];
        let omitted = lines.len() - 25;

        format!(
            "{}\n\n[... {} lines omitted by AgentMMU AST Sieve ...]\n\n{}",
            head.join("\n"),
            omitted,
            tail.join("\n")
        )
    }

    fn truncate_middle(text: &str, max_tokens: usize) -> String {
        let max_chars = max_tokens * 4;
        if text.len() <= max_chars {
            return text.to_string();
        }
        let half = (max_chars / 2).saturating_sub(100);
        let head = safe_slice_head(text, half);
        let tail = safe_slice_tail(text, half);
        let omitted = text.len().saturating_sub(head.len() + tail.len());

        format!(
            "{}\n\n[... Omitted {} chars to adhere to MMU token budget ...]\n\n{}",
            head, omitted, tail
        )
    }
}
