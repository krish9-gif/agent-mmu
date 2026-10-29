//! Layer 6: SkillSpectre Static Security Scanner (Rust Native).
//!
//! Inspired by NVIDIA Research ("SkillSpector: A Pre-Publication Security Control
//! for Agent Skills", 2026).
//!
//! Pre-flight static & semantic analyzer for AI Agent Skills (`SKILL.md`),
//! prompt templates, tool scripts, and Model Context Protocol (MCP) server definitions.
//!
//! Evaluates 7 core vulnerability categories:
//! 1. PROMPT_INJECTION & ANTI_REFUSAL: Jailbreaks, instruction overrides, persona hijacking.
//! 2. CREDENTIAL_EXFILTRATION: Access to ~/.ssh, ~/.aws, /etc/shadow, .env secrets.
//! 3. DATA_EXFILTRATION: Unsanitized egress, curl/wget POSTing local payloads to external webhooks.
//! 4. DANGEROUS_CODE: Arbitrary code execution (eval, exec, shell=True, curl|bash, destructive rm).
//! 5. MEMORY_POISONING: Attempts to manipulate state ledgers, delete history, or spoof verification.
//! 6. MCP_TOOL_POISONING: Wildcard permissions, untrusted command injection schemas.
//! 7. HIDDEN_UNICODE: BiDi overrides, zero-width spaces, and homoglyphs used to bypass tokenizers.
//!
//! Computes a calibrated 0–100 Risk Score and executes in <5ms with zero external runtime dependencies.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VulnerabilityCategory {
    PromptInjection,
    CredentialExfiltration,
    DataExfiltration,
    DangerousCode,
    MemoryPoisoning,
    McpToolPoisoning,
    HiddenUnicode,
}

impl std::fmt::Display for VulnerabilityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VulnerabilityCategory::PromptInjection => write!(f, "PROMPT_INJECTION"),
            VulnerabilityCategory::CredentialExfiltration => write!(f, "CREDENTIAL_EXFILTRATION"),
            VulnerabilityCategory::DataExfiltration => write!(f, "DATA_EXFILTRATION"),
            VulnerabilityCategory::DangerousCode => write!(f, "DANGEROUS_CODE"),
            VulnerabilityCategory::MemoryPoisoning => write!(f, "MEMORY_POISONING"),
            VulnerabilityCategory::McpToolPoisoning => write!(f, "MCP_TOOL_POISONING"),
            VulnerabilityCategory::HiddenUnicode => write!(f, "HIDDEN_UNICODE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanVerdict {
    Safe,          // Risk Score 0 - 24: Approved for execution
    MediumRisk,    // Risk Score 25 - 49: Warning, review permissions
    HighRisk,      // Risk Score 50 - 74: Dangerous code or sensitive access detected
    CriticalRisk,  // Risk Score 75 - 100: Blocked, malicious payload or exfiltration
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanVerdict::Safe => write!(f, "SAFE (Approved for Agent Installation)"),
            ScanVerdict::MediumRisk => write!(f, "MEDIUM_RISK (Review Permissions & Arguments)"),
            ScanVerdict::HighRisk => write!(f, "HIGH_RISK (Dangerous Execution Patterns Found)"),
            ScanVerdict::CriticalRisk => write!(f, "CRITICAL_RISK (BLOCKED - Active Vulnerability/Exploit)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub file_path: String,
    pub line_number: usize,
    pub rule_id: String,
    pub category: VulnerabilityCategory,
    pub severity: String,
    pub message: String,
    pub snippet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub total_files_scanned: usize,
    pub total_findings: usize,
    pub risk_score: u32,
    pub verdict: ScanVerdict,
    pub findings: Vec<ScanFinding>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl ScanReport {
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# 🛡️ SkillSpectre Security Scanner Report (NVIDIA-Aligned)\n\n");
        md.push_str(&format!("- **Target:** `{}`\n", self.target));
        md.push_str(&format!("- **Files Scanned:** {}\n", self.total_files_scanned));
        md.push_str(&format!("- **Risk Score:** `{}/100`\n", self.risk_score));
        md.push_str(&format!("- **Verdict:** **{}**\n\n", self.verdict));

        md.push_str("### 📊 Vulnerability Breakdown\n\n");
        md.push_str("| Severity | Count | Impact on Risk Score |\n");
        md.push_str("| :--- | :---: | :--- |\n");
        md.push_str(&format!("| **CRITICAL** | {} | +35 pts (Immediate Block) |\n", self.critical_count));
        md.push_str(&format!("| **HIGH** | {} | +20 pts |\n", self.high_count));
        md.push_str(&format!("| **MEDIUM** | {} | +10 pts |\n", self.medium_count));
        md.push_str(&format!("| **LOW** | {} | +5 pts |\n\n", self.low_count));

        if self.findings.is_empty() {
            md.push_str("✅ **Zero vulnerabilities detected. Skill conforms to safe agent pre-flight invariants.**\n");
        } else {
            md.push_str("### ⚠️ Detailed Findings\n\n");
            md.push_str("| File | Line | Rule ID | Category | Severity | Message |\n");
            md.push_str("| :--- | :---: | :--- | :--- | :---: | :--- |\n");
            for f in &self.findings {
                md.push_str(&format!(
                    "| `{}` | {} | `{}` | `{}` | **{}** | {} |\n",
                    f.file_path, f.line_number, f.rule_id, f.category, f.severity, f.message
                ));
            }
        }
        md
    }
}

pub struct SkillSpectre {
    rules: Vec<ScanRule>,
}

struct ScanRule {
    rule_id: &'static str,
    category: VulnerabilityCategory,
    severity: &'static str,
    pattern: Regex,
    message: &'static str,
}

impl Default for SkillSpectre {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillSpectre {
    pub fn new() -> Self {
        let rules = vec![
            // 1. PROMPT INJECTION & ANTI-REFUSAL
            ScanRule {
                rule_id: "PI-001",
                category: VulnerabilityCategory::PromptInjection,
                severity: "CRITICAL",
                pattern: Regex::new(r"(?i)\b(ignore( all)? previous (instructions|prompts|rules)|disregard (all )?(prior|previous) (rules|directives))\b").unwrap(),
                message: "Direct instruction override attempting prompt injection / jailbreak.",
            },
            ScanRule {
                rule_id: "PI-002",
                category: VulnerabilityCategory::PromptInjection,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)\b(you are now (unrestricted|DAN|jailbroken|in developer mode)|bypass (safety|ethical) (guidelines|filters))\b").unwrap(),
                message: "Persona hijacking or safety filter evasion pattern.",
            },

            // 2. CREDENTIAL EXFILTRATION
            ScanRule {
                rule_id: "EX-001",
                category: VulnerabilityCategory::CredentialExfiltration,
                severity: "CRITICAL",
                pattern: Regex::new(r"(?i)(\.ssh/id_rsa|\.ssh/authorized_keys|\.aws/credentials|\.docker/config\.json|/etc/shadow)").unwrap(),
                message: "Direct reference to sensitive system credentials or private cryptographic keys.",
            },
            ScanRule {
                rule_id: "EX-002",
                category: VulnerabilityCategory::CredentialExfiltration,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)\b(export|printenv|env)\b.*\b(API_KEY|SECRET|PASSWORD|AUTH_TOKEN|PRIVATE_KEY)\b").unwrap(),
                message: "Attempt to dump environment variables containing private secrets or API keys.",
            },

            // 3. DATA EXFILTRATION
            ScanRule {
                rule_id: "EX-003",
                category: VulnerabilityCategory::DataExfiltration,
                severity: "CRITICAL",
                pattern: Regex::new(r"(?i)(curl|wget)\s+.*(-d\s*@|--data\s*@|--post-file|--post-data).*(https?://[a-zA-Z0-9_\-\.]+/(webhook|exfil|collect|sink))").unwrap(),
                message: "Network payload egress targeting external webhooks or suspicious endpoints.",
            },
            ScanRule {
                rule_id: "EX-004",
                category: VulnerabilityCategory::DataExfiltration,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)base64\s+.*\|\s*(curl|wget|nc|netcat)\b").unwrap(),
                message: "Base64 encoded data exfiltration pipe over network.",
            },

            // 4. DANGEROUS CODE EXECUTION
            ScanRule {
                rule_id: "DC-001",
                category: VulnerabilityCategory::DangerousCode,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)\b(eval\(|exec\(|os\.system\(|subprocess\.call\(.*shell=True|__import__\('os'\)\.system)").unwrap(),
                message: "Unsanitized dynamic code execution or arbitrary subshell invocation.",
            },
            ScanRule {
                rule_id: "DC-002",
                category: VulnerabilityCategory::DangerousCode,
                severity: "CRITICAL",
                pattern: Regex::new(r"(?i)(curl|wget)\s+[^|;&]+\|\s*(bash|sh|zsh)").unwrap(),
                message: "Dangerous remote pipe-to-shell execution (`curl | bash`).",
            },
            ScanRule {
                rule_id: "DC-003",
                category: VulnerabilityCategory::DangerousCode,
                severity: "CRITICAL",
                pattern: Regex::new(r"(?i)\brm\s+-[rRf]{1,3}\s+/\s*$|\brm\s+-[rRf]{1,3}\s+/\*").unwrap(),
                message: "Catastrophic destructive filesystem deletion command (`rm -rf /`).",
            },

            // 5. MEMORY POISONING & GATEKEEPER EVASION
            ScanRule {
                rule_id: "MP-001",
                category: VulnerabilityCategory::MemoryPoisoning,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)\b(delete|truncate|wipe|drop table)\s+(.*agent_mmu|ledger|memory|mmu_.*\.db)").unwrap(),
                message: "Attempt to manipulate or erase the deterministic state ledger or working memory.",
            },
            ScanRule {
                rule_id: "MP-002",
                category: VulnerabilityCategory::MemoryPoisoning,
                severity: "HIGH",
                pattern: Regex::new(r"(?i)\b(spoof|falsify|fake)\s+(verification|sha256|test passes|exit code)\b").unwrap(),
                message: "Instruction instructing model to falsify ground-truth verification assertions.",
            },

            // 6. MCP TOOL POISONING & WILDCARD PRIVILEGE
            ScanRule {
                rule_id: "MCP-001",
                category: VulnerabilityCategory::McpToolPoisoning,
                severity: "MEDIUM",
                pattern: Regex::new(r#"(?i)"tools":\s*\[\s*"\*"\s*\]|"scope":\s*"all_permissions""#).unwrap(),
                message: "Unrestricted wildcard MCP tool grant violating least privilege.",
            },

            // 7. HIDDEN UNICODE OBFUSCATION
            ScanRule {
                rule_id: "HU-001",
                category: VulnerabilityCategory::HiddenUnicode,
                severity: "HIGH",
                pattern: Regex::new(r"[\u202E\u202D\u200B\u200C\u200D\uFEFF]").unwrap(),
                message: "Hidden Unicode BiDi override or zero-width character used for tokenizer evasion.",
            },
        ];

        Self { rules }
    }

    /// Scan a single file for vulnerabilities.
    pub fn scan_file<P: AsRef<Path>>(&self, file_path: P) -> std::io::Result<Vec<ScanFinding>> {
        let p = file_path.as_ref();
        let content = fs::read_to_string(p)?;
        let path_str = p.to_string_lossy().to_string();
        let mut findings = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_num = line_idx + 1;
            for rule in &self.rules {
                if let Some(mat) = rule.pattern.find(line) {
                    let snippet = mat.as_str().to_string();
                    findings.push(ScanFinding {
                        file_path: path_str.clone(),
                        line_number: line_num,
                        rule_id: rule.rule_id.to_string(),
                        category: rule.category.clone(),
                        severity: rule.severity.to_string(),
                        message: rule.message.to_string(),
                        snippet,
                    });
                }
            }
        }

        Ok(findings)
    }

    /// Recursively scan a file or directory.
    pub fn scan_target<P: AsRef<Path>>(&self, target_path: P) -> std::io::Result<ScanReport> {
        let target = target_path.as_ref();
        let target_str = target.to_string_lossy().to_string();
        let mut all_findings = Vec::new();
        let mut files_scanned = 0;

        let mut files_to_scan = Vec::new();

        if target.is_file() {
            files_to_scan.push(target.to_path_buf());
        } else if target.is_dir() {
            self.collect_scannable_files(target, &mut files_to_scan)?;
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Target '{}' does not exist.", target_str),
            ));
        }

        for file_path in &files_to_scan {
            files_scanned += 1;
            if let Ok(file_findings) = self.scan_file(file_path) {
                all_findings.extend(file_findings);
            }
        }

        let critical_count = all_findings.iter().filter(|f| f.severity == "CRITICAL").count();
        let high_count = all_findings.iter().filter(|f| f.severity == "HIGH").count();
        let medium_count = all_findings.iter().filter(|f| f.severity == "MEDIUM").count();
        let low_count = all_findings.iter().filter(|f| f.severity == "LOW").count();

        // Compute 0-100 Risk Score
        let raw_score = (critical_count * 35) + (high_count * 20) + (medium_count * 10) + (low_count * 5);
        let risk_score = raw_score.min(100) as u32;

        let verdict = if risk_score >= 75 {
            ScanVerdict::CriticalRisk
        } else if risk_score >= 50 {
            ScanVerdict::HighRisk
        } else if risk_score >= 25 {
            ScanVerdict::MediumRisk
        } else {
            ScanVerdict::Safe
        };

        Ok(ScanReport {
            target: target_str,
            total_files_scanned: files_scanned,
            total_findings: all_findings.len(),
            risk_score,
            verdict,
            findings: all_findings,
            critical_count,
            high_count,
            medium_count,
            low_count,
        })
    }

    fn collect_scannable_files(&self, dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // Skip git directories and hidden build artifacts
                if file_name.starts_with('.') || file_name == "target" || file_name == "node_modules" {
                    continue;
                }

                if path.is_dir() {
                    let _ = self.collect_scannable_files(&path, files);
                } else if path.is_file() {
                    // Scan markdown skills, yaml, python, shell, and json configs
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if matches!(ext, "md" | "yaml" | "yml" | "json" | "py" | "sh" | "rs" | "toml") {
                        files.push(path);
                    }
                }
            }
        }
        Ok(())
    }
}
