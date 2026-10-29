//! AgentMMU Command-Line Interface (Rust Native).
//!
//! Subcommands for managing agent working memory, sieving CLI logs,
//! querying episodic swap space, and running as an MCP server.

use agent_mmu::{AgentMMU, MCPServer};
use clap::{Parser, Subcommand};
use std::process::{Command, exit};

#[derive(Parser)]
#[command(name = "agent-mmu")]
#[command(author = "Krish Joshi <krishjoshikrishjoshi9@gmail.com>")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Deterministic Memory Management Unit & Virtual Context Kernel for AI Agents", long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "default_session")]
    session: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize an AgentMMU workspace
    Init {
        #[arg(short, long, default_value = "")]
        objective: String,
    },
    /// Display current MMU state ledger, active invariants, and cache metrics
    Status,
    /// Execute a command, sieve its output, and log to MMU
    Sieve {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Search episodic virtual swap space using SQLite FTS5 BM25 ranking
    Page {
        query: String,
        #[arg(short, long, default_value_t = 3)]
        limit: usize,
    },
    /// Render the assembled 3-Zone context frame (Z0 + Z1 + Z2)
    Prompt {
        #[arg(short, long, default_value = "")]
        message: String,
    },
    /// Forensically audit an agent execution trajectory against T4 SWE benchmark standards
    Audit {
        /// Path to trajectory JSONL file
        #[arg(trailing_var_arg = false)]
        trajectory: Option<String>,

        /// Output machine-readable JSON for CI/CD gating
        #[arg(long)]
        json: bool,

        /// Append benchmark metric row to results.tsv
        #[arg(long)]
        tsv: bool,

        /// Minimum acceptable SQS score (e.g. 4.0 or 4.5); exits with code 1 if score is lower
        #[arg(long)]
        threshold: Option<f64>,
    },
    /// Scan AI agent skills, prompts, or MCP configurations for security vulnerabilities (NVIDIA SkillSpector-aligned)
    Scan {
        /// Path to skill file (.md), script, or directory of skills
        #[arg(default_value = ".")]
        target: String,

        /// Output machine-readable JSON format
        #[arg(long)]
        json: bool,

        /// Maximum acceptable risk score (0-100); exits with code 1 if risk score meets or exceeds threshold
        #[arg(long)]
        threshold: Option<u32>,
    },
    /// Run as an MCP Server over stdio for Antigravity & Claude Code
    Mcp,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { objective } => {
            match AgentMMU::new(".", &cli.session, &objective) {
                Ok(mmu) => {
                    println!("Initialized AgentMMU (Rust Native) in {:?}", mmu.workspace_dir);
                    println!("Session: {}", mmu.session_id);
                    if !objective.is_empty() {
                        println!("Objective: {}", objective);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to initialize AgentMMU: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Status => {
            match AgentMMU::new(".", &cli.session, "") {
                Ok(mmu) => {
                    let metrics = match mmu.get_metrics() {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("Error fetching metrics: {}", e);
                            exit(1);
                        }
                    };
                    let ledger = match mmu.ledger.to_json() {
                        Ok(l) => l,
                        Err(e) => {
                            eprintln!("Error reading ledger JSON: {}", e);
                            exit(1);
                        }
                    };

                    println!("=== AgentMMU (Rust Native v{}) Status ===", env!("CARGO_PKG_VERSION"));
                    println!("Session: {} | Turn: {}", cli.session, metrics.turn);
                    println!("Objective: {}", ledger["objective"].as_str().unwrap_or("None"));
                    println!("\n--- Metrics & Cache Invariants ---");
                    println!("Working Context Size:    {} tokens (Bounded)", metrics.current_working_tokens);
                    println!("Estimated Cache Hit Rate:{}% (Prefix Pinned)", metrics.estimated_cache_hit_pct);
                    println!("Total Tokens Saved:      {} ({}%)", metrics.tokens_saved, metrics.reduction_pct);
                    println!("Epistemic Traps Caught:  {}", metrics.epistemic_traps_intercepted);
                    println!("FTS5 Swapped Pages:      {} ({} bytes)", metrics.swapped_pages, metrics.swapped_bytes);

                    if let Some(constraints) = ledger["active_constraints"].as_array() {
                        if !constraints.is_empty() {
                            println!("\n--- Active Constraints (Invariants) ---");
                            for c in constraints {
                                println!("  * [INVARIANT] {}", c.as_str().unwrap_or(""));
                            }
                        }
                    }

                    if let Some(dead_ends) = ledger["dead_ends"].as_array() {
                        if !dead_ends.is_empty() {
                            println!("\n--- Known Dead Ends ---");
                            for de in dead_ends {
                                println!("  * [AVOID] {}", de.as_str().unwrap_or(""));
                            }
                        }
                    }

                    if let Some(dirty) = ledger["dirty_files"].as_array() {
                        if !dirty.is_empty() {
                            println!("\n--- Modified Files (SHA-256 Anchored) ---");
                            for df in dirty {
                                println!(
                                    "  * {} ({}) - sha:{}",
                                    df["path"].as_str().unwrap_or(""),
                                    df["status"].as_str().unwrap_or(""),
                                    df["sha256"].as_str().unwrap_or("")
                                );
                            }
                        }
                    }

                    if let Some(facts) = ledger["verified_facts"].as_array() {
                        if !facts.is_empty() {
                            println!("\n--- Verified Facts ---");
                            for f in facts {
                                println!("  * {}", f.as_str().unwrap_or(""));
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading status: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Sieve { cmd } => {
            if cmd.is_empty() {
                eprintln!("Error: No command specified to run.");
                exit(1);
            }

            let mut mmu = match AgentMMU::new(".", &cli.session, "") {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error initializing AgentMMU: {}", e);
                    exit(1);
                }
            };
            let _ = mmu.advance_turn();

            // Execute directly to eliminate shell injection vulnerabilities
            let output = if cmd.len() == 1 && (cmd[0].contains('|') || cmd[0].contains('&') || cmd[0].contains('>')) {
                Command::new("sh").arg("-c").arg(&cmd[0]).output()
            } else {
                Command::new(&cmd[0]).args(&cmd[1..]).output()
            };

            let (stdout, stderr, exit_code) = match output {
                Ok(out) => (
                    String::from_utf8_lossy(&out.stdout).to_string(),
                    String::from_utf8_lossy(&out.stderr).to_string(),
                    out.status.code().unwrap_or(-1),
                ),
                Err(e) => {
                    eprintln!("Failed to execute '{}': {}", cmd[0], e);
                    exit(1);
                }
            };

            let cmd_str = cmd.join(" ");
            let res = match mmu.process_tool_output(
                "bash",
                &stdout,
                &stderr,
                exit_code,
                &cmd_str,
                None,
                None,
                None,
            ) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error processing output through MMU: {}", e);
                    exit(1);
                }
            };

            println!("{}", res.sieved_text);
            eprintln!(
                "\n[AgentMMU Sieve: Saved {} tokens ({}% reduction) | Exit: {}]",
                res.tokens_saved, res.reduction_pct, exit_code
            );
            if res.has_trap {
                eprintln!("[TRAP INTERCEPTED: {}]", res.trap_message);
            }

            exit(exit_code);
        }
        Commands::Page { query, limit } => {
            let mmu = match AgentMMU::new(".", &cli.session, "") {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error initializing AgentMMU: {}", e);
                    exit(1);
                }
            };
            match mmu.page_in_evidence(&query, limit) {
                Ok(results) => {
                    if results.is_empty() {
                        println!("No historical matches found for query: '{}'", query);
                    } else {
                        println!("Found {} matches in episodic swap:", results.len());
                        for (i, r) in results.iter().enumerate() {
                            println!("\n[{}] Turn {} | Role: {} | Tool: {}", i + 1, r.turn, r.role, r.tool_name);
                            println!("    Excerpt: {}", r.excerpt);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Paging error: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Prompt { message } => {
            let mmu = match AgentMMU::new(".", &cli.session, "") {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error initializing AgentMMU: {}", e);
                    exit(1);
                }
            };
            match mmu.render_prompt_frame("", &message) {
                Ok(prompt) => println!("{}", prompt),
                Err(e) => {
                    eprintln!("Error rendering prompt: {}", e);
                    exit(1);
                }
            }
        }
        Commands::Audit {
            trajectory,
            json,
            tsv,
            threshold,
        } => {
            let path_str = match trajectory {
                Some(p) => p,
                None => {
                    if std::path::Path::new("transcript.jsonl").exists() {
                        "transcript.jsonl".to_string()
                    } else if std::path::Path::new(".agent_mmu/transcript.jsonl").exists() {
                        ".agent_mmu/transcript.jsonl".to_string()
                    } else {
                        eprintln!("Error: No trajectory file specified and no default 'transcript.jsonl' found.");
                        eprintln!("Usage: agent-mmu audit <path/to/trajectory.jsonl> [--json] [--tsv] [--threshold 4.0]");
                        exit(1);
                    }
                }
            };

            let auditor = agent_mmu::TrajectoryAuditor::new();
            let report = match auditor.audit_file(&path_str) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to audit trajectory '{}': {}", path_str, e);
                    exit(1);
                }
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
                println!("║               🛡️  AGENT-MMU T4 SWE BENCHMARK AUDIT REPORT                    ║");
                println!("╚══════════════════════════════════════════════════════════════════════════════╝");
                println!("Trajectory: {}", report.trajectory_path);
                println!("Verdict:    {}", report.verdict);
                println!("SQS Score:  {:.2} / 5.00", report.sqs_score);
                println!("Turns:      {} | Executed Tool Calls: {}", report.total_turns, report.total_tool_calls);
                println!("\n┌────────────────────────────┬───────┬─────────────────────────────────────────┐");
                println!("│ Anomaly Metric             │ Count │ Benchmark Penalty                       │");
                println!("├────────────────────────────┼───────┼─────────────────────────────────────────┤");
                println!("│ Ghost Actions              │ {:^5} │ -1.50 per occurrence (Critical)         │", report.ghost_action_count);
                println!("│ Masked Failures            │ {:^5} │ -1.00 per occurrence (Critical)         │", report.masked_failure_count);
                println!("│ Circular Loops             │ {:^5} │ -0.75 per occurrence                    │", report.circular_loop_count);
                println!("│ Context Bloats (>2.5k tok) │ {:^5} │ -0.25 per occurrence                    │", report.context_bloat_count);
                println!("│ Unverified Completions     │ {:^5} │ -0.50 per occurrence                    │", report.unverified_completion_count);
                println!("└────────────────────────────┴───────┴─────────────────────────────────────────┘");
                println!(
                    "Context Tokens: ~{} raw -> ~{} sieved ({:.1}% reduction)",
                    report.total_raw_tokens_est, report.total_sieved_tokens_est, report.potential_savings_pct
                );

                if !report.anomalies.is_empty() {
                    println!("\n⚠️  DETAILED ANOMALIES INTERCEPTED:");
                    for (i, a) in report.anomalies.iter().enumerate() {
                        println!("  [{}] Turn {}: [{}] {}", i + 1, a.turn, a.anomaly_type, a.description);
                        if !a.evidence.is_empty() {
                            let excerpt: String = a.evidence.chars().take(80).collect();
                            println!("      Evidence: \"{}\"", excerpt);
                        }
                    }
                } else {
                    println!("\n✅ ZERO ANOMALIES DETECTED. Trajectory satisfies 100% of T4 SWE Grounding Invariants.");
                }
            }

            if tsv {
                use std::io::Write;
                let tsv_file = "results.tsv";
                let exists = std::path::Path::new(tsv_file).exists();
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(tsv_file) {
                    if !exists {
                        let _ = writeln!(
                            f,
                            "timestamp\ttrajectory\tturns\ttools\tsqs\tghosts\tmasked\tloops\tbloats\tunverified\tsavings\tverdict"
                        );
                    }
                    let _ = writeln!(f, "{}", report.to_tsv_row());
                    eprintln!("[Benchmark Metric appended to {}]", tsv_file);
                }
            }

            if let Some(th) = threshold {
                if report.sqs_score < th {
                    eprintln!(
                        "\n[GATING FAILURE] SQS score {:.2} is below required threshold {:.2}!",
                        report.sqs_score, th
                    );
                    exit(1);
                }
            }
        }
        Commands::Scan {
            target,
            json,
            threshold,
        } => {
            let scanner = agent_mmu::SkillSpectre::new();
            let report = match scanner.scan_target(&target) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to scan target '{}': {}", target, e);
                    exit(1);
                }
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else {
                println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
                println!("║         🛡️  SKILLSPECTRE AGENT SECURITY SCANNER (NVIDIA-ALIGNED)              ║");
                println!("╚══════════════════════════════════════════════════════════════════════════════╝");
                println!("Target:        {}", report.target);
                println!("Files Scanned: {}", report.total_files_scanned);
                println!("Risk Score:    {}/100", report.risk_score);
                println!("Verdict:       {}", report.verdict);
                println!("\n┌────────────────────────────┬───────┬─────────────────────────────────────────┐");
                println!("│ Severity Level             │ Count │ Risk Penalty                            │");
                println!("├────────────────────────────┼───────┼─────────────────────────────────────────┤");
                println!("│ CRITICAL                   │ {:^5} │ +35 pts (Active Exploit / Block)        │", report.critical_count);
                println!("│ HIGH                       │ {:^5} │ +20 pts (Dangerous Code / Exfil Risk)   │", report.high_count);
                println!("│ MEDIUM                     │ {:^5} │ +10 pts (Privilege / Permission Warning)│", report.medium_count);
                println!("│ LOW                        │ {:^5} │ +5 pts  (Minor Lint / Anomaly)          │", report.low_count);
                println!("└────────────────────────────┴───────┴─────────────────────────────────────────┘");

                if !report.findings.is_empty() {
                    println!("\n⚠️  DETAILED VULNERABILITIES DETECTED:");
                    for (i, f) in report.findings.iter().enumerate() {
                        println!("  [{}] {}:{} [{}] {}", i + 1, f.file_path, f.line_number, f.rule_id, f.message);
                        if !f.snippet.is_empty() {
                            let excerpt: String = f.snippet.chars().take(80).collect();
                            println!("      Match: \"{}\"", excerpt);
                        }
                    }
                } else {
                    println!("\n✅ ZERO VULNERABILITIES DETECTED. Skill conforms 100% to Agent Invariant Standards.");
                }
            }

            if let Some(th) = threshold {
                if report.risk_score >= th {
                    eprintln!(
                        "\n[GATING FAILURE] Risk score {} met or exceeded threshold {}! Installation blocked.",
                        report.risk_score, th
                    );
                    exit(1);
                }
            }
        }
        Commands::Mcp => {
            let mut server = match MCPServer::new() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Failed to initialize MCP Server: {}", e);
                    exit(1);
                }
            };
            if let Err(e) = server.run_stdio() {
                eprintln!("MCP Server error: {}", e);
                exit(1);
            }
        }
    }
}
