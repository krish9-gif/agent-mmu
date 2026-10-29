//! Layer 1: Deterministic State Ledger
//!
//! Schema-enforced, zero-LLM-overhead SQLite state machine representing
//! the agent's authoritative working memory. Bounded to <=1,200 tokens.

use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirtyFile {
    pub path: String,
    pub inode: i64,
    pub sha256_before: String,
    pub sha256_after: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: i64,
    pub description: String,
    pub status: String,
    pub outcome: String,
}

pub struct StateLedger {
    conn: Connection,
    session_id: String,
}

impl StateLedger {
    pub fn new_in_memory(session_id: &str, objective: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut ledger = Self {
            conn,
            session_id: session_id.to_string(),
        };
        ledger.init_schema()?;
        if !objective.is_empty() {
            ledger.set_objective(objective)?;
        }
        Ok(ledger)
    }

    pub fn new_file(path: &str, session_id: &str, objective: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let mut ledger = Self {
            conn,
            session_id: session_id.to_string(),
        };
        ledger.init_schema()?;
        if !objective.is_empty() {
            ledger.set_objective(objective)?;
        }
        Ok(ledger)
    }

    fn init_schema(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS session_meta (
                session_id TEXT PRIMARY KEY,
                turn INTEGER DEFAULT 0,
                objective TEXT DEFAULT '',
                created_at REAL,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS verified_facts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fact TEXT UNIQUE NOT NULL,
                turn INTEGER,
                created_at REAL
            );

            CREATE TABLE IF NOT EXISTS dirty_files (
                path TEXT PRIMARY KEY,
                inode INTEGER,
                sha256_before TEXT,
                sha256_after TEXT,
                status TEXT,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS hypotheses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                status TEXT DEFAULT 'ACTIVE',
                outcome TEXT DEFAULT '',
                turn INTEGER
            );

            CREATE TABLE IF NOT EXISTS dead_ends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                anti_pattern TEXT UNIQUE NOT NULL,
                reason TEXT,
                turn INTEGER
            );

            CREATE TABLE IF NOT EXISTS active_constraints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                constraint_rule TEXT UNIQUE NOT NULL,
                is_negative BOOLEAN DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_dirty_files_updated ON dirty_files(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_verified_facts_id ON verified_facts(id DESC);
            CREATE INDEX IF NOT EXISTS idx_hypotheses_id ON hypotheses(id DESC);
            "#,
        )?;

        let now = now_secs();
        self.conn.execute(
            "INSERT OR IGNORE INTO session_meta (session_id, turn, objective, created_at, updated_at) VALUES (?1, 0, '', ?2, ?3)",
            params![self.session_id, now, now],
        )?;

        Ok(())
    }

    pub fn advance_turn(&self) -> Result<i64> {
        let now = now_secs();
        self.conn.execute(
            "UPDATE session_meta SET turn = turn + 1, updated_at = ?1 WHERE session_id = ?2",
            params![now, self.session_id],
        )?;
        self.get_turn()
    }

    pub fn get_turn(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT turn FROM session_meta WHERE session_id = ?1")?;
        let turn = stmt.query_row(params![self.session_id], |row| row.get(0)).unwrap_or(0);
        Ok(turn)
    }

    pub fn set_objective(&self, objective: &str) -> Result<()> {
        let now = now_secs();
        self.conn.execute(
            "UPDATE session_meta SET objective = ?1, updated_at = ?2 WHERE session_id = ?3",
            params![objective.trim(), now, self.session_id],
        )?;
        Ok(())
    }

    pub fn add_fact(&self, fact: &str) -> Result<()> {
        let fact_clean = fact.trim();
        if fact_clean.is_empty() {
            return Ok(());
        }
        let turn = self.get_turn()?;
        let now = now_secs();
        self.conn.execute(
            "INSERT OR REPLACE INTO verified_facts (fact, turn, created_at) VALUES (?1, ?2, ?3)",
            params![fact_clean, turn, now],
        )?;
        Ok(())
    }

    pub fn record_dirty_file(
        &self,
        path: &str,
        inode: i64,
        sha256_before: &str,
        sha256_after: &str,
        status: &str,
    ) -> Result<()> {
        let now = now_secs();
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO dirty_files (path, inode, sha256_before, sha256_after, status, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![path.trim(), inode, sha256_before, sha256_after, status, now],
        )?;
        Ok(())
    }

    pub fn propose_hypothesis(&self, description: &str) -> Result<i64> {
        let turn = self.get_turn()?;
        self.conn.execute(
            "INSERT INTO hypotheses (description, status, turn) VALUES (?1, 'ACTIVE', ?2)",
            params![description.trim(), turn],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn resolve_hypothesis(&self, id: i64, status: &str, outcome: &str) -> Result<()> {
        let st = status.to_uppercase();
        let valid_status = match st.as_str() {
            "ACTIVE" | "VERIFIED" | "REFUTED" => &st,
            _ => "REFUTED",
        };
        self.conn.execute(
            "UPDATE hypotheses SET status = ?1, outcome = ?2 WHERE id = ?3",
            params![valid_status, outcome.trim(), id],
        )?;
        Ok(())
    }

    pub fn add_dead_end(&self, anti_pattern: &str, reason: &str) -> Result<()> {
        let turn = self.get_turn()?;
        self.conn.execute(
            "INSERT OR REPLACE INTO dead_ends (anti_pattern, reason, turn) VALUES (?1, ?2, ?3)",
            params![anti_pattern.trim(), reason.trim(), turn],
        )?;
        Ok(())
    }

    pub fn add_constraint(&self, rule: &str, is_negative: bool) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO active_constraints (constraint_rule, is_negative) VALUES (?1, ?2)",
            params![rule.trim(), is_negative],
        )?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<serde_json::Value> {
        let turn = self.get_turn()?;
        let mut obj_stmt = self.conn.prepare("SELECT objective FROM session_meta WHERE session_id = ?1")?;
        let objective: String = obj_stmt.query_row(params![self.session_id], |r| r.get(0)).unwrap_or_default();

        let mut facts_stmt = self.conn.prepare("SELECT fact FROM verified_facts ORDER BY id DESC LIMIT 15")?;
        let facts: Vec<String> = facts_stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();

        let mut files_stmt = self.conn.prepare("SELECT path, status, sha256_after FROM dirty_files ORDER BY updated_at DESC LIMIT 10")?;
        let dirty: Vec<serde_json::Value> = files_stmt.query_map([], |r| {
            let path: String = r.get(0)?;
            let status: String = r.get(1)?;
            let sha: String = r.get(2)?;
            let short_sha = if sha.len() >= 8 { format!("{}...", &sha[..8]) } else { sha };
            Ok(serde_json::json!({ "path": path, "status": status, "sha256": short_sha }))
        })?.filter_map(|r| r.ok()).collect();

        let mut hyp_stmt = self.conn.prepare("SELECT id, description, status, outcome FROM hypotheses ORDER BY id DESC LIMIT 8")?;
        let hypotheses: Vec<serde_json::Value> = hyp_stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "id": r.get::<_, i64>(0)?,
                "description": r.get::<_, String>(1)?,
                "status": r.get::<_, String>(2)?,
                "outcome": r.get::<_, String>(3)?
            }))
        })?.filter_map(|r| r.ok()).collect();

        let mut de_stmt = self.conn.prepare("SELECT anti_pattern, reason FROM dead_ends ORDER BY id DESC LIMIT 10")?;
        let dead_ends: Vec<String> = de_stmt.query_map([], |r| {
            let ap: String = r.get(0)?;
            let reason: String = r.get(1)?;
            if reason.is_empty() { Ok(ap) } else { Ok(format!("{} ({})", ap, reason)) }
        })?.filter_map(|r| r.ok()).collect();

        let mut constr_stmt = self.conn.prepare("SELECT constraint_rule FROM active_constraints ORDER BY id ASC")?;
        let constraints: Vec<String> = constr_stmt.query_map([], |r| r.get(0))?.filter_map(|r| r.ok()).collect();

        Ok(serde_json::json!({
            "session_id": self.session_id,
            "turn": turn,
            "objective": objective,
            "verified_facts": facts,
            "dirty_files": dirty,
            "hypotheses": hypotheses,
            "dead_ends": dead_ends,
            "active_constraints": constraints,
        }))
    }

    pub fn render_markdown(&self, max_tokens: usize) -> Result<String> {
        let data = self.to_json()?;
        let turn = data["turn"].as_i64().unwrap_or(0);
        let objective = data["objective"].as_str().unwrap_or("Not specified");

        let mut lines = vec![
            format!("### [AGENT_MMU_STATE_LEDGER (Turn {})]", turn),
            format!("**Objective:** {}", objective),
        ];

        if let Some(constraints) = data["active_constraints"].as_array() {
            if !constraints.is_empty() {
                lines.push("\n**Active Invariant Constraints (DO NOT VIOLATE):**".to_string());
                for c in constraints {
                    if let Some(s) = c.as_str() {
                        lines.push(format!("- [INVARIANT] {}", s));
                    }
                }
            }
        }

        if let Some(dead_ends) = data["dead_ends"].as_array() {
            if !dead_ends.is_empty() {
                lines.push("\n**Known Dead Ends (DO NOT REPEAT):**".to_string());
                for de in dead_ends {
                    if let Some(s) = de.as_str() {
                        lines.push(format!("- [AVOID] {}", s));
                    }
                }
            }
        }

        if let Some(facts) = data["verified_facts"].as_array() {
            if !facts.is_empty() {
                lines.push("\n**Verified Empirical Facts:**".to_string());
                for f in facts {
                    if let Some(s) = f.as_str() {
                        lines.push(format!("- {}", s));
                    }
                }
            }
        }

        if let Some(dirty) = data["dirty_files"].as_array() {
            if !dirty.is_empty() {
                lines.push("\n**Modified Files (Anchored by SHA-256):**".to_string());
                for df in dirty {
                    let path = df["path"].as_str().unwrap_or("");
                    let status = df["status"].as_str().unwrap_or("");
                    let sha = df["sha256"].as_str().unwrap_or("");
                    lines.push(format!("- `{}` ({}, sha:{})", path, status, sha));
                }
            }
        }

        if let Some(hypotheses) = data["hypotheses"].as_array() {
            if !hypotheses.is_empty() {
                lines.push("\n**Hypothesis Tracking:**".to_string());
                for h in hypotheses {
                    let id = h["id"].as_i64().unwrap_or(0);
                    let desc = h["description"].as_str().unwrap_or("");
                    let status = h["status"].as_str().unwrap_or("");
                    let outcome = h["outcome"].as_str().unwrap_or("");
                    let out_str = if outcome.is_empty() { "".to_string() } else { format!(" -> {}", outcome) };
                    lines.push(format!("- #{} [{}]: {}{}", id, status, desc, out_str));
                }
            }
        }

        let mut rendered = lines.join("\n");
        let max_chars = max_tokens * 4;
        if rendered.len() > max_chars {
            let target = max_chars.saturating_sub(60);
            let mut cut = target;
            while cut > 0 && !rendered.is_char_boundary(cut) {
                cut -= 1;
            }
            rendered.truncate(cut);
            rendered.push_str("\n... [Ledger bounded by MMU budget]");
        }

        Ok(rendered)
    }
}
