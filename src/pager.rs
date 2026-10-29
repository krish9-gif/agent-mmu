//! Layer 3: Virtual Context Pager
//!
//! SQLite FTS5 Episodic Swap Space. Enables lossless historical recall
//! via sub-token pointers without polluting or saturating active context.

use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if max_bytes >= s.len() {
        return s;
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagedEvidence {
    pub rowid: i64,
    pub turn: i64,
    pub role: String,
    pub tool_name: String,
    pub excerpt: String,
    pub full_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerStats {
    pub total_pages: i64,
    pub raw_bytes: i64,
    pub estimated_tokens_swapped: usize,
}

pub struct ContextPager {
    conn: Connection,
    session_id: String,
}

impl ContextPager {
    pub fn new_in_memory(session_id: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut pager = Self {
            conn,
            session_id: session_id.to_string(),
        };
        pager.init_tables()?;
        Ok(pager)
    }

    pub fn new_file(path: &str, session_id: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let mut pager = Self {
            conn,
            session_id: session_id.to_string(),
        };
        pager.init_tables()?;
        Ok(pager)
    }

    fn init_tables(&mut self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA synchronous = NORMAL;

            CREATE TABLE IF NOT EXISTS episodic_raw (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                turn INTEGER NOT NULL,
                role TEXT NOT NULL,
                tool_name TEXT DEFAULT '',
                raw_content TEXT NOT NULL,
                sieved_content TEXT DEFAULT '',
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_episodic_raw_session_turn ON episodic_raw(session_id, turn DESC);
            "#,
        )?;

        // Try creating FTS5 virtual table
        let _ = self.conn.execute_batch(
            r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS episodic_fts USING fts5(
                turn UNINDEXED,
                role,
                tool_name,
                content,
                tokenize = 'porter unicode61'
            );
            "#,
        );

        Ok(())
    }

    pub fn page_out(
        &self,
        turn: i64,
        role: &str,
        content: &str,
        tool_name: &str,
        sieved_content: &str,
    ) -> Result<i64> {
        let now = now_secs();
        self.conn.execute(
            r#"
            INSERT INTO episodic_raw (session_id, turn, role, tool_name, raw_content, sieved_content, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![self.session_id, turn, role, tool_name, content, sieved_content, now],
        )?;

        let raw_id = self.conn.last_insert_rowid();
        let fts_content = if sieved_content.is_empty() { content } else { sieved_content };

        let _ = self.conn.execute(
            "INSERT INTO episodic_fts (rowid, turn, role, tool_name, content) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![raw_id, turn, role, tool_name, fts_content],
        );

        Ok(raw_id)
    }

    pub fn page_in_evidence(&self, query: &str, limit: usize, snippet_chars: usize) -> Result<Vec<PagedEvidence>> {
        let clean_q = query.trim();
        if clean_q.is_empty() {
            return Ok(Vec::new());
        }

        // Try FTS5 query first
        let terms: Vec<String> = clean_q
            .split_whitespace()
            .filter(|w| w.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .map(|w| format!("\"{}\"", w))
            .collect();

        if !terms.is_empty() {
            let match_str = terms.join(" OR ");
            let fts_res = self.conn.prepare(
                r#"
                SELECT rowid, turn, role, tool_name,
                       snippet(episodic_fts, 3, '[MATCH]', '[/MATCH]', '...', 25) AS excerpt,
                       content
                FROM episodic_fts
                WHERE episodic_fts MATCH ?1
                ORDER BY bm25(episodic_fts)
                LIMIT ?2
                "#,
            );

            if let Ok(mut stmt) = fts_res {
                let evidence: Vec<PagedEvidence> = stmt
                    .query_map(params![match_str, limit as i64], |row| {
                        let full: String = row.get(5)?;
                        let trunc = safe_truncate(&full, snippet_chars);
                        Ok(PagedEvidence {
                            rowid: row.get(0)?,
                            turn: row.get(1)?,
                            role: row.get(2)?,
                            tool_name: row.get(3)?,
                            excerpt: row.get(4)?,
                            full_text: trunc.to_string(),
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();

                if !evidence.is_empty() {
                    return Ok(evidence);
                }
            }
        }

        // Fallback to LIKE search on episodic_raw with sanitized wildcards
        let mut like_stmt = self.conn.prepare(
            r#"
            SELECT id, turn, role, tool_name, raw_content
            FROM episodic_raw
            WHERE session_id = ?1 AND raw_content LIKE ?2 ESCAPE '\'
            ORDER BY turn DESC
            LIMIT ?3
            "#,
        )?;

        let sanitized_q = clean_q
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let pattern = format!("%{}%", sanitized_q);
        let results = like_stmt
            .query_map(params![self.session_id, pattern, limit as i64], |row| {
                let full: String = row.get(4)?;
                let trunc = safe_truncate(&full, snippet_chars);
                Ok(PagedEvidence {
                    rowid: row.get(0)?,
                    turn: row.get(1)?,
                    role: row.get(2)?,
                    tool_name: row.get(3)?,
                    excerpt: trunc.to_string(),
                    full_text: trunc.to_string(),
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(results)
    }

    pub fn stats(&self) -> Result<PagerStats> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(raw_content)), 0) FROM episodic_raw WHERE session_id = ?1",
        )?;
        let (total_pages, raw_bytes): (i64, i64) = stmt.query_row(params![self.session_id], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        Ok(PagerStats {
            total_pages,
            raw_bytes,
            estimated_tokens_swapped: (raw_bytes.max(0) as usize + 3) / 4,
        })
    }
}
