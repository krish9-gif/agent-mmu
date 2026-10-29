"""Virtual Context Pager (Layer 3).

Episodic Swap Space backed by SQLite FTS5 (Full-Text Search).
Enables lossless historical recall via sub-token pointers without polluting
or saturating the active working context buffer. Zero dependencies.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any, Dict, List, Optional


class ContextPager:
    """SQLite FTS5 Episodic Swap File for Agent Context Recall."""

    def __init__(self, db_path: str = ":memory:", session_id: str = "default_session"):
        self.db_path = db_path
        self.session_id = session_id
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create full-text search virtual table and raw episodic storage."""
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS episodic_raw (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    turn INTEGER NOT NULL,
                    role TEXT NOT NULL,          -- 'user', 'assistant', 'tool'
                    tool_name TEXT DEFAULT '',
                    raw_content TEXT NOT NULL,
                    sieved_content TEXT DEFAULT '',
                    created_at REAL NOT NULL
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS episodic_fts USING fts5(
                    turn UNINDEXED,
                    role,
                    tool_name,
                    content,
                    tokenize = 'porter unicode61'
                );
                """
            )
            conn.commit()

    def page_out(
        self,
        turn: int,
        role: str,
        content: str,
        tool_name: str = "",
        sieved_content: str = "",
    ) -> int:
        """Page out historical turn content to disk and index in FTS5."""
        now = time.time()
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO episodic_raw (session_id, turn, role, tool_name, raw_content, sieved_content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (self.session_id, turn, role, tool_name, content, sieved_content, now),
            )
            raw_id = cur.lastrowid

            # Index in FTS5
            fts_content = sieved_content if sieved_content else content
            conn.execute(
                """
                INSERT INTO episodic_fts (rowid, turn, role, tool_name, content)
                VALUES (?, ?, ?, ?, ?)
                """,
                (raw_id, turn, role, tool_name, fts_content),
            )
            conn.commit()
            return raw_id or 0

    def page_in_evidence(
        self,
        query: str,
        limit: int = 3,
        snippet_chars: int = 400,
    ) -> List[Dict[str, Any]]:
        """Search historical swap space using FTS5 BM25 ranking.

        Returns high-signal excerpts with exact turn numbers and tool names.
        """
        clean_q = query.replace('"', '""').strip()
        if not clean_q:
            return []

        # Safe phrase matching or individual terms
        terms = [t for t in clean_q.split() if t.isalnum()]
        if not terms:
            return []
        match_query = " OR ".join(f'"{t}"' for t in terms)

        results: List[Dict[str, Any]] = []
        with self._get_connection() as conn:
            try:
                cur = conn.execute(
                    """
                    SELECT rowid, turn, role, tool_name,
                           snippet(episodic_fts, 3, '[MATCH]', '[/MATCH]', '...', 25) AS excerpt,
                           content
                    FROM episodic_fts
                    WHERE episodic_fts MATCH ?
                    ORDER BY bm25(episodic_fts)
                    LIMIT ?
                    """,
                    (match_query, limit),
                )
                for row in cur.fetchall():
                    results.append(
                        {
                            "rowid": row["rowid"],
                            "turn": row["turn"],
                            "role": row["role"],
                            "tool_name": row["tool_name"],
                            "excerpt": row["excerpt"],
                            "full_text": row["content"][:snippet_chars],
                        }
                    )
            except sqlite3.OperationalError:
                # Fallback to LIKE if FTS query syntax fails on special chars
                like_cur = conn.execute(
                    """
                    SELECT id AS rowid, turn, role, tool_name, raw_content AS content
                    FROM episodic_raw
                    WHERE session_id = ? AND raw_content LIKE ?
                    ORDER BY turn DESC
                    LIMIT ?
                    """,
                    (self.session_id, f"%{clean_q}%", limit),
                )
                for row in like_cur.fetchall():
                    results.append(
                        {
                            "rowid": row["rowid"],
                            "turn": row["turn"],
                            "role": row["role"],
                            "tool_name": row["tool_name"],
                            "excerpt": row["content"][:snippet_chars],
                            "full_text": row["content"][:snippet_chars],
                        }
                    )
        return results

    def get_turn(self, turn: int) -> List[Dict[str, Any]]:
        """Fetch all raw events for a specific historical turn."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, turn, role, tool_name, raw_content, sieved_content, created_at
                FROM episodic_raw
                WHERE session_id = ? AND turn = ?
                ORDER BY id ASC
                """,
                (self.session_id, turn),
            )
            return [dict(r) for r in cur.fetchall()]

    def stats(self) -> Dict[str, Any]:
        """Return memory swap statistics."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS total_pages, SUM(LENGTH(raw_content)) AS raw_bytes FROM episodic_raw WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            total_pages = row["total_pages"] if row else 0
            raw_bytes = row["raw_bytes"] if row and row["raw_bytes"] else 0
            return {
                "total_pages": total_pages,
                "raw_bytes": raw_bytes,
                "estimated_tokens_swapped": max(1, raw_bytes // 4) if raw_bytes else 0,
            }
