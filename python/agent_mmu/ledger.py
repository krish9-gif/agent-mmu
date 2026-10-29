"""Deterministic State Ledger (Layer 1).

A schema-enforced, zero-LLM-overhead SQLite state machine representing the agent's
authoritative working memory. Bounded to <=1,200 tokens regardless of trajectory length.
Zero dependencies (uses Python standard library sqlite3).
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class DirtyFile:
    path: str
    inode: int
    sha256_before: str
    sha256_after: str
    status: str  # 'created', 'modified', 'deleted'


@dataclass
class Hypothesis:
    id: int
    description: str
    status: str  # 'ACTIVE', 'VERIFIED', 'REFUTED'
    outcome: str = ""


class StateLedger:
    """Deterministic SQLite State Machine for Agent Working Memory."""

    def __init__(self, db_path: str = ":memory:", session_id: str = "default_session", objective: str = ""):
        self.db_path = db_path
        self.session_id = session_id
        self._init_db()
        if objective:
            self.set_objective(objective)

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initialize relational tables for state ledger."""
        with self._get_connection() as conn:
            conn.executescript(
                """
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
                    status TEXT DEFAULT 'ACTIVE', -- ACTIVE, VERIFIED, REFUTED
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
                """
            )
            # Ensure session_meta row exists
            now = time.time()
            conn.execute(
                """
                INSERT OR IGNORE INTO session_meta (session_id, turn, objective, created_at, updated_at)
                VALUES (?, 0, '', ?, ?)
                """,
                (self.session_id, now, now),
            )
            conn.commit()

    def advance_turn(self) -> int:
        """Advance session turn counter."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE session_meta SET turn = turn + 1, updated_at = ? WHERE session_id = ?",
                (now, self.session_id),
            )
            cur = conn.execute("SELECT turn FROM session_meta WHERE session_id = ?", (self.session_id,))
            row = cur.fetchone()
            conn.commit()
            return int(row["turn"]) if row else 1

    def get_turn(self) -> int:
        """Get current turn number."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT turn FROM session_meta WHERE session_id = ?", (self.session_id,))
            row = cur.fetchone()
            return int(row["turn"]) if row else 0

    def set_objective(self, objective: str) -> None:
        """Set the overarching task objective."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE session_meta SET objective = ?, updated_at = ? WHERE session_id = ?",
                (objective.strip(), now, self.session_id),
            )
            conn.commit()

    def add_fact(self, fact: str) -> None:
        """Add an empirically verified fact."""
        fact_clean = fact.strip()
        if not fact_clean:
            return
        turn = self.get_turn()
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO verified_facts (fact, turn, created_at) VALUES (?, ?, ?)",
                (fact_clean, turn, now),
            )
            conn.commit()

    def record_dirty_file(
        self,
        path: str,
        inode: int,
        sha256_before: str,
        sha256_after: str,
        status: str = "modified",
    ) -> None:
        """Record or update a modified file in the ledger."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dirty_files (path, inode, sha256_before, sha256_after, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (path.strip(), inode, sha256_before, sha256_after, status, now),
            )
            conn.commit()

    def propose_hypothesis(self, description: str) -> int:
        """Propose a new hypothesis or planned approach."""
        turn = self.get_turn()
        with self._get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO hypotheses (description, status, turn) VALUES (?, 'ACTIVE', ?)",
                (description.strip(), turn),
            )
            conn.commit()
            return cur.lastrowid or 0

    def resolve_hypothesis(self, hyp_id: int, status: str, outcome: str = "") -> None:
        """Resolve a hypothesis (VERIFIED or REFUTED)."""
        valid_statuses = {"ACTIVE", "VERIFIED", "REFUTED"}
        st = status.upper()
        if st not in valid_statuses:
            raise ValueError(f"Invalid hypothesis status: {status}. Must be one of {valid_statuses}")
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE hypotheses SET status = ?, outcome = ? WHERE id = ?",
                (st, outcome.strip(), hyp_id),
            )
            conn.commit()

    def add_dead_end(self, anti_pattern: str, reason: str = "") -> None:
        """Record a prohibited path or dead end to prevent repeating mistakes."""
        turn = self.get_turn()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dead_ends (anti_pattern, reason, turn) VALUES (?, ?, ?)",
                (anti_pattern.strip(), reason.strip(), turn),
            )
            conn.commit()

    def add_constraint(self, rule: str, is_negative: bool = True) -> None:
        """Record an active invariant or negative constraint (e.g. 'Never delete schema.sql')."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO active_constraints (constraint_rule, is_negative) VALUES (?, ?)",
                (rule.strip(), 1 if is_negative else 0),
            )
            conn.commit()

    def to_dict(self) -> Dict[str, Any]:
        """Export ledger as a structured dictionary."""
        with self._get_connection() as conn:
            s_row = conn.execute(
                "SELECT session_id, turn, objective FROM session_meta WHERE session_id = ?",
                (self.session_id,),
            ).fetchone()
            facts = [r["fact"] for r in conn.execute("SELECT fact FROM verified_facts ORDER BY id DESC LIMIT 15")]
            dirty = [
                {
                    "path": r["path"],
                    "status": r["status"],
                    "sha256": r["sha256_after"][:8] + "...",
                }
                for r in conn.execute("SELECT path, status, sha256_after FROM dirty_files ORDER BY updated_at DESC LIMIT 10")
            ]
            hypotheses = [
                {
                    "id": r["id"],
                    "description": r["description"],
                    "status": r["status"],
                    "outcome": r["outcome"],
                }
                for r in conn.execute("SELECT id, description, status, outcome FROM hypotheses ORDER BY id DESC LIMIT 8")
            ]
            dead_ends = [
                f"{r['anti_pattern']} ({r['reason']})" if r["reason"] else r["anti_pattern"]
                for r in conn.execute("SELECT anti_pattern, reason FROM dead_ends ORDER BY id DESC LIMIT 10")
            ]
            constraints = [
                r["constraint_rule"]
                for r in conn.execute("SELECT constraint_rule FROM active_constraints ORDER BY id ASC")
            ]

        return {
            "session_id": s_row["session_id"] if s_row else self.session_id,
            "turn": s_row["turn"] if s_row else 0,
            "objective": s_row["objective"] if s_row else "",
            "verified_facts": facts,
            "dirty_files": dirty,
            "hypotheses": hypotheses,
            "dead_ends": dead_ends,
            "active_constraints": constraints,
        }

    def render_markdown(self, max_tokens: int = 1200) -> str:
        """Render bounded markdown representation for direct prompt injection ($Z_1$)."""
        data = self.to_dict()
        lines: List[str] = [
            f"### [AGENT_MMU_STATE_LEDGER (Turn {data['turn']})]",
            f"**Objective:** {data['objective'] or 'Not specified'}",
        ]

        if data["active_constraints"]:
            lines.append("\n**Active Invariant Constraints (DO NOT VIOLATE):**")
            for c in data["active_constraints"]:
                lines.append(f"- [INVARIANT] {c}")

        if data["dead_ends"]:
            lines.append("\n**Known Dead Ends (DO NOT REPEAT):**")
            for de in data["dead_ends"]:
                lines.append(f"- [AVOID] {de}")

        if data["verified_facts"]:
            lines.append("\n**Verified Empirical Facts:**")
            for f in data["verified_facts"]:
                lines.append(f"- {f}")

        if data["dirty_files"]:
            lines.append("\n**Modified Files (Anchored by SHA-256):**")
            for df in data["dirty_files"]:
                lines.append(f"- `{df['path']}` ({df['status']}, sha:{df['sha256']})")

        if data["hypotheses"]:
            lines.append("\n**Hypothesis Tracking:**")
            for h in data["hypotheses"]:
                st = h["status"]
                out = f" -> {h['outcome']}" if h["outcome"] else ""
                lines.append(f"- #{h['id']} [{st}]: {h['description']}{out}")

        rendered = "\n".join(lines)
        # Cap strictly at max_tokens (~4 chars per token)
        max_chars = max_tokens * 4
        if len(rendered) > max_chars:
            rendered = rendered[:max_chars - 50] + "\n... [Ledger truncated to stay within MMU budget]"
        return rendered
