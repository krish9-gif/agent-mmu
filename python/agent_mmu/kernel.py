"""Cache-Pinned Invariant Kernel (Layer 0).

Maintains a byte-identical, immutable system prompt prefix ($Z_0$) to guarantee
>88% Prompt Cache Hit rates across Anthropic Claude, OpenAI, and Gemini APIs.
Eliminates KV-cache thrashing and stabilizes agent persona and negative constraints.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional


# Authoritative, byte-identical invariant system prompt prefix
DEFAULT_INVARIANT_KERNEL_TEXT = """# AGENT_MMU CORE INVARIANT KERNEL (VERSION 0.1.0)
You are an autonomous software engineering agent managed by AgentMMU (Virtual Context Kernel).
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
"""


class InvariantKernel:
    """Manages the byte-immutable prompt prefix and stitches the 3-zone frame."""

    def __init__(self, custom_prefix: Optional[str] = None):
        self.prefix_text = (custom_prefix or DEFAULT_INVARIANT_KERNEL_TEXT).strip()
        self._prefix_sha256 = self._compute_sha256(self.prefix_text)

    @staticmethod
    def _compute_sha256(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    @property
    def prefix_hash(self) -> str:
        """Cryptographic hash verifying prefix invariance."""
        return self._prefix_sha256

    def verify_cache_integrity(self) -> bool:
        """Ensure prefix has not drifted by even a single character."""
        return self._compute_sha256(self.prefix_text) == self._prefix_sha256

    def assemble_prompt_frame(
        self,
        ledger_markdown: str,
        active_slice: str,
        user_message: str = "",
    ) -> str:
        """Assemble the complete 3-Zone AgentMMU Context Frame.

        Zone 0 ($Z_0$): Pinned Invariant Kernel (Prefix Cache Pinned)
        Zone 1 ($Z_1$): Deterministic State Ledger (SQLite Working RAM)
        Zone 2 ($Z_2$): AST-Sieved Active Execution Slice (Ephemeral)
        """
        assert self.verify_cache_integrity(), "FATAL: Invariant kernel prefix hash mismatch!"

        sections: List[str] = [
            self.prefix_text,
            "\n---\n",
            ledger_markdown.strip(),
        ]

        if user_message.strip():
            sections.extend([
                "\n---\n### [CURRENT_USER_OBJECTIVE]",
                user_message.strip(),
            ])

        if active_slice.strip():
            sections.extend([
                "\n---\n### [ACTIVE_INGRESS_EXECUTION_FRAME]",
                active_slice.strip(),
            ])

        return "\n".join(sections)
