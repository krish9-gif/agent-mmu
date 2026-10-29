"""AgentMMU: Deterministic Memory Management Unit & Virtual Context Kernel.

Author: Krish Joshi (@krish9-gif)
License: Apache-2.0
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .gatekeeper import CryptographicGatekeeper, FileSnapshot
from .kernel import InvariantKernel
from .ledger import StateLedger
from .pager import ContextPager
from .sieve import ASTIngressSieve, estimate_tokens

__version__ = "0.1.0"
__all__ = [
    "AgentMMU",
    "StateLedger",
    "ASTIngressSieve",
    "ContextPager",
    "CryptographicGatekeeper",
    "InvariantKernel",
]


class AgentMMU:
    """Master Memory Management Unit orchestrating 4 memory layers for AI agents."""

    def __init__(
        self,
        workspace_dir: str = ".",
        session_id: str = "default_session",
        objective: str = "",
        db_path: Optional[str] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.session_id = session_id

        # Determine database location
        if db_path is None:
            mmu_dir = self.workspace_dir / ".agent_mmu"
            mmu_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(mmu_dir / f"mmu_{session_id}.db")
        else:
            self.db_path = db_path

        # Initialize the 4 Layers
        self.kernel = InvariantKernel()
        self.ledger = StateLedger(db_path=self.db_path, session_id=session_id, objective=objective)
        self.sieve = ASTIngressSieve()
        self.pager = ContextPager(db_path=self.db_path, session_id=session_id)
        self.gatekeeper = CryptographicGatekeeper(root_dir=str(self.workspace_dir))

        # Metrics accounting
        self.total_raw_tokens: int = 0
        self.total_sieved_tokens: int = 0
        self.epistemic_traps_intercepted: int = 0

    def set_objective(self, objective: str) -> None:
        """Set or update overarching task objective."""
        self.ledger.set_objective(objective)

    def add_constraint(self, rule: str, is_negative: bool = True) -> None:
        """Add invariant constraint rule (e.g. 'Never touch alembic migrations')."""
        self.ledger.add_constraint(rule, is_negative)

    def advance_turn(self) -> int:
        """Advance session turn counter."""
        return self.ledger.advance_turn()

    def process_tool_output(
        self,
        tool_name: str,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        command: str = "",
        target_file: Optional[str] = None,
        pre_snapshot: Optional[FileSnapshot] = None,
        file_operation: Optional[str] = None,  # 'create', 'edit', 'delete'
    ) -> Dict[str, Any]:
        """Process, sieve, verify, and page tool output through the MMU pipeline."""
        turn = self.ledger.get_turn()

        # 1. Sieve raw stdout/stderr through AST Ingress Sieve (Layer 2)
        sieve_res = self.sieve.sieve(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            command=command,
        )
        self.total_raw_tokens += sieve_res["original_tokens"]
        self.total_sieved_tokens += sieve_res["sieved_tokens"]

        # 2. Check for circular loops via Gatekeeper (Layer 4)
        is_loop, loop_msg = self.gatekeeper.check_circular_loop(
            tool_name=tool_name,
            payload=command or stdout[:200],
            exit_code=exit_code,
        )
        if is_loop:
            self.epistemic_traps_intercepted += 1
            self.ledger.add_dead_end(
                anti_pattern=f"Circular retry of '{command or tool_name}'",
                reason=loop_msg,
            )

        # 3. Cryptographic Invariant Verification (Layer 4)
        trap_message = ""
        if target_file and pre_snapshot and file_operation:
            is_valid, reason, post_snap = self.gatekeeper.verify_file_mutation(
                file_path=target_file,
                pre_snapshot=pre_snapshot,
                claim_type=file_operation,
            )
            if not is_valid:
                self.epistemic_traps_intercepted += 1
                trap_message = reason
            else:
                # Update dirty files in ledger
                if post_snap and post_snap.exists:
                    self.ledger.record_dirty_file(
                        path=target_file,
                        inode=post_snap.inode,
                        sha256_before=pre_snapshot.sha256,
                        sha256_after=post_snap.sha256,
                        status="created" if file_operation in ("create", "write") else "modified",
                    )
                elif file_operation == "delete":
                    self.ledger.record_dirty_file(
                        path=target_file,
                        inode=0,
                        sha256_before=pre_snapshot.sha256,
                        sha256_after="",
                        status="deleted",
                    )

        # 4. Check for unrecovered masked failures
        if exit_code != 0:
            is_valid_exec, exec_reason = self.gatekeeper.verify_execution_outcome(
                command=command or tool_name,
                exit_code=exit_code,
                claimed_success=False,
            )

        # 5. Page out to Episodic Swap (Layer 3 - FTS5)
        raw_full = stdout + ("\n" + stderr if stderr else "")
        self.pager.page_out(
            turn=turn,
            role="tool",
            tool_name=tool_name,
            content=raw_full,
            sieved_content=sieve_res["sieved_text"],
        )

        return {
            "sieved_text": sieve_res["sieved_text"],
            "tokens_saved": sieve_res["tokens_saved"],
            "reduction_pct": sieve_res["reduction_pct"],
            "trap_message": trap_message,
            "has_trap": bool(trap_message or is_loop),
            "exit_code": exit_code,
        }

    def page_in_evidence(self, query: str, limit: int = 3) -> List[Dict[str, Any]]:
        """JIT Recall of historical information from FTS5 swap space."""
        return self.pager.page_in_evidence(query=query, limit=limit)

    def render_prompt_frame(self, active_slice: str = "", user_message: str = "") -> str:
        """Render complete 3-Zone context frame for LLM inference."""
        ledger_md = self.ledger.render_markdown()
        return self.kernel.assemble_prompt_frame(
            ledger_markdown=ledger_md,
            active_slice=active_slice,
            user_message=user_message,
        )

    def get_metrics(self) -> Dict[str, Any]:
        """Return comprehensive MMU operational telemetry."""
        pager_stats = self.pager.stats()
        saved = max(0, self.total_raw_tokens - self.total_sieved_tokens)
        reduction = round((saved / self.total_raw_tokens * 100.0), 2) if self.total_raw_tokens > 0 else 0.0

        current_prompt = self.render_prompt_frame()
        prompt_tokens = estimate_tokens(current_prompt)
        kernel_tokens = estimate_tokens(self.kernel.prefix_text)
        cache_hit_est = round((kernel_tokens / prompt_tokens * 100.0), 2) if prompt_tokens > 0 else 0.0

        return {
            "turn": self.ledger.get_turn(),
            "total_raw_tokens": self.total_raw_tokens,
            "total_sieved_tokens": self.total_sieved_tokens,
            "tokens_saved": saved,
            "reduction_pct": reduction,
            "current_working_tokens": prompt_tokens,
            "estimated_cache_hit_pct": cache_hit_est,
            "epistemic_traps_intercepted": self.epistemic_traps_intercepted,
            "swapped_pages": pager_stats["total_pages"],
            "swapped_bytes": pager_stats["raw_bytes"],
        }
