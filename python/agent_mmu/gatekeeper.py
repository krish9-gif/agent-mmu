"""Cryptographic State Gatekeeper (Layer 4).

Adapted and elevated from AgentTrace (by Krish Joshi).
Enforces empirical ground-truth invariants on tool execution:
- Cryptographic SHA-256 + Inode filesystem delta anchoring (Zero Ghost Actions).
- Non-zero exit code and masked error interception (Zero Masked Failures).
- Exact circular loop detection via action signature hashing. Zero dependencies.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FileSnapshot:
    path: str
    exists: bool
    inode: int = 0
    mtime_ns: int = 0
    size: int = 0
    sha256: str = ""


class CryptographicGatekeeper:
    """Empirical Invariant Gatekeeper for Agent Actions and File Mutators."""

    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir).resolve()
        self._action_history: List[str] = []
        self._loop_window: int = 6

    def compute_fingerprint(self, file_path: str) -> FileSnapshot:
        """Compute cryptographic SHA-256 and inode fingerprint of a file."""
        p = Path(file_path)
        if not p.is_absolute():
            p = (self.root_dir / p).resolve()

        if not p.exists() or not p.is_file():
            return FileSnapshot(path=str(p), exists=False)

        stat = p.stat()
        hasher = hashlib.sha256()
        try:
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha = hasher.hexdigest()
        except (PermissionError, OSError):
            sha = "UNREADABLE_IO_ERROR"

        return FileSnapshot(
            path=str(p),
            exists=True,
            inode=stat.st_ino,
            mtime_ns=stat.st_mtime_ns,
            size=stat.st_size,
            sha256=sha,
        )

    def verify_file_mutation(
        self,
        file_path: str,
        pre_snapshot: FileSnapshot,
        claim_type: str = "edit",
    ) -> Tuple[bool, str, Optional[FileSnapshot]]:
        """Verify that a stated file operation genuinely altered disk state.

        Returns (is_valid, reason, post_snapshot).
        """
        post = self.compute_fingerprint(file_path)

        if claim_type in ("create", "write"):
            if not post.exists:
                return (
                    False,
                    f"FAULT_EPISTEMIC_MISMATCH: File '{file_path}' claimed created, but does not exist on disk.",
                    post,
                )
            if pre_snapshot.exists and pre_snapshot.sha256 == post.sha256:
                return (
                    False,
                    f"FAULT_EPISTEMIC_MISMATCH: File '{file_path}' claimed overwritten, but SHA-256 hash was completely identical ({post.sha256[:8]}).",
                    post,
                )
            return (True, "VERIFIED_FILE_CREATED_OR_OVERWRITTEN", post)

        if claim_type in ("edit", "modify"):
            if not post.exists:
                return (
                    False,
                    f"FAULT_EPISTEMIC_MISMATCH: File '{file_path}' claimed modified, but was deleted or missing.",
                    post,
                )
            if not pre_snapshot.exists:
                return (
                    True,
                    "VERIFIED_FILE_NEWLY_CREATED",
                    post,
                )
            if pre_snapshot.sha256 == post.sha256:
                return (
                    False,
                    f"FAULT_EPISTEMIC_MISMATCH: File '{file_path}' claimed edited, but SHA-256 unchanged ({post.sha256[:8]}). Zero disk mutation.",
                    post,
                )
            return (True, "VERIFIED_FILE_MUTATED", post)

        if claim_type == "delete":
            if post.exists:
                return (
                    False,
                    f"FAULT_EPISTEMIC_MISMATCH: File '{file_path}' claimed deleted, but still exists on disk.",
                    post,
                )
            return (True, "VERIFIED_FILE_DELETED", post)

        return (True, "UNKNOWN_CLAIM_TYPE_PASSED", post)

    def verify_execution_outcome(
        self,
        command: str,
        exit_code: int,
        claimed_success: bool = True,
    ) -> Tuple[bool, str]:
        """Verify that a tool command succeeded without error masking."""
        if claimed_success and exit_code != 0:
            return (
                False,
                f"FAULT_MASKED_FAILURE: Agent claimed command '{command}' succeeded, but process exited with non-zero exit code {exit_code}.",
            )
        return (True, "VERIFIED_EXECUTION_OUTCOME")

    def check_circular_loop(self, tool_name: str, payload: str, exit_code: int) -> Tuple[bool, str]:
        """Detect repetitive circular execution loops (same command failing repeatedly)."""
        # Create normalized action signature
        norm_payload = payload.strip().replace("\n", " ")[:300]
        sig = f"{tool_name}:{exit_code}:{norm_payload}"

        self._action_history.append(sig)
        if len(self._action_history) > 50:
            self._action_history.pop(0)

        # Check window for duplicates
        window = self._action_history[-self._loop_window :]
        if window.count(sig) >= 3:
            return (
                True,
                f"FAULT_CIRCULAR_LOOP_DETECTED: Agent invoked '{tool_name}' with identical payload 3 times in last {self._loop_window} turns. Forcing dead-end registration.",
            )

        return (False, "NO_LOOP_DETECTED")
