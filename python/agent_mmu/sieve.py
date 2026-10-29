"""AST Ingress Sieve (Layer 2).

Adapted and elevated from AgentFixer (by Krish Joshi).
Intercepts raw subprocess outputs (stdout/stderr) and compresses noisy CLI streams
(PyTest, Cargo, NPM, Python tracebacks) by 85%–98% before tokens enter the prompt buffer.
Prevents context bloating and KV-cache saturation. Zero dependencies.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Comprehensive regex to strip ANSI color codes, cursor movement, and styles
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi(text: str) -> str:
    """Remove all ANSI escape sequences from the string."""
    return ANSI_ESCAPE_RE.sub("", text)


def clean_progress_bars(text: str) -> str:
    """Normalize carriage returns (\r) produced by spinners and progress bars."""
    lines: List[str] = []
    for raw_line in text.split("\n"):
        if "\r" in raw_line:
            parts = [p for p in raw_line.split("\r") if p.strip()]
            line = parts[-1] if parts else ""
        else:
            line = raw_line
        lines.append(line)
    return "\n".join(lines)


def estimate_tokens(text: str) -> int:
    """Accurate token estimation heuristic (1 token ~ 4 characters)."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


class ASTIngressSieve:
    """Syntactic CLI output compressor for test runners, compilers, and shell commands."""

    @classmethod
    def sieve(
        cls,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        command: str = "",
        max_output_tokens: int = 1500,
    ) -> Dict[str, Any]:
        """Sieve raw CLI execution output.

        Returns a dictionary containing:
            - sieved_text: High-signal token-compressed output
            - original_tokens: Raw uncompressed token estimate
            - sieved_tokens: Compressed token estimate
            - tokens_saved: Original - Sieved
            - reduction_pct: Percentage token reduction
            - is_compressed: Whether output was compressed
        """
        raw_combined = (stdout + ("\n" + stderr if stderr else "")).strip()
        cleaned = clean_progress_bars(strip_ansi(raw_combined))
        orig_tokens = estimate_tokens(raw_combined)

        if not cleaned:
            return {
                "sieved_text": "[Empty output, exit code 0]" if exit_code == 0 else f"[Empty output, exit code {exit_code}]",
                "original_tokens": orig_tokens,
                "sieved_tokens": 10,
                "tokens_saved": 0,
                "reduction_pct": 0.0,
                "is_compressed": False,
            }

        # 1. Detect command type or output signature
        cmd_lower = command.lower() if command else ""
        text_lower = cleaned.lower()

        if "pytest" in cmd_lower or "test session starts" in text_lower or "= failures =" in text_lower:
            compressed = cls._sieve_pytest(cleaned, exit_code)
        elif "cargo" in cmd_lower or "rustc" in cmd_lower or "error[e" in text_lower:
            compressed = cls._sieve_cargo(cleaned, exit_code)
        elif "npm" in cmd_lower or "yarn" in cmd_lower or "vitest" in cmd_lower or "jest" in text_lower:
            compressed = cls._sieve_jest(cleaned, exit_code)
        elif "traceback (most recent call last):" in text_lower:
            compressed = cls._sieve_python_traceback(cleaned, exit_code)
        elif "git diff" in cmd_lower or "diff --git" in text_lower:
            compressed = cls._sieve_git_diff(cleaned)
        else:
            compressed = cls._sieve_generic(cleaned, exit_code)

        # Enforce max_output_tokens bound
        sieved_tokens = estimate_tokens(compressed)
        if sieved_tokens > max_output_tokens:
            compressed = cls._truncate_middle(compressed, max_output_tokens)
            sieved_tokens = estimate_tokens(compressed)

        saved = max(0, orig_tokens - sieved_tokens)
        reduction = round((saved / orig_tokens * 100.0), 2) if orig_tokens > 0 else 0.0

        return {
            "sieved_text": compressed,
            "original_tokens": orig_tokens,
            "sieved_tokens": sieved_tokens,
            "tokens_saved": saved,
            "reduction_pct": reduction,
            "is_compressed": orig_tokens > sieved_tokens,
        }

    @classmethod
    def _sieve_pytest(cls, text: str, exit_code: int) -> str:
        """Extract only failing assertions, summary counts, and immediate error lines from PyTest."""
        if exit_code == 0 and "= failures =" not in text.lower():
            # All tests passed; return summary line only
            summary_match = re.search(r"(=+ .*(?:passed|failed).* =+)", text)
            if summary_match:
                return f"[PyTest: ALL TESTS PASSED]\n{summary_match.group(1).strip()}"
            return "[PyTest: All tests passed successfully]"

        lines = text.split("\n")
        retained: List[str] = ["[PyTest Execution Failure - Sieved Output]"]
        in_failure = False
        in_short_summary = False

        for line in lines:
            # Capture failure header
            if line.startswith("____") and line.endswith("____"):
                retained.append("\n" + line.strip("_ "))
                in_failure = True
                continue
            if line.startswith("==== FAILURES ===="):
                in_failure = True
                continue
            if line.startswith("==== short test summary info ===="):
                in_short_summary = True
                in_failure = False
                retained.append("\n" + line)
                continue
            if line.startswith("====") and ("passed" in line or "failed" in line):
                retained.append(line)
                in_short_summary = False
                in_failure = False
                continue

            if in_short_summary:
                if line.strip():
                    retained.append(line)
                continue

            if in_failure:
                # Capture assertion errors, raised exceptions, and file:line
                if (
                    ">" in line
                    or "E   " in line
                    or re.search(r"^[\w/.-]+\.py:\d+:", line)
                    or "AssertionError" in line
                    or "Error:" in line
                ):
                    retained.append(line)

        return "\n".join(retained).strip()

    @classmethod
    def _sieve_cargo(cls, text: str, exit_code: int) -> str:
        """Extract compiler error messages, file:line:col, and suggestion blocks from Cargo."""
        if exit_code == 0:
            return "[Cargo: Build/Check Succeeded]"

        lines = text.split("\n")
        retained: List[str] = ["[Cargo Compiler Errors - Sieved Output]"]
        capture_next = 0

        for line in lines:
            if "error[" in line or line.startswith("error:"):
                retained.append("\n" + line)
                capture_next = 3  # Capture immediate 3 context lines
                continue
            if " --> " in line:
                retained.append(line)
                capture_next = 2
                continue
            if capture_next > 0:
                retained.append(line)
                capture_next -= 1

        return "\n".join(retained).strip()

    @classmethod
    def _sieve_jest(cls, text: str, exit_code: int) -> str:
        """Extract failed test suites and expect assertions from Jest / Vitest."""
        if exit_code == 0:
            return "[Jest/Vitest: All Tests Passed]"

        lines = text.split("\n")
        retained: List[str] = ["[Jest/Vitest Failure - Sieved Output]"]
        capture = False

        for line in lines:
            if "FAIL " in line or "● " in line:
                retained.append("\n" + line)
                capture = True
                continue
            if "Tests:" in line or "Suites:" in line:
                retained.append(line)
                continue
            if capture:
                if "Expected:" in line or "Received:" in line or "at " in line:
                    retained.append(line)
                    if "at " in line:
                        capture = False

        return "\n".join(retained).strip()

    @classmethod
    def _sieve_python_traceback(cls, text: str, exit_code: int) -> str:
        """Compress Python traceback, stripping site-packages boilerplate."""
        lines = text.split("\n")
        retained: List[str] = ["[Python Traceback - Sieved Output]"]
        for line in lines:
            # Skip standard library and site-packages noise frames unless user frame
            if "site-packages" in line and "File " in line:
                continue
            if "Traceback " in line or 'File "' in line or re.search(r"^\w*Error:", line) or "Exception:" in line:
                retained.append(line)

        return "\n".join(retained).strip()

    @classmethod
    def _sieve_git_diff(cls, text: str) -> str:
        """Compress git diff by stripping unmodified context lines."""
        lines = text.split("\n")
        retained: List[str] = ["[Git Diff - Compact Sieve]"]
        for line in lines:
            if (
                line.startswith("diff --git")
                or line.startswith("--- ")
                or line.startswith("+++ ")
                or line.startswith("@@")
                or line.startswith("+")
                or line.startswith("-")
            ):
                retained.append(line)
        return "\n".join(retained)

    @classmethod
    def _sieve_generic(cls, text: str, exit_code: int) -> str:
        """Generic fallback filter for arbitrary terminal logs."""
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if len(lines) <= 25:
            return text

        # Retain head (10 lines) and tail (15 lines) with middle omission marker
        head = lines[:10]
        tail = lines[-15:]
        omitted = len(lines) - 25
        return "\n".join(head) + f"\n\n[... {omitted} lines omitted by AgentMMU AST Sieve ...]\n\n" + "\n".join(tail)

    @classmethod
    def _truncate_middle(cls, text: str, max_tokens: int) -> str:
        """Truncate excessive text in the middle, preserving head and tail context."""
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        half = max_chars // 2 - 100
        return (
            text[:half]
            + f"\n\n[... Omitted {len(text) - 2 * half} chars to adhere to MMU budget ...]\n\n"
            + text[-half:]
        )
