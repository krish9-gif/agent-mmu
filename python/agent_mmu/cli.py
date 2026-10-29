"""Command-Line Interface for AgentMMU.

Provides interactive CLI commands to initialize workspaces, inspect working state,
sieve CLI outputs, query virtual swap space, and audit file mutations. Zero dependencies.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from . import AgentMMU, __version__
from .sieve import ASTIngressSieve


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize AgentMMU in the current workspace."""
    workspace = Path(".").resolve()
    mmu = AgentMMU(workspace_dir=str(workspace), session_id=args.session, objective=args.objective)
    print(f"Initialized AgentMMU v{__version__} in {mmu.workspace_dir}")
    print(f"Database: {mmu.db_path}")
    print(f"Session: {mmu.session_id}")
    if args.objective:
        print(f"Objective: {args.objective}")


def cmd_status(args: argparse.Namespace) -> None:
    """Display current MMU working context, metrics, and state ledger."""
    mmu = AgentMMU(workspace_dir=".", session_id=args.session)
    metrics = mmu.get_metrics()
    ledger_data = mmu.ledger.to_dict()

    print(f"=== AgentMMU v{__version__} Status ===")
    print(f"Session: {ledger_data['session_id']} | Turn: {ledger_data['turn']}")
    print(f"Objective: {ledger_data['objective'] or 'None'}")
    print(f"\n--- Metrics & Cache Invariants ---")
    print(f"Working Context Size:    {metrics['current_working_tokens']} tokens (Bounded)")
    print(f"Estimated Cache Hit Rate:{metrics['estimated_cache_hit_pct']}% (Prefix Pinned)")
    print(f"Total Tokens Saved:      {metrics['tokens_saved']} ({metrics['reduction_pct']}%)")
    print(f"Epistemic Traps Caught:  {metrics['epistemic_traps_intercepted']}")
    print(f"FTS5 Swapped Pages:      {metrics['swapped_pages']} ({metrics['swapped_bytes']} bytes)")

    if ledger_data["active_constraints"]:
        print(f"\n--- Active Constraints (Invariants) ---")
        for c in ledger_data["active_constraints"]:
            print(f"  * [INVARIANT] {c}")

    if ledger_data["dead_ends"]:
        print(f"\n--- Known Dead Ends ---")
        for de in ledger_data["dead_ends"]:
            print(f"  * [AVOID] {de}")

    if ledger_data["dirty_files"]:
        print(f"\n--- Modified Files (SHA-256 Anchored) ---")
        for df in ledger_data["dirty_files"]:
            print(f"  * {df['path']} ({df['status']}) - sha:{df['sha256']}")

    if ledger_data["verified_facts"]:
        print(f"\n--- Verified Facts ---")
        for f in ledger_data["verified_facts"]:
            print(f"  * {f}")


def cmd_sieve(args: argparse.Namespace) -> None:
    """Execute a command, sieve its output, and log to MMU."""
    if not args.cmd:
        print("Error: No command specified to run and sieve.", file=sys.stderr)
        sys.exit(1)

    cmd_str = " ".join(args.cmd)
    mmu = AgentMMU(workspace_dir=".", session_id=args.session)
    mmu.advance_turn()

    proc = subprocess.run(
        cmd_str,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    res = mmu.process_tool_output(
        tool_name="bash",
        stdout=proc.stdout,
        stderr=proc.stderr,
        exit_code=proc.returncode,
        command=cmd_str,
    )

    print(res["sieved_text"])
    print(
        f"\n[AgentMMU Sieve: Saved {res['tokens_saved']} tokens ({res['reduction_pct']}% reduction) | Exit: {proc.returncode}]",
        file=sys.stderr,
    )
    if res["has_trap"]:
        print(f"[TRAP INTERCEPTED: {res['trap_message']}]", file=sys.stderr)

    sys.exit(proc.returncode)


def cmd_page(args: argparse.Namespace) -> None:
    """Query episodic virtual swap space via FTS5."""
    mmu = AgentMMU(workspace_dir=".", session_id=args.session)
    results = mmu.page_in_evidence(query=args.query, limit=args.limit)

    if not results:
        print(f"No historical matches found in swap for query: '{args.query}'")
        return

    print(f"Found {len(results)} matches in episodic swap:")
    for i, r in enumerate(results, 1):
        print(f"\n[{i}] Turn {r['turn']} | Role: {r['role']} | Tool: {r['tool_name']}")
        print(f"    Excerpt: {r['excerpt']}")


def cmd_prompt(args: argparse.Namespace) -> None:
    """Render the assembled 3-Zone context frame."""
    mmu = AgentMMU(workspace_dir=".", session_id=args.session)
    print(mmu.render_prompt_frame(user_message=args.message or ""))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent-mmu",
        description="AgentMMU: Deterministic Memory Management Unit & Virtual Context Kernel",
    )
    parser.add_argument("--version", action="version", version=f"agent-mmu {__version__}")
    parser.add_argument("--session", default="default_session", help="Session ID")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Initialize AgentMMU workspace")
    p_init.add_argument("--objective", default="", help="Task objective")
    p_init.set_defaults(func=cmd_init)

    # status
    p_status = subparsers.add_parser("status", help="Show current state ledger and telemetry")
    p_status.set_defaults(func=cmd_status)

    # sieve
    p_sieve = subparsers.add_parser("sieve", help="Execute command and sieve output")
    p_sieve.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run")
    p_sieve.set_defaults(func=cmd_sieve)

    # page
    p_page = subparsers.add_parser("page", help="Search episodic swap space (FTS5)")
    p_page.add_argument("query", help="Search query")
    p_page.add_argument("--limit", type=int, default=3, help="Max results")
    p_page.set_defaults(func=cmd_page)

    # prompt
    p_prompt = subparsers.add_parser("prompt", help="Render full 3-Zone prompt frame")
    p_prompt.add_argument("--message", default="", help="Optional user message")
    p_prompt.set_defaults(func=cmd_prompt)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
