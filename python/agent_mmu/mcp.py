"""Model Context Protocol (MCP) Server for AgentMMU.

Exposes AgentMMU's 4 layers as standard MCP tools over stdio JSON-RPC.
Enables plug-and-play integration with Google Antigravity, Claude Code, Cursor, and OpenHands.
Zero external dependencies (pure Python standard library).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from . import AgentMMU, __version__


class MCPServer:
    """Zero-dependency stdio JSON-RPC MCP Server for AgentMMU."""

    def __init__(self, workspace_dir: str = "."):
        self.workspace_dir = workspace_dir
        self.mmu = AgentMMU(workspace_dir=workspace_dir)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return MCP tool schemas."""
        return [
            {
                "name": "mmu_get_state",
                "description": "Fetch current deterministic state ledger, active constraints, verified facts, and memory metrics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
            {
                "name": "mmu_sieve_output",
                "description": "Sieve raw test/compiler logs (PyTest, Cargo, NPM, tracebacks) to reduce tokens by 85%-98% before context entry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "stdout": {"type": "string", "description": "Raw stdout from command"},
                        "stderr": {"type": "string", "description": "Raw stderr from command"},
                        "exit_code": {"type": "integer", "description": "Command exit code"},
                        "command": {"type": "string", "description": "Command executed"},
                    },
                    "required": ["stdout"],
                },
            },
            {
                "name": "mmu_page_in_evidence",
                "description": "Search historical virtual swap space (SQLite FTS5) for past errors, flags, or interactions without bloating context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query terms"},
                        "limit": {"type": "integer", "description": "Max results to return (default 3)"},
                    },
                    "required": ["query"],
                },
            },
            {
                "name": "mmu_record_fact",
                "description": "Empirically record a verified fact into the deterministic working state ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fact": {"type": "string", "description": "Verified fact to store"},
                    },
                    "required": ["fact"],
                },
            },
            {
                "name": "mmu_add_constraint",
                "description": "Register a permanent negative constraint or prohibited anti-pattern to prevent amnesia or circular loops.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "rule": {"type": "string", "description": "Constraint rule or prohibited pattern"},
                        "is_dead_end": {"type": "boolean", "description": "True if recording a refuted hypothesis/dead-end"},
                    },
                    "required": ["rule"],
                },
            },
        ]

    def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Route and execute MCP tool requests."""
        if name == "mmu_get_state":
            ledger = self.mmu.ledger.to_dict()
            metrics = self.mmu.get_metrics()
            return {
                "ledger": ledger,
                "metrics": metrics,
                "working_context_tokens": metrics["current_working_tokens"],
                "cache_hit_pct": metrics["estimated_cache_hit_pct"],
            }

        elif name == "mmu_sieve_output":
            stdout = arguments.get("stdout", "")
            stderr = arguments.get("stderr", "")
            exit_code = arguments.get("exit_code", 0)
            command = arguments.get("command", "")
            return self.mmu.process_tool_output(
                tool_name="bash",
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                command=command,
            )

        elif name == "mmu_page_in_evidence":
            query = arguments.get("query", "")
            limit = arguments.get("limit", 3)
            return self.mmu.page_in_evidence(query=query, limit=limit)

        elif name == "mmu_record_fact":
            fact = arguments.get("fact", "")
            self.mmu.ledger.add_fact(fact)
            return {"status": "SUCCESS", "fact_recorded": fact}

        elif name == "mmu_add_constraint":
            rule = arguments.get("rule", "")
            is_dead_end = arguments.get("is_dead_end", False)
            if is_dead_end:
                self.mmu.ledger.add_dead_end(rule)
            else:
                self.mmu.add_constraint(rule)
            return {"status": "SUCCESS", "rule_registered": rule}

        else:
            raise ValueError(f"Unknown tool: {name}")

    def run_stdio(self) -> None:
        """Run stdio JSON-RPC loop."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params", {})

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "agent-mmu", "version": __version__},
                        "capabilities": {"tools": {}},
                    },
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": self.get_tool_definitions()},
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                try:
                    out = self.handle_tool_call(tool_name, tool_args)
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": json.dumps(out, indent=2)}]
                        },
                    }
                except Exception as e:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32000, "message": str(e)},
                    }
            elif method == "ping":
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method '{method}' not found"},
                }

            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def main() -> None:
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
