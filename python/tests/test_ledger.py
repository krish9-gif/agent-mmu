"""Tests for Deterministic State Ledger (Layer 1)."""

import unittest
from agent_mmu.ledger import StateLedger
from agent_mmu.sieve import estimate_tokens


class TestStateLedger(unittest.TestCase):

    def setUp(self):
        self.ledger = StateLedger(db_path=":memory:", session_id="test_sess", objective="Fix race condition")

    def test_state_ledger_crud(self):
        self.assertEqual(self.ledger.get_turn(), 0)
        self.ledger.advance_turn()
        self.assertEqual(self.ledger.get_turn(), 1)

        # Facts
        self.ledger.add_fact("PostgreSQL 15 running on port 5432")
        self.ledger.add_fact("CUDA 12.2 available")

        # Dirty files
        self.ledger.record_dirty_file(
            path="src/kernel.cu",
            inode=123456,
            sha256_before="aaa111",
            sha256_after="bbb222",
            status="modified",
        )

        # Hypotheses
        hid = self.ledger.propose_hypothesis("Add atomicCAS barrier in thread block")
        self.ledger.resolve_hypothesis(hid, "REFUTED", outcome="Deadlock on warps > 32")

        # Dead ends & Constraints
        self.ledger.add_dead_end("atomicCAS on global memory", "Causes GPU freeze")
        self.ledger.add_constraint("Do not alter shared memory layout", is_negative=True)

        data = self.ledger.to_dict()
        self.assertEqual(data["objective"], "Fix race condition")
        self.assertEqual(data["turn"], 1)
        self.assertEqual(len(data["verified_facts"]), 2)
        self.assertEqual(len(data["dirty_files"]), 1)
        self.assertEqual(len(data["hypotheses"]), 1)
        self.assertEqual(len(data["dead_ends"]), 1)
        self.assertEqual(len(data["active_constraints"]), 1)

    def test_token_boundedness(self):
        # Stress test: add 50 facts, 30 dead ends, 20 dirty files
        for i in range(50):
            self.ledger.add_fact(f"Empirical fact number {i:03d} verified through testing")
        for i in range(30):
            self.ledger.add_dead_end(f"Prohibited method {i:03d}", f"Failed in benchmark {i}")
        for i in range(20):
            self.ledger.record_dirty_file(f"file_{i}.py", 1000 + i, "sha_a", "sha_b")

        rendered = self.ledger.render_markdown(max_tokens=1200)
        tokens = estimate_tokens(rendered)
        self.assertLessEqual(tokens, 1200)
        self.assertIn("AGENT_MMU_STATE_LEDGER", rendered)


if __name__ == "__main__":
    unittest.main()
