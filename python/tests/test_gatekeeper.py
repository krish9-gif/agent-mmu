"""Tests for Cryptographic State Gatekeeper (Layer 4)."""

import os
import tempfile
import unittest
from agent_mmu.gatekeeper import CryptographicGatekeeper


class TestCryptographicGatekeeper(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.gatekeeper = CryptographicGatekeeper(root_dir=self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ghost_action_interception(self):
        target = os.path.join(self.temp_dir.name, "app.py")
        with open(target, "w") as f:
            f.write("print('original')\n")

        pre_snap = self.gatekeeper.compute_fingerprint(target)

        # 1. Stated edit, but file was not modified (Ghost Action)
        is_valid, msg, post_snap = self.gatekeeper.verify_file_mutation(
            file_path=target,
            pre_snapshot=pre_snap,
            claim_type="edit",
        )
        self.assertFalse(is_valid)
        self.assertIn("FAULT_EPISTEMIC_MISMATCH", msg)

        # 2. Genuine file edit
        with open(target, "w") as f:
            f.write("print('mutated')\n")

        is_valid_real, msg_real, post_real = self.gatekeeper.verify_file_mutation(
            file_path=target,
            pre_snapshot=pre_snap,
            claim_type="edit",
        )
        self.assertTrue(is_valid_real)
        self.assertIn("VERIFIED_FILE_MUTATED", msg_real)

    def test_masked_error_detection(self):
        # Claimed success on exit code 1
        is_valid, msg = self.gatekeeper.verify_execution_outcome(
            command="pytest tests/",
            exit_code=1,
            claimed_success=True,
        )
        self.assertFalse(is_valid)
        self.assertIn("FAULT_MASKED_FAILURE", msg)

    def test_circular_loop_interception(self):
        for _ in range(2):
            is_loop, _ = self.gatekeeper.check_circular_loop(
                tool_name="bash",
                payload="npm test",
                exit_code=1,
            )
            self.assertFalse(is_loop)

        # 3rd identical attempt triggers trap
        is_loop, msg = self.gatekeeper.check_circular_loop(
            tool_name="bash",
            payload="npm test",
            exit_code=1,
        )
        self.assertTrue(is_loop)
        self.assertIn("FAULT_CIRCULAR_LOOP_DETECTED", msg)


if __name__ == "__main__":
    unittest.main()
