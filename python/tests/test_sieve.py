"""Tests for AST Ingress Sieve (Layer 2)."""

import unittest
from agent_mmu.sieve import ASTIngressSieve, strip_ansi, clean_progress_bars, estimate_tokens


class TestASTIngressSieve(unittest.TestCase):

    def test_strip_ansi_and_progress_bars(self):
        raw = "\x1b[31mRed Error\x1b[0m\r[1/2] Compiling...\r[2/2] Done!"
        cleaned = clean_progress_bars(strip_ansi(raw))
        self.assertNotIn("\x1b[", cleaned)
        self.assertIn("Red Error", cleaned)
        self.assertIn("[2/2] Done!", cleaned)

    def test_pytest_log_compression(self):
        # Generate simulated 500-line passing PyTest noise followed by 1 failure
        noisy_pytest = "\n".join([f"test_{i:03d}.py ... [ 10%]" for i in range(100)])
        failure_block = """
=================================== FAILURES ===================================
___________________________ test_matrix_mult_ragged ____________________________
    def test_matrix_mult_ragged():
>       assert result == expected
E       AssertionError: assert [1, 2] == [1, 3]
tests/test_kernels.py:42: AssertionError
=========================== short test summary info ============================
FAILED tests/test_kernels.py::test_matrix_mult_ragged - AssertionError: assert [1, 2] == [1, 3]
========================= 1 failed, 99 passed in 0.82s =========================
"""
        full_log = noisy_pytest + failure_block
        res = ASTIngressSieve.sieve(stdout=full_log, exit_code=1, command="pytest tests/")

        self.assertTrue(res["is_compressed"])
        self.assertGreater(res["reduction_pct"], 70.0)
        self.assertIn("test_matrix_mult_ragged", res["sieved_text"])
        self.assertIn("AssertionError: assert [1, 2] == [1, 3]", res["sieved_text"])
        self.assertNotIn("test_050.py", res["sieved_text"])

    def test_cargo_error_extraction(self):
        cargo_output = """
   Compiling libc v0.2.147
   Compiling syn v2.0.28
error[E0308]: mismatched types
  --> src/main.rs:18:9
   |
18 |     let x: u32 = "hello";
   |            ---   ^^^^^^^ expected `u32`, found `&str`
   |            |
   |            expected due to this
For more information about this error, try `rustc --explain E0308`.
error: could not compile `my-crate` due to previous error
"""
        res = ASTIngressSieve.sieve(stdout=cargo_output, exit_code=101, command="cargo build")
        self.assertIn("error[E0308]: mismatched types", res["sieved_text"])
        self.assertIn("--> src/main.rs:18:9", res["sieved_text"])
        self.assertNotIn("Compiling libc", res["sieved_text"])

    def test_python_traceback_compression(self):
        traceback_log = """
Traceback (most recent call last):
  File "/usr/local/lib/python3.11/site-packages/urllib3/connectionpool.py", line 467, in _make_request
    self._validate_conn(conn)
  File "/home/krish/project/src/api_client.py", line 84, in fetch_user
    res = requests.get(url)
ConnectionRefusedError: [Errno 111] Connection refused
"""
        res = ASTIngressSieve.sieve(stdout=traceback_log, exit_code=1, command="python src/main.py")
        self.assertIn("api_client.py", res["sieved_text"])
        self.assertIn("ConnectionRefusedError", res["sieved_text"])
        self.assertNotIn("connectionpool.py", res["sieved_text"])


if __name__ == "__main__":
    unittest.main()
