#!/usr/bin/env python3
"""Unit tests for poc_safety_linter.py in Devia-CyberSecurity."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from poc_safety_linter import lint_python_code


class TestPoCSafetyLinter(unittest.TestCase):
    def test_safe_benign_poc_passes(self):
        safe_code = """
import urllib.request
import json
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
req = urllib.request.Request(f"{target}/api/version")
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        if "version" in data:
            print("VULNERABLE: Version disclosure observed")
            sys.exit(0)
except Exception as e:
    print(f"NOT CONFIRMED: {e}")
    sys.exit(1)
"""
        report = lint_python_code(safe_code)
        self.assertTrue(report["valid"])
        self.assertEqual(report["totalViolations"], 0)

    def test_subprocess_import_and_call_detected(self):
        unsafe_code = """
import subprocess
subprocess.run(["calc.exe"])
"""
        report = lint_python_code(unsafe_code)
        self.assertFalse(report["valid"])
        rules = [v["rule"] for v in report["violations"]]
        self.assertIn("DISALLOWED_IMPORT", rules)
        self.assertIn("DISALLOWED_FUNCTION_CALL", rules)

    def test_os_system_detected(self):
        unsafe_code = """
import os
os.system("whoami")
"""
        report = lint_python_code(unsafe_code)
        self.assertFalse(report["valid"])
        targets = [v["target"] for v in report["violations"]]
        self.assertIn("os.system", targets)

    def test_eval_exec_detected(self):
        unsafe_code = """
payload = "__import__('os').system('id')"
eval(payload)
exec(payload)
"""
        report = lint_python_code(unsafe_code)
        self.assertFalse(report["valid"])
        rules = [v["rule"] for v in report["violations"]]
        self.assertTrue(any("DISALLOWED_FUNCTION_CALL" in r for r in rules))

    def test_file_write_mode_detected(self):
        unsafe_code = """
with open("/etc/cron.d/malicious", "w") as f:
    f.write("* * * * * root /bin/sh\\n")
"""
        report = lint_python_code(unsafe_code)
        self.assertFalse(report["valid"])
        rules = [v["rule"] for v in report["violations"]]
        self.assertIn("UNSAFE_FILE_WRITE", rules)

    def test_cli_execution_with_json(self):
        script_path = Path(__file__).parent / "poc_safety_linter.py"
        test_snippet = "import os\nos.system('whoami')"
        proc = subprocess.run(
            [sys.executable, str(script_path), "--code", test_snippet, "--json"],
            capture_output=True,
            text=True
        )
        self.assertEqual(proc.returncode, 1)
        data = json.loads(proc.stdout)
        self.assertFalse(data["valid"])
        self.assertGreater(data["totalViolations"], 0)


if __name__ == "__main__":
    unittest.main()
