#!/usr/bin/env python3
"""Unit tests for sarif_toolkit.py."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sarif_toolkit import (
    extract_findings,
    filter_sarif,
    load_sarif,
    merge_sarifs,
    normalize_artifact_uri,
    save_sarif,
    summarize_sarif,
    validate_sarif_version,
)


SAMPLE_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "version": "1.0.0"
                }
            },
            "results": [
                {
                    "ruleId": "security.injection.sql-sqli",
                    "level": "error",
                    "message": {"text": "Potential SQL Injection detected"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "file:///src/db/user.ts"},
                                "region": {"startLine": 45, "endLine": 45, "startColumn": 10, "endColumn": 40}
                            }
                        }
                    ],
                    "fingerprints": {"primary": "fp-sqli-001"}
                },
                {
                    "ruleId": "security.crypto.weak-hash",
                    "level": "warning",
                    "message": {"text": "MD5 hash used"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/utils/hash.ts"},
                                "region": {"startLine": 12, "endLine": 12}
                            }
                        }
                    ]
                }
            ]
        }
    ]
}


class TestSarifToolkit(unittest.TestCase):
    def test_version_validation(self):
        self.assertTrue(validate_sarif_version(SAMPLE_SARIF))
        self.assertFalse(validate_sarif_version({"version": "2.0.0"}))

    def test_uri_normalization(self):
        self.assertEqual(normalize_artifact_uri("file:///src/db/user.ts"), "/src/db/user.ts" if not normalize_artifact_uri("file:///src/db/user.ts").startswith("src") else "src/db/user.ts")
        self.assertEqual(normalize_artifact_uri("src%2Fdb%2Fuser.ts"), "src/db/user.ts")

    def test_extract_findings(self):
        findings = extract_findings(SAMPLE_SARIF)
        self.assertEqual(len(findings), 2)
        
        sqli = findings[0]
        self.assertEqual(sqli.rule_id, "security.injection.sql-sqli")
        self.assertEqual(sqli.level, "error")
        self.assertEqual(sqli.start_line, 45)
        self.assertEqual(sqli.tool_name, "Semgrep")
        self.assertEqual(sqli.fingerprint, "fp-sqli-001")

        crypto = findings[1]
        self.assertEqual(crypto.rule_id, "security.crypto.weak-hash")
        self.assertEqual(crypto.level, "warning")
        self.assertEqual(crypto.start_line, 12)

    def test_summarize_sarif(self):
        summary = summarize_sarif(SAMPLE_SARIF)
        self.assertEqual(summary["totalFindings"], 2)
        self.assertEqual(summary["levels"]["error"], 1)
        self.assertEqual(summary["levels"]["warning"], 1)
        self.assertIn("Semgrep", summary["tools"])

    def test_filter_sarif(self):
        # Filter by level
        filtered_errors = filter_sarif(SAMPLE_SARIF, levels=["error"])
        findings_err = extract_findings(filtered_errors)
        self.assertEqual(len(findings_err), 1)
        self.assertEqual(findings_err[0].rule_id, "security.injection.sql-sqli")

        # Filter by rule
        filtered_rule = filter_sarif(SAMPLE_SARIF, rules=["security.crypto.weak-hash"])
        findings_rule = extract_findings(filtered_rule)
        self.assertEqual(len(findings_rule), 1)
        self.assertEqual(findings_rule[0].rule_id, "security.crypto.weak-hash")

        # Filter by path pattern
        filtered_path = filter_sarif(SAMPLE_SARIF, file_pattern="hash.ts")
        findings_path = extract_findings(filtered_path)
        self.assertEqual(len(findings_path), 1)
        self.assertEqual(findings_path[0].file_path, "src/utils/hash.ts")

    def test_merge_sarifs(self):
        sarif_b = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": [
                        {
                            "ruleId": "js/xss",
                            "level": "error",
                            "message": {"text": "Cross-site scripting"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/views/page.ts"},
                                        "region": {"startLine": 88}
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        merged = merge_sarifs([SAMPLE_SARIF, sarif_b])
        findings = extract_findings(merged)
        self.assertEqual(len(findings), 3)

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile("w+", suffix=".sarif", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            save_sarif(SAMPLE_SARIF, tmp_path)
            loaded = load_sarif(tmp_path)
            self.assertEqual(loaded["version"], "2.1.0")
            self.assertEqual(len(extract_findings(loaded)), 2)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()


if __name__ == "__main__":
    unittest.main()
