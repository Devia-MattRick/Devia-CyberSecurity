#!/usr/bin/env python3
"""Unit tests for forensic_inventory.py and absorption_planner.py."""

import json
from pathlib import Path
import tempfile
import unittest

from forensic_inventory import run_forensic_inventory, is_link_or_reparse
from absorption_planner import build_absorption_plan


class TestForensicTools(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.target_dir = self.root / "mock_target"
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir = self.root / "mock_output"

        # Create mock target files
        (self.target_dir / "package.json").write_text('{"name": "test-pkg"}', encoding="utf-8")
        (self.target_dir / "SKILL.md").write_text('---\nname: test-skill\n---', encoding="utf-8")
        (self.target_dir / ".env").write_text('SECRET_KEY=supersecret', encoding="utf-8")
        
        src_dir = self.target_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "app.ts").write_text('console.log("hello");', encoding="utf-8")
        (src_dir / "crypto_service.py").write_text('import hashlib\nprint("secure")', encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_forensic_inventory_execution(self):
        summary, code = run_forensic_inventory(
            root_path=self.target_dir,
            output_dir=self.output_dir,
            hash_critical=True
        )

        self.assertEqual(code, 0)
        self.assertTrue((self.output_dir / "inventory.jsonl").exists())
        self.assertTrue((self.output_dir / "summary.json").exists())

        # Check summary metrics
        self.assertGreaterEqual(summary["metrics"]["total_files"], 4)
        self.assertEqual(summary["target"]["archetype"], "AGENTIC_SKILL_OR_PLUGIN")
        self.assertIn("CRITICAL_MANIFEST_OR_CONFIG", summary["category_distribution"])

        # Check inventory lines
        with (self.output_dir / "inventory.jsonl").open("r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        manifest_entry = next((e for e in lines if e.get("path") == "package.json"), None)
        self.assertIsNotNone(manifest_entry)
        self.assertTrue(manifest_entry["is_security_critical"])
        self.assertIsNotNone(manifest_entry["sha256"])

    def test_absorption_planner_execution(self):
        summary, _ = run_forensic_inventory(
            root_path=self.target_dir,
            output_dir=self.output_dir,
            hash_critical=True
        )

        records = []
        with (self.output_dir / "inventory.jsonl").open("r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]

        plan_output = self.output_dir / "absorption-plan.json"
        plan = build_absorption_plan(
            target_path=self.target_dir,
            inventory_summary=summary,
            inventory_records=records,
            output_path=plan_output
        )

        self.assertIn("planId", plan)
        self.assertIn("target", plan)
        self.assertGreater(len(plan["extractedKnowledge"]), 0)
        self.assertGreater(len(plan["absorptionActions"]), 0)

        # Verify output files
        self.assertTrue(plan_output.exists())
        self.assertTrue(plan_output.with_suffix(".md").exists())

        # Verify destinations are valid
        valid_destinations = {
            "NEW_SKILL", "SKILL_REFERENCE", "PYTHON_SCRIPT",
            "ZOD_SCHEMA", "MCP_TOOL_OR_ENGINE", "UPDATE_EXISTING"
        }
        valid_intents = {
            "CREATE_NEW", "ABSORB_EXPAND", "UPDATE_ENHANCE",
            "ROBUSTIFY_HARDEN", "REFINE_OPTIMIZE", "CORRECT_FIX"
        }
        for action in plan["absorptionActions"]:
            self.assertIn(action["destination"], valid_destinations)
            self.assertIn(action["intent"], valid_intents)


if __name__ == "__main__":
    unittest.main()
