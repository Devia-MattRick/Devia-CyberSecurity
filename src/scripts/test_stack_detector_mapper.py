#!/usr/bin/env python3
"""test_stack_detector_mapper.py — Unit tests for stack_detector_mapper.py."""

import json
import os
import shutil
import tempfile
import unittest

from src.scripts.stack_detector_mapper import compute_dimensional_mapping, scan_target_stack


class TestStackDetectorMapper(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="devia_test_stack_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_scan_empty_repo(self):
        recon = scan_target_stack(self.test_dir)
        self.assertEqual(recon["totalFilesDiscovered"], 0)
        self.assertEqual(len(recon["languages"]), 0)

        mapping = compute_dimensional_mapping(recon)
        # Baselines are always active
        self.assertIn("SOURCE_CODE_SAST", mapping["activeDimensions"])
        self.assertIn("SECRETS_CRYPTOGRAPHY", mapping["activeDimensions"])
        self.assertIn("THREAT_MODELING_ATTACK_SURFACE", mapping["activeDimensions"])
        self.assertIn("scan_secrets.py", mapping["recommendedScripts"])

    def test_scan_node_typescript_repo(self):
        # Create dummy package.json and ts files
        pkg_json = {
            "name": "dummy-app",
            "dependencies": {
                "express": "^4.18.2",
                "jsonwebtoken": "^9.0.0",
                "pg": "^8.11.0"
            }
        }
        with open(os.path.join(self.test_dir, "package.json"), "w", encoding="utf-8") as f:
            json.dump(pkg_json, f)

        with open(os.path.join(self.test_dir, "index.ts"), "w", encoding="utf-8") as f:
            f.write("import express from 'express';\nconst app = express();\n")

        with open(os.path.join(self.test_dir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write("FROM node:20-alpine\nCOPY . .\nCMD ['node', 'dist/index.js']\n")

        recon = scan_target_stack(self.test_dir)
        self.assertIn("TypeScript", recon["languages"])
        self.assertIn("Express", recon["frameworks"])
        self.assertIn("JWT / Token Auth", recon["authPatterns"])
        self.assertIn("PostgreSQL", recon["databases"])
        self.assertIn("Docker", recon["infrastructure"])

        mapping = compute_dimensional_mapping(recon)
        self.assertIn("SUPPLY_CHAIN_SCA", mapping["activeDimensions"])
        self.assertIn("IDENTITY_ACCESS_SESSION", mapping["activeDimensions"])
        self.assertIn("CONFIGURATION_HARDENING", mapping["activeDimensions"])
        self.assertIn("check_lockfiles.py", mapping["recommendedScripts"])
        self.assertIn("role_mining_analyzer.py", mapping["recommendedScripts"])
        self.assertIn("endpoint_hardening_auditor.py", mapping["recommendedScripts"])

    def test_scan_ai_agent_mcp_repo(self):
        pkg_json = {
            "name": "agent-mcp-tool",
            "dependencies": {
                "@modelcontextprotocol/sdk": "^1.0.0",
                "openai": "^4.0.0"
            }
        }
        with open(os.path.join(self.test_dir, "package.json"), "w", encoding="utf-8") as f:
            json.dump(pkg_json, f)

        recon = scan_target_stack(self.test_dir)
        self.assertIn("LLM / Agentic Systems / MCP", recon["aiAndAgentic"])

        mapping = compute_dimensional_mapping(recon)
        self.assertIn("mcp_tool_poisoning_scanner.py", mapping["recommendedScripts"])
        self.assertIn("prompt_injection_detector.py", mapping["recommendedScripts"])
        self.assertIn("VULN-ARCH-011", mapping["priorityVulnerabilities"])


if __name__ == "__main__":
    unittest.main()

