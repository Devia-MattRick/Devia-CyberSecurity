#!/usr/bin/env python3
"""Unit tests for target_snapshot.py."""

import json
from pathlib import Path
import tempfile
import unittest

from target_snapshot import (
    compute_directory_snapshot,
    derive_primary_fingerprint
)


class TestTargetSnapshot(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Create dummy directory structure
        (self.root / "sub").mkdir(parents=True)
        (self.root / "fileA.txt").write_text("Hello World", encoding="utf-8")
        (self.root / "sub" / "fileB.txt").write_text("Security Research", encoding="utf-8")

        # Excluded dir
        (self.root / "node_modules").mkdir()
        (self.root / "node_modules" / "ignored.js").write_text("ignored", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_deterministic_directory_snapshot(self):
        digest1, inv1 = compute_directory_snapshot(self.root)
        digest2, inv2 = compute_directory_snapshot(self.root)

        self.assertTrue(digest1.startswith("devia-snapshot/v1:sha256:"))
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(inv1), 2)
        self.assertEqual(inv1[0]["path"], "fileA.txt")
        self.assertEqual(inv1[1]["path"], "sub/fileB.txt")

    def test_primary_fingerprint_derivation(self):
        target = "repo_target_123"
        rule = "path-traversal.archive-extraction"
        anchor = "zip-extract-handler"
        instance = "unzip-helper"

        fp1 = derive_primary_fingerprint(target, rule, anchor, instance)
        fp2 = derive_primary_fingerprint(target, rule, anchor, instance)

        self.assertTrue(fp1.startswith("devia/v1:sha256:"))
        self.assertEqual(fp1, fp2)

        # Different instance produces different fingerprint
        fp3 = derive_primary_fingerprint(target, rule, anchor, "other-instance")
        self.assertNotEqual(fp1, fp3)


if __name__ == "__main__":
    unittest.main()
