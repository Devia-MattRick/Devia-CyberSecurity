#!/usr/bin/env python3
"""Unit tests for scan_formula_injection.py (Capa 3)."""

import json
from pathlib import Path
import tempfile
import unittest

from src.scripts.scan_formula_injection import (
    analyze_code_file,
    analyze_tabular_file,
    scan_directory,
    DANGEROUS_PREFIXES
)


class TestScanFormulaInjection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dangerous_prefixes_complete(self):
        expected = ["=", "+", "-", "@", "\t", "\r", "|", "%"]
        for p in expected:
            self.assertIn(p, DANGEROUS_PREFIXES)

    def test_clean_exporter_not_flagged(self):
        clean_code = '''
        export class SafeExporter {
          exportCsv(rows: any[]) {
            const bom = "\\uFEFF";
            return bom + rows.map(r => this.sanitizeCsvCell(r)).join("\\n");
          }
          sanitizeCsvCell(val: unknown): string {
            let s = String(val).trim();
            if (/^[=+\\-@\\t\\r|%]/.test(s)) {
              s = `'${s}`;
            }
            return `"${s.replace(/"/g, '""')}"`;
          }
        }
        '''
        clean_file = self.dir_path / "safe-exporter.ts"
        clean_file.write_text(clean_code, encoding="utf-8")

        findings = analyze_code_file(clean_file)
        self.assertEqual(len(findings), 0)

    def test_vulnerable_exporter_flagged(self):
        vuln_code = '''
        export function exportCsv(leads: any[]) {
          return leads.map(l => `${l.name},${l.company}`).join("\\n");
        }
        '''
        vuln_file = self.dir_path / "vuln-exporter.ts"
        vuln_file.write_text(vuln_code, encoding="utf-8")

        findings = analyze_code_file(vuln_file)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["verdict"], "VULNERABLE_DIRECT_RAW")

    def test_csv_missing_bom_and_dangerous_cell(self):
        csv_file = self.dir_path / "leads.csv"
        # Write without UTF-8 BOM
        content = "name,command\nJohn,=cmd|'/C calc'!A0\n"
        csv_file.write_text(content, encoding="utf-8")

        findings = analyze_tabular_file(csv_file)
        verdicts = [f["verdict"] for f in findings]
        self.assertIn("MISSING_UTF8_BOM", verdicts)
        self.assertIn("VULNERABLE_DIRECT_RAW", verdicts)

    def test_full_scan_directory_json(self):
        # Create one safe and one vuln file
        safe_file = self.dir_path / "safe.ts"
        safe_file.write_text('// no csv exporter here\nexport const x = 1;', encoding="utf-8")

        report = scan_directory(self.dir_path)
        self.assertIn("overallStatus", report)
        self.assertIn("vulnerableCount", report)


if __name__ == "__main__":
    unittest.main()
