#!/usr/bin/env python3
"""Deterministic Hard Exclusion and Noise Reduction Engine for Devia-CyberSecurity.

Absorbed and hardened from Claude Code Security Reviewer (Anthropic).
Provides O(1) precompiled regex heuristics to discard low-signal security findings
(generic DoS, missing rate limiting, unclosed resource leaks, open redirects without impact,
memory safety issues in memory-safe languages, SSRF in HTML) while strictly preserving
genuine vulnerabilities that demonstrate actionable exploit scenarios.

Zero external dependencies (Python 3.11+ stdlib only).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Pattern, Tuple


@dataclass
class ExclusionResult:
    is_excluded: bool
    reason: Optional[str] = None
    rule_category: Optional[str] = None
    exploit_override: bool = False


@dataclass
class FilterSummary:
    total_findings: int = 0
    kept_findings: int = 0
    excluded_findings: int = 0
    exploit_overrides: int = 0
    breakdown_by_category: Dict[str, int] = field(default_factory=dict)


class HardExclusionEngine:
    """Pre-compiled regex engine for high-throughput finding filtering."""

    # Denial of Service & Resource Exhaustion (Low-signal unless proven critical)
    _DOS_PATTERNS: List[Pattern] = [
        re.compile(r"\b(denial of service|dos attack|resource exhaustion)\b", re.IGNORECASE),
        re.compile(r"\b(exhaust|overwhelm|overload).*?(resource|memory|cpu)\b", re.IGNORECASE),
        re.compile(r"\b(infinite|unbounded).*?(loop|recursion)\b", re.IGNORECASE),
    ]

    # Rate Limiting concerns (Perimeter / Gateway handled)
    _RATE_LIMITING_PATTERNS: List[Pattern] = [
        re.compile(r"\b(missing|lack of|no)\s+rate\s+limit", re.IGNORECASE),
        re.compile(r"\brate\s+limiting\s+(missing|required|not implemented)", re.IGNORECASE),
        re.compile(r"\b(implement|add)\s+rate\s+limit", re.IGNORECASE),
        re.compile(r"\bunlimited\s+(requests|calls|api)", re.IGNORECASE),
    ]

    # Resource management & unclosed handles
    _RESOURCE_LEAK_PATTERNS: List[Pattern] = [
        re.compile(r"\b(resource|memory|file)\s+leak\s+potential", re.IGNORECASE),
        re.compile(r"\bunclosed\s+(resource|file|connection|stream|handle)", re.IGNORECASE),
        re.compile(r"\b(close|cleanup|release)\s+(resource|file|connection|socket)", re.IGNORECASE),
        re.compile(r"\bpotential\s+memory\s+leak", re.IGNORECASE),
        re.compile(r"\b(database|thread|socket|connection)\s+leak", re.IGNORECASE),
    ]

    # Open Redirect without demonstrated impact chain
    _OPEN_REDIRECT_PATTERNS: List[Pattern] = [
        re.compile(r"\b(open redirect|unvalidated redirect)\b", re.IGNORECASE),
        re.compile(r"\b(redirect.(attack|exploit|vulnerability))\b", re.IGNORECASE),
        re.compile(r"\b(malicious.redirect)\b", re.IGNORECASE),
    ]

    # Memory Safety (buffer overflows, UAF, bounds checks) in non-native languages
    _MEMORY_SAFETY_PATTERNS: List[Pattern] = [
        re.compile(r"\b(buffer overflow|stack overflow|heap overflow)\b", re.IGNORECASE),
        re.compile(r"\b(oob)\s+(read|write|access)\b", re.IGNORECASE),
        re.compile(r"\b(out.?of.?bounds?)\b", re.IGNORECASE),
        re.compile(r"\b(memory safety|memory corruption)\b", re.IGNORECASE),
        re.compile(r"\b(use.?after.?free|double.?free|null.?pointer.?dereference)\b", re.IGNORECASE),
        re.compile(r"\b(segmentation fault|segfault|memory violation)\b", re.IGNORECASE),
        re.compile(r"\b(bounds check|boundary check|array bounds)\b", re.IGNORECASE),
        re.compile(r"\b(integer overflow|integer underflow|integer conversion)\b", re.IGNORECASE),
        re.compile(r"\barbitrary.?(memory read|pointer dereference|memory address|memory pointer)\b", re.IGNORECASE),
    ]

    # Regex injection / Regex DoS
    _REGEX_INJECTION_PATTERNS: List[Pattern] = [
        re.compile(r"\b(regex|regular expression)\s+injection\b", re.IGNORECASE),
        re.compile(r"\b(regex|regular expression)\s+denial of service\b", re.IGNORECASE),
        re.compile(r"\b(regex|regular expression)\s+flooding\b", re.IGNORECASE),
        re.compile(r"\bredos\b", re.IGNORECASE),
    ]

    # SSRF patterns
    _SSRF_PATTERNS: List[Pattern] = [
        re.compile(r"\b(ssrf|server\s+.?side\s+.?request\s+.?forgery)\b", re.IGNORECASE),
    ]

    # Exploit override indicators (preserves findings with proven attack scenarios)
    _EXPLOIT_INDICATORS: List[Pattern] = [
        re.compile(r"\b(remote code execution|rce|arbitrary command execution)\b", re.IGNORECASE),
        re.compile(r"\b(sql injection|sqli|command injection|path traversal)\b", re.IGNORECASE),
        re.compile(r"\b(privilege escalation|authentication bypass|auth bypass)\b", re.IGNORECASE),
        re.compile(r"\b(data exfiltration|account takeover)\b", re.IGNORECASE),
        re.compile(r"\b(exploit scenario|attack path|cve-\d+)\b", re.IGNORECASE),
    ]

    C_CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"}
    HTML_EXTENSIONS = {".html", ".htm"}
    MARKDOWN_EXTENSIONS = {".md", ".markdown", ".rst"}

    @classmethod
    def evaluate_finding(cls, finding: Dict[str, Any]) -> ExclusionResult:
        """Evaluate a single security finding against deterministic hard exclusion rules."""
        file_path = str(finding.get("file") or finding.get("target_path") or finding.get("path") or "").lower()
        title = str(finding.get("title") or finding.get("name") or "")
        description = str(finding.get("description") or finding.get("message") or "")
        category = str(finding.get("category") or "")
        exploit_scenario = str(finding.get("exploit_scenario") or "")

        combined_text = f"{title} {description} {category}".lower()

        # Rule 1: Exclude documentation files (markdown, rst)
        if any(file_path.endswith(ext) for ext in cls.MARKDOWN_EXTENSIONS):
            return ExclusionResult(
                is_excluded=True,
                reason="Finding in Markdown or documentation file",
                rule_category="DOCUMENTATION_FILE"
            )

        # Check for exploit override
        has_exploit_proof = bool(exploit_scenario.strip()) or any(
            p.search(f"{combined_text} {exploit_scenario.lower()}") for p in cls._EXPLOIT_INDICATORS
        )

        # Rule 2: DoS & Resource Exhaustion
        for pattern in cls._DOS_PATTERNS:
            if pattern.search(combined_text):
                if has_exploit_proof and ("rce" in combined_text or "code execution" in combined_text):
                    return ExclusionResult(is_excluded=False, exploit_override=True)
                return ExclusionResult(
                    is_excluded=True,
                    reason="Generic DoS or resource exhaustion finding (low signal)",
                    rule_category="DOS_RESOURCE_EXHAUSTION"
                )

        # Rule 3: Missing rate limiting
        for pattern in cls._RATE_LIMITING_PATTERNS:
            if pattern.search(combined_text):
                return ExclusionResult(
                    is_excluded=True,
                    reason="Generic rate limiting recommendation (perimeter/gateway concern)",
                    rule_category="RATE_LIMITING"
                )

        # Rule 4: Resource / memory leaks
        for pattern in cls._RESOURCE_LEAK_PATTERNS:
            if pattern.search(combined_text):
                return ExclusionResult(
                    is_excluded=True,
                    reason="Resource management finding (not an exploitable vulnerability)",
                    rule_category="RESOURCE_MANAGEMENT"
                )

        # Rule 5: Open redirect
        for pattern in cls._OPEN_REDIRECT_PATTERNS:
            if pattern.search(combined_text):
                # If tied to OAuth or ATO, keep it
                if "oauth" in combined_text or "account takeover" in combined_text or "ato" in combined_text:
                    return ExclusionResult(is_excluded=False, exploit_override=True)
                return ExclusionResult(
                    is_excluded=True,
                    reason="Isolated open redirect vulnerability (acceptable risk without exploit chain)",
                    rule_category="OPEN_REDIRECT"
                )

        # Rule 6: Regex injection / ReDoS
        for pattern in cls._REGEX_INJECTION_PATTERNS:
            if pattern.search(combined_text):
                return ExclusionResult(
                    is_excluded=True,
                    reason="Regex injection or ReDoS finding (excluded by hard precedent)",
                    rule_category="REGEX_INJECTION"
                )

        # Rule 7: Memory safety in non-C/C++ code
        file_ext = Path(file_path).suffix.lower() if "." in file_path else ""
        if file_ext and file_ext not in cls.C_CPP_EXTENSIONS:
            for pattern in cls._MEMORY_SAFETY_PATTERNS:
                if pattern.search(combined_text):
                    return ExclusionResult(
                        is_excluded=True,
                        reason=f"Memory safety finding in non-native managed code ({file_ext})",
                        rule_category="MEMORY_SAFETY_IN_SAFE_LANGUAGE"
                    )

        # Rule 8: SSRF in client-side HTML
        if file_ext in cls.HTML_EXTENSIONS:
            for pattern in cls._SSRF_PATTERNS:
                if pattern.search(combined_text):
                    return ExclusionResult(
                        is_excluded=True,
                        reason="SSRF finding in client-side HTML file (not applicable)",
                        rule_category="CLIENT_SIDE_SSRF"
                    )

        return ExclusionResult(is_excluded=False)

    @classmethod
    def filter_findings(cls, findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], FilterSummary]:
        """Filter a collection of findings, returning (kept, excluded, summary)."""
        kept: List[Dict[str, Any]] = []
        excluded: List[Dict[str, Any]] = []
        summary = FilterSummary(total_findings=len(findings))

        for finding in findings:
            res = cls.evaluate_finding(finding)
            if res.is_excluded:
                excluded_item = {
                    "finding": finding,
                    "exclusion_reason": res.reason,
                    "rule_category": res.rule_category
                }
                excluded.append(excluded_item)
                summary.excluded_findings += 1
                cat = res.rule_category or "OTHER"
                summary.breakdown_by_category[cat] = summary.breakdown_by_category.get(cat, 0) + 1
            else:
                if res.exploit_override:
                    summary.exploit_overrides += 1
                kept.append(finding)
                summary.kept_findings += 1

        return kept, excluded, summary


def main():
    parser = argparse.ArgumentParser(description="Deterministic Hard Exclusion Engine for Devia-CyberSecurity")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: filter
    filter_parser = subparsers.add_parser("filter", help="Filter findings from a JSON file")
    filter_parser.add_argument("input_file", help="Path to findings JSON file (array or object with 'findings' key)")
    filter_parser.add_argument("-o", "--output", help="Optional path to output filtered findings JSON")
    filter_parser.add_argument("--json", action="store_true", help="Print summary in JSON format")

    # Subcommand: test-text
    test_parser = subparsers.add_parser("test-text", help="Test arbitrary text against exclusion rules")
    test_parser.add_argument("text", help="Text to evaluate (title/description)")
    test_parser.add_argument("--file", default="", help="File path context")
    test_parser.add_argument("--json", action="store_true", help="Output result as JSON")

    args = parser.parse_args()

    if args.command == "test-text":
        finding = {
            "title": args.text,
            "description": args.text,
            "file": args.file
        }
        res = HardExclusionEngine.evaluate_finding(finding)
        out = {
            "is_excluded": res.is_excluded,
            "reason": res.reason,
            "rule_category": res.rule_category,
            "exploit_override": res.exploit_override
        }
        if args.json:
            print(json.dumps(out, indent=2))
        else:
            if res.is_excluded:
                print(f"[EXCLUDED] Category: {res.rule_category} | Reason: {res.reason}")
            else:
                print(f"[KEPT] Exploit Override: {res.exploit_override}")

    elif args.command == "filter":
        in_path = Path(args.input_file)
        if not in_path.exists():
            print(f"Error: file not found: {in_path}", file=sys.stderr)
            sys.exit(1)

        with open(in_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings: List[Dict[str, Any]]
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
            findings = data["findings"]
        else:
            print("Error: JSON must be an array of findings or an object with 'findings' array.", file=sys.stderr)
            sys.exit(1)

        kept, excluded, summary = HardExclusionEngine.filter_findings(findings)

        result_payload = {
            "summary": {
                "total_findings": summary.total_findings,
                "kept_findings": summary.kept_findings,
                "excluded_findings": summary.excluded_findings,
                "exploit_overrides": summary.exploit_overrides,
                "breakdown_by_category": summary.breakdown_by_category
            },
            "kept_findings": kept,
            "excluded_findings": excluded
        }

        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result_payload, f, indent=2, ensure_ascii=False)
            print(f"Filtered results written to {out_path}", file=sys.stderr)

        if args.json or not args.output:
            print(json.dumps(result_payload["summary"], indent=2))


if __name__ == "__main__":
    main()
