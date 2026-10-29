#!/usr/bin/env python3
"""Deterministic scanner for MCP tool poisoning, unicode smuggling, and rug-pull detection.

Part of Devia-CyberSecurity (Layer 3: Python Deterministic Utilities).
Zero external dependencies (pure Python 3.11+ stdlib).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

POISON_PATTERNS = [
    (r"do not (?:tell|inform|mention to) the user", "hidden_instruction"),
    (r"ignore (?:previous|prior|all) instructions", "prompt_injection_pattern"),
    (r"<(?:important|system|override)>|\[system\]", "prompt_injection_pattern"),
    (r"(?:read|access|exfiltrate|send) .*(?:\.ssh|id_rsa|\.env|credentials|passwd)", "credential_access_pattern"),
    (r"before (?:using|calling) (?:this|any) tool,? (?:you must|always)", "hidden_instruction"),
    (r"call (?:the )?\w+ tool (?:first|before)", "hidden_instruction"),
    (r"(?:send|post) .* to https?://", "credential_access_pattern"),
]

# Zero-width spaces, bidi overrides, formatting controls, Unicode tags (U+E0000 - U+E007F)
UNICODE_SMUGGLE_REGEX = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\U000e0000-\U000e007f]")


def compute_schema_digest(tool_dict: Dict[str, Any]) -> str:
    """Compute deterministic SHA-256 digest of canonical tool definition."""
    canonical_payload = {
        "name": tool_dict.get("name", ""),
        "description": tool_dict.get("description", ""),
        "inputSchema": tool_dict.get("inputSchema", {}),
        "outputSchema": tool_dict.get("outputSchema", {}),
        "annotations": tool_dict.get("annotations", {}),
    }
    raw = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def analyze_description(description: str) -> List[str]:
    """Analyze tool description for poisoning flags."""
    flags: List[str] = []
    if not description:
        return flags

    low = description.lower()
    for pattern, flag_name in POISON_PATTERNS:
        if re.search(pattern, low) and flag_name not in flags:
            flags.append(flag_name)

    if UNICODE_SMUGGLE_REGEX.search(description):
        if "unicode_smuggling" not in flags:
            flags.append("unicode_smuggling")

    if len(description) > 1500:
        if "oversized_description" not in flags:
            flags.append("oversized_description")

    return flags


def extract_tools_from_config(config_data: Any) -> List[Dict[str, Any]]:
    """Extract tool definitions from diverse MCP configuration formats."""
    tools: List[Dict[str, Any]] = []

    if isinstance(config_data, list):
        for item in config_data:
            if isinstance(item, dict) and "name" in item:
                tools.append(item)
        return tools

    if not isinstance(config_data, dict):
        return tools

    # 1. Format: Direct tools array {"tools": [...]}
    if "tools" in config_data and isinstance(config_data["tools"], list):
        for item in config_data["tools"]:
            if isinstance(item, dict) and "name" in item:
                tools.append(item)
        return tools

    # 2. Format: mcpServers dict {"mcpServers": {"serverName": {"tools": [...]}}}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        for srv_name, srv_conf in config_data["mcpServers"].items():
            if isinstance(srv_conf, dict) and "tools" in srv_conf and isinstance(srv_conf["tools"], list):
                for item in srv_conf["tools"]:
                    if isinstance(item, dict) and "name" in item:
                        tools.append(item)

    # 3. Fallback: Search recursively for any object with 'name' and 'description'
    if not tools:
        def _search_recursive(obj: Any):
            if isinstance(obj, dict):
                if "name" in obj and "description" in obj and isinstance(obj["name"], str):
                    tools.append(obj)
                for v in obj.values():
                    _search_recursive(v)
            elif isinstance(obj, list):
                for elem in obj:
                    _search_recursive(elem)

        _search_recursive(config_data)

    return tools


def scan_mcp_config(
    config_path: str,
    pinned_registry: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Scan an MCP config file, evaluate heuristics, compute digests, and check rug pulls."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    extracted_tools = extract_tools_from_config(data)
    findings: List[Dict[str, Any]] = []
    clean_count = 0
    suspicious_count = 0
    poisoned_count = 0
    current_registry: Dict[str, str] = {}

    for tool in extracted_tools:
        name = str(tool.get("name", "unnamed_tool"))
        description = str(tool.get("description", ""))
        flags = analyze_description(description)
        digest = compute_schema_digest(tool)
        current_registry[name] = digest

        rug_pull_detected = False
        pinned_digest: Optional[str] = None

        if pinned_registry and name in pinned_registry:
            pinned_digest = pinned_registry[name]
            if pinned_digest != digest:
                rug_pull_detected = True
                if "prompt_injection_pattern" not in flags:
                    flags.append("prompt_injection_pattern")

        # Determine verdict
        if "hidden_instruction" in flags or "prompt_injection_pattern" in flags or "credential_access_pattern" in flags or rug_pull_detected:
            verdict = "POISONED"
            poisoned_count += 1
        elif flags:
            verdict = "SUSPICIOUS"
            suspicious_count += 1
        else:
            verdict = "CLEAN"
            clean_count += 1

        finding_entry: Dict[str, Any] = {
            "toolName": name,
            "verdict": verdict,
            "flags": flags,
            "schemaDigest": digest,
            "descriptionLength": len(description),
            "rugPullDetected": rug_pull_detected
        }

        if flags or rug_pull_detected:
            snippet = description[:200]
            if len(description) > 200:
                snippet += "..."
            finding_entry["snippet"] = snippet

        if pinned_digest:
            finding_entry["pinnedDigest"] = pinned_digest

        findings.append(finding_entry)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "targetConfig": os.path.abspath(config_path).replace("\\", "/"),
        "totalToolsScanned": len(findings),
        "verdictCounts": {
            "clean": clean_count,
            "suspicious": suspicious_count,
            "poisoned": poisoned_count
        },
        "findings": findings,
        "pinnedToolsHashRegistry": current_registry
    }

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic MCP Tool Poisoning and Rug-Pull Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    p_scan = subparsers.add_parser("scan", help="Scan MCP config file for poisoning patterns")
    p_scan.add_argument("config", help="Path to mcp.json config")
    p_scan.add_argument("--pin-file", help="Path to previously pinned tools registry (JSON)")
    p_scan.add_argument("--json", action="store_true", help="Emit raw JSON report conforming to Zod schema")

    # pin command
    p_pin = subparsers.add_parser("pin", help="Generate pinned registry lockfile of tool schema digests")
    p_pin.add_argument("config", help="Path to mcp.json config")
    p_pin.add_argument("--output", "-o", required=True, help="Path to save pinned registry (JSON)")
    p_pin.add_argument("--json", action="store_true", help="Emit JSON output")

    # verify command
    p_verify = subparsers.add_parser("verify", help="Verify config against pinned registry for rug pulls")
    p_verify.add_argument("config", help="Path to mcp.json config")
    p_verify.add_argument("--pin-file", required=True, help="Path to pinned registry JSON")
    p_verify.add_argument("--json", action="store_true", help="Emit JSON output")

    args = parser.parse_args()

    if args.command == "scan":
        pinned: Optional[Dict[str, str]] = None
        if args.pin_file and os.path.exists(args.pin_file):
            with open(args.pin_file, "r", encoding="utf-8") as pf:
                pdata = json.load(pf)
                pinned = pdata.get("pinnedToolsHashRegistry", pdata)

        report = scan_mcp_config(args.config, pinned_registry=pinned)

        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"=== MCP Tool Poisoning Audit Report ===")
            print(f"Target: {report['targetConfig']}")
            print(f"Tools Scanned: {report['totalToolsScanned']}")
            print(f"Clean: {report['verdictCounts']['clean']} | Suspicious: {report['verdictCounts']['suspicious']} | Poisoned: {report['verdictCounts']['poisoned']}")
            for f in report["findings"]:
                if f["verdict"] != "CLEAN":
                    print(f"  [{f['verdict']}] {f['toolName']} (Flags: {', '.join(f['flags'])})")
                    if f.get("snippet"):
                        print(f"    Snippet: {repr(f['snippet'])}")
                    if f.get("rugPullDetected"):
                        print(f"    [!] RUG PULL DETECTED: Digest mismatch from pinned baseline")

        sys.exit(1 if report["verdictCounts"]["poisoned"] > 0 else 0)

    elif args.command == "pin":
        report = scan_mcp_config(args.config)
        with open(args.output, "w", encoding="utf-8") as out_f:
            json.dump(report["pinnedToolsHashRegistry"], out_f, indent=2, ensure_ascii=False)

        if args.json:
            print(json.dumps({"pinnedFile": args.output, "toolsPinned": len(report["pinnedToolsHashRegistry"])}, indent=2))
        else:
            print(f"Successfully pinned {len(report['pinnedToolsHashRegistry'])} tool digests to {args.output}")

    elif args.command == "verify":
        with open(args.pin_file, "r", encoding="utf-8") as pf:
            pdata = json.load(pf)
            pinned = pdata.get("pinnedToolsHashRegistry", pdata)

        report = scan_mcp_config(args.config, pinned_registry=pinned)
        rug_pulls = [f for f in report["findings"] if f.get("rugPullDetected")]

        if args.json:
            print(json.dumps({
                "verified": len(rug_pulls) == 0,
                "rugPullCount": len(rug_pulls),
                "rugPulls": rug_pulls
            }, indent=2))
        else:
            if rug_pulls:
                print(f"[!] RUG PULL ALERT: {len(rug_pulls)} tools changed since pinning!")
                for r in rug_pulls:
                    print(f"  Tool: {r['toolName']} - Current: {r['schemaDigest']} vs Pinned: {r.get('pinnedDigest')}")
            else:
                print("All tool digests verified match pinned baseline. Zero rug pulls detected.")

        sys.exit(1 if rug_pulls else 0)


if __name__ == "__main__":
    main()
