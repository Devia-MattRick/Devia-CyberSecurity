#!/usr/bin/env python3
"""Deterministic Scanner for Spreadsheet & CSV Formula Injection (CWE-1236) in Devia-CyberSecurity (Capa 3).

Audits source code exporters and static CSV/XLSX datasets for:
1. Missing formula prefix sanitization (=, +, -, @, \\t, \\r, |, %).
2. Missing UTF-8 BOM (\\uFEFF) in CSV output streams.
3. Dangerous unescaped spreadsheet cells starting with DDE commands or formula triggers.

Conforms strictly to Devia-CyberSecurity's Capa 3 standards:
- Deterministic execution without running target code.
- Fully typed Python 3.11+.
- CLI output supporting formatted text and structured --json.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


DANGEROUS_PREFIXES = ["=", "+", "-", "@", "\t", "\r", "|", "%"]
DANGEROUS_PREFIX_REGEX = re.compile(r"^[=+\-@\t\r|%]")

# Patterns identifying CSV/Excel generation functions or sinks
EXPORTER_KEYWORDS = [
    "csv", "xlsx", "excel", "spreadsheet", "exporttocsv", "sanitizecsvcell",
    "export_leads_file", "writecsv", "createobjecturl", "text/csv"
]

CODE_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".cs", ".php", ".rb"}
TABULAR_EXTENSIONS = {".csv", ".tsv"}


def get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def analyze_code_file(path: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    lines = content.splitlines()
    has_exporter = any(kw in content.lower() for kw in EXPORTER_KEYWORDS)
    if not has_exporter:
        return findings

    has_bom = "\\uFEFF" in content or "\ufeff" in content or "0xEF, 0xBB, 0xBF" in content
    has_sanitization = bool(re.search(r"^[=+\-@\\t\\r|%]", content) or re.search(r"\^[=+\-@]", content))

    # Look for export functions lacking sanitization
    for idx, line in enumerate(lines, start=1):
        line_lower = line.lower()
        if any(term in line_lower for term in ["function export", "exportcsv", "tocsv", "generatecsv", "sanitizecsv"]):
            # Check if this function or nearby lines implement the defense
            window = "\n".join(lines[max(0, idx - 1):min(len(lines), idx + 25)])
            if not re.search(r"^[=+\-@]", window) and not "sanitizecsvcell" in window.lower():
                missing = DANGEROUS_PREFIXES.copy()
                findings.append({
                    "id": f"FORMULA-CODE-{path.name.replace('.', '_')}-{idx}",
                    "filePath": str(path.as_posix()),
                    "line": idx,
                    "format": "CSV" if "csv" in line_lower else "XLSX",
                    "verdict": "VULNERABLE_DIRECT_RAW",
                    "functionOrMethod": line.strip()[:60],
                    "codeSnippet": line.strip(),
                    "missingPrefixes": missing,
                    "bomEnforced": has_bom,
                    "explanation": "Función de exportación de datos tabulares sin sanitización preventiva de fórmulas (=, +, -, @, \\t, \\r, |, %).",
                    "remediationSnippet": "if (/^[=+\\-@\\t\\r|%]/.test(s)) { s = `'${s}`; } return `\"${s.replace(/\"/g, '\"\"')}\"`;"
                })

    return findings


def analyze_tabular_file(path: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        with path.open("rb") as f:
            header = f.read(3)
            has_bom = (header == b"\xef\xbb\xbf")
    except Exception:
        return findings

    if not has_bom:
        findings.append({
            "id": f"FORMULA-BOM-{path.name.replace('.', '_')}-1",
            "filePath": str(path.as_posix()),
            "line": 1,
            "format": "CSV",
            "verdict": "MISSING_UTF8_BOM",
            "functionOrMethod": None,
            "codeSnippet": f"File starts with bytes {header.hex()}",
            "missingPrefixes": [],
            "bomEnforced": False,
            "explanation": "El archivo CSV carece del prefijo Byte Order Mark UTF-8 (\\uFEFF), lo que puede causar corrupción de caracteres y comportamiento errático en Microsoft Excel.",
            "remediationSnippet": "Prefijar con \\uFEFF al generar el buffer o stream CSV."
        })

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        for idx, line in enumerate(content.splitlines()[:100], start=1):
            cells = [c.strip().strip('"') for c in line.split(",")]
            for cell in cells:
                if cell and cell[0] in DANGEROUS_PREFIXES and len(cell) > 1:
                    findings.append({
                        "id": f"FORMULA-RAW-{path.name.replace('.', '_')}-{idx}",
                        "filePath": str(path.as_posix()),
                        "line": idx,
                        "format": "CSV",
                        "verdict": "VULNERABLE_DIRECT_RAW",
                        "functionOrMethod": None,
                        "codeSnippet": line.strip()[:100],
                        "missingPrefixes": [cell[0]],
                        "bomEnforced": has_bom,
                        "explanation": f"Celda cruda '{cell[:20]}' comienza con carácter de fórmula peligroso sin neutralizar con comilla simple.",
                        "remediationSnippet": f"Prefijar con comilla simple: '{cell[:20]}"
                    })
                    break
    except Exception:
        pass

    return findings


def scan_directory(target_path: Path) -> Dict[str, Any]:
    all_findings: List[Dict[str, Any]] = []
    export_functions_analyzed = 0

    for root, dirs, files in os.walk(target_path):
        # Skip noisy runtime directories
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv", "__pycache__", "dist"}]
        for file in files:
            p = Path(root) / file
            ext = p.suffix.lower()
            if ext in CODE_EXTENSIONS:
                code_findings = analyze_code_file(p)
                if code_findings:
                    all_findings.extend(code_findings)
                    export_functions_analyzed += len(code_findings)
            elif ext in TABULAR_EXTENSIONS:
                tab_findings = analyze_tabular_file(p)
                if tab_findings:
                    all_findings.extend(tab_findings)
                    export_functions_analyzed += 1

    status = "COMPLIANT" if not all_findings else "NON_COMPLIANT"
    return {
        "targetPath": str(target_path.resolve().as_posix()),
        "scannedAt": get_utc_timestamp(),
        "totalExportFunctionsAnalyzed": export_functions_analyzed,
        "vulnerableCount": len(all_findings),
        "findings": all_findings,
        "overallStatus": status
    }


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic scanner for Spreadsheet & CSV Formula Injection (CWE-1236)"
    )
    parser.add_argument("target", help="Directory, file, or repository to audit")
    parser.add_argument("--json", action="store_true", help="Output results in structured JSON format")
    args = parser.parse_args()

    target = Path(args.target).expanduser().resolve()
    if not target.exists():
        print(f"Error: Target '{target}' does not exist.", file=sys.stderr)
        sys.exit(2)

    report = scan_directory(target)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"--- Devia-CyberSecurity Formula Injection Scanner (CWE-1236) ---")
        print(f"Target: {report['targetPath']}")
        print(f"Status: {report['overallStatus']}")
        print(f"Findings: {report['vulnerableCount']}")
        for f in report["findings"]:
            print(f"  [{f['verdict']}] {f['filePath']}:{f['line']} - {f['explanation']}")

    sys.exit(0 if report["overallStatus"] == "COMPLIANT" else 1)


if __name__ == "__main__":
    main()
