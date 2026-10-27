#!/usr/bin/env python3
"""SARIF 2.1.0 Processing, Merging, and Filtering Toolkit for Devia-CyberSecurity.

Deterministic, zero-dependency Python 3.11+ utility to parse, normalize,
filter, summarize, and merge Static Analysis Results Interchange Format (SARIF 2.1.0)
files produced by security scanners (e.g., Semgrep, CodeQL).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import unquote


@dataclass
class SarifFinding:
    """Structured representation of a SARIF finding."""
    rule_id: str
    level: str
    message: str
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    fingerprint: Optional[str] = None
    tool_name: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("raw", None)
        return data


def load_sarif(path: Path | str) -> Dict[str, Any]:
    """Load and parse a SARIF JSON file."""
    p = Path(path).expanduser().resolve()
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid SARIF structure in {path}: expected JSON object")
    return data


def save_sarif(data: Dict[str, Any], path: Path | str, indent: int = 2) -> None:
    """Save SARIF data to a file."""
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def validate_sarif_version(sarif: Dict[str, Any]) -> bool:
    """Check if SARIF version is 2.1.0."""
    return sarif.get("version") == "2.1.0"


def normalize_artifact_uri(uri: str, base_path: str = "") -> str:
    """Normalize SARIF artifact URI to a consistent relative or absolute path."""
    if not uri:
        return ""
    if uri.startswith("file:///"):
        uri = uri[8:] if os.name == "nt" and len(uri) > 9 and uri[9] == ":" else uri[7:]
    elif uri.startswith("file://"):
        uri = uri[7:]
    uri = unquote(uri).replace("\\", "/")
    if base_path and not Path(uri).is_absolute():
        uri = str(Path(base_path) / uri).replace("\\", "/")
    return uri


def safe_get(data: Any, *keys: Any, default: Any = None) -> Any:
    """Safely navigate nested dictionaries and lists."""
    curr = data
    for key in keys:
        if isinstance(curr, dict) and key in curr:
            curr = curr[key]
        elif isinstance(curr, list) and isinstance(key, int) and 0 <= key < len(curr):
            curr = curr[key]
        else:
            return default
    return curr if curr is not None else default


def extract_location(result: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """Extract normalized file path, start line, and end line from result."""
    loc = safe_get(result, "locations", 0, default={})
    phys = loc.get("physicalLocation", {})
    region = phys.get("region", {})

    raw_uri = safe_get(phys, "artifactLocation", "uri")
    file_path = normalize_artifact_uri(raw_uri) if raw_uri else None
    start_line = region.get("startLine")
    end_line = region.get("endLine", start_line)

    return file_path, start_line, end_line


def iter_results(sarif: Dict[str, Any]) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """Iterate over all results paired with their parent run context."""
    for run in sarif.get("runs", []):
        if not isinstance(run, dict):
            continue
        for res in run.get("results", []):
            if isinstance(res, dict):
                yield res, run


def extract_findings(sarif: Dict[str, Any]) -> List[SarifFinding]:
    """Extract findings as structured objects."""
    findings: List[SarifFinding] = []

    for result, run in iter_results(sarif):
        tool_name = safe_get(run, "tool", "driver", "name")
        file_path, start_line, end_line = extract_location(result)
        loc = safe_get(result, "locations", 0, default={})
        region = safe_get(loc, "physicalLocation", "region", default={})

        fp = None
        if result.get("partialFingerprints"):
            fp = next(iter(result["partialFingerprints"].values()), None)
        elif result.get("fingerprints"):
            fp = next(iter(result["fingerprints"].values()), None)

        msg = safe_get(result, "message", "text", default="")

        findings.append(
            SarifFinding(
                rule_id=result.get("ruleId", "unknown"),
                level=result.get("level", "warning"),
                message=msg,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                start_column=region.get("startColumn"),
                end_column=region.get("endColumn"),
                fingerprint=fp,
                tool_name=tool_name,
                raw=result
            )
        )

    return findings


def summarize_sarif(sarif: Dict[str, Any]) -> Dict[str, Any]:
    """Produce summary statistics from a SARIF file."""
    findings = extract_findings(sarif)
    level_counts: Dict[str, int] = defaultdict(int)
    rule_counts: Dict[str, int] = defaultdict(int)
    tool_counts: Dict[str, int] = defaultdict(int)

    for f in findings:
        level_counts[f.level] += 1
        rule_counts[f.rule_id] += 1
        if f.tool_name:
            tool_counts[f.tool_name] += 1

    return {
        "version": sarif.get("version", "unknown"),
        "totalRuns": len(sarif.get("runs", [])),
        "totalFindings": len(findings),
        "levels": dict(level_counts),
        "topRules": sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        "tools": dict(tool_counts)
    }


def merge_sarifs(sarif_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple SARIF files into a unified SARIF 2.1.0 document."""
    if not sarif_list:
        return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []}

    merged_runs: List[Dict[str, Any]] = []
    seen_fingerprints = set()

    for sarif in sarif_list:
        for run in sarif.get("runs", []):
            if not isinstance(run, dict):
                continue
            
            tool = run.get("tool", {})
            orig_results = run.get("results", [])
            deduped_results = []

            for r in orig_results:
                rule_id = r.get("ruleId", "")
                loc = safe_get(r, "locations", 0, "physicalLocation", "artifactLocation", "uri", default="")
                line = safe_get(r, "locations", 0, "physicalLocation", "region", "startLine", default=0)
                fp = f"{rule_id}:{loc}:{line}"

                if fp not in seen_fingerprints:
                    seen_fingerprints.add(fp)
                    deduped_results.append(r)

            run_copy = dict(run)
            run_copy["results"] = deduped_results
            merged_runs.append(run_copy)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": merged_runs
    }


def filter_sarif(
    sarif: Dict[str, Any],
    levels: Optional[List[str]] = None,
    rules: Optional[List[str]] = None,
    file_pattern: Optional[str] = None
) -> Dict[str, Any]:
    """Filter SARIF results based on levels, rules, and file path substring."""
    level_set = set(levels) if levels else None
    rule_set = set(rules) if rules else None

    filtered_runs = []
    for run in sarif.get("runs", []):
        if not isinstance(run, dict):
            continue
        new_results = []
        for r in run.get("results", []):
            if level_set and r.get("level", "warning") not in level_set:
                continue
            if rule_set and r.get("ruleId") not in rule_set:
                continue
            if file_pattern:
                uri, _, _ = extract_location(r)
                if not uri or file_pattern not in uri:
                    continue
            new_results.append(r)

        run_copy = dict(run)
        run_copy["results"] = new_results
        filtered_runs.append(run_copy)

    return {
        "$schema": sarif.get("$schema", "https://json.schemastore.org/sarif-2.1.0.json"),
        "version": "2.1.0",
        "runs": filtered_runs
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="SARIF 2.1.0 Processing Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: summary
    p_summary = subparsers.add_parser("summary", help="Summarize SARIF file")
    p_summary.add_argument("file", help="Path to SARIF file")
    p_summary.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: merge
    p_merge = subparsers.add_parser("merge", help="Merge multiple SARIF files")
    p_merge.add_argument("files", nargs="+", help="Input SARIF files")
    p_merge.add_argument("-o", "--output", required=True, help="Output merged SARIF path")
    p_merge.add_argument("--json", action="store_true", help="Output status in JSON")

    # Subcommand: filter
    p_filter = subparsers.add_parser("filter", help="Filter SARIF findings")
    p_filter.add_argument("file", help="Input SARIF file")
    p_filter.add_argument("-o", "--output", required=True, help="Output filtered SARIF path")
    p_filter.add_argument("--level", help="Comma-separated severity levels (error,warning,note)")
    p_filter.add_argument("--rule", help="Comma-separated rule IDs")
    p_filter.add_argument("--path-pattern", help="Substring match on file path")
    p_filter.add_argument("--json", action="store_true", help="Output status in JSON")

    args = parser.parse_args()

    try:
        if args.command == "summary":
            data = load_sarif(args.file)
            summary = summarize_sarif(data)
            if args.json:
                print(json.dumps(summary, indent=2))
            else:
                print(f"SARIF Version: {summary['version']}")
                print(f"Total Runs:    {summary['totalRuns']}")
                print(f"Total Findings:{summary['totalFindings']}")
                print("\nSeverity Levels:")
                for lvl, cnt in summary["levels"].items():
                    print(f"  {lvl}: {cnt}")
                print("\nTop Rules:")
                for rule, cnt in summary["topRules"]:
                    print(f"  {rule}: {cnt}")

        elif args.command == "merge":
            sarifs = [load_sarif(f) for f in args.files]
            merged = merge_sarifs(sarifs)
            save_sarif(merged, args.output)
            total = sum(len(r.get("results", [])) for r in merged.get("runs", []))
            if args.json:
                print(json.dumps({"status": "SUCCESS", "output": args.output, "totalFindings": total}))
            else:
                print(f"Merged {len(args.files)} files into {args.output} (Total findings: {total})")

        elif args.command == "filter":
            data = load_sarif(args.file)
            levels = [s.strip() for s in args.level.split(",")] if args.level else None
            rules = [s.strip() for s in args.rule.split(",")] if args.rule else None
            filtered = filter_sarif(data, levels=levels, rules=rules, file_pattern=args.path_pattern)
            save_sarif(filtered, args.output)
            total = sum(len(r.get("results", [])) for r in filtered.get("runs", []))
            if args.json:
                print(json.dumps({"status": "SUCCESS", "output": args.output, "totalFindings": total}))
            else:
                print(f"Filtered SARIF saved to {args.output} (Matching findings: {total})")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
