#!/usr/bin/env python3
"""C2 Beaconing Frequency and Network Anomaly Detector for Devia-CyberSecurity.

Analyzes connection logs (JSON, CSV, or Zeek conn.log format) deterministically
using statistical interval analysis, Coefficient of Variation (CV = sigma / mu),
payload consistency, and Shannon entropy for DGA/tunneling detection.
Zero external dependencies (Python 3.11+ stdlib only).
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple


STANDARD_WEB_PORTS = {"80", "443", "8080", "8443", "53"}

KNOWN_BENIGN_DOMAINS = {
    "microsoft.com", "windowsupdate.com", "google.com", "googleapis.com",
    "gstatic.com", "amazonaws.com", "cloudflare.com", "akamai.net",
    "apple.com", "icloud.com", "github.com", "office.com", "live.com"
}


def compute_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per symbol)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_benign_domain(domain: str) -> bool:
    """Check if destination domain belongs to known benign services."""
    clean = domain.strip().lower().rstrip(".")
    return any(clean == b or clean.endswith("." + b) for b in KNOWN_BENIGN_DOMAINS)


def parse_timestamp(val: Any) -> Optional[float]:
    """Parse various timestamp representations into epoch seconds."""
    if isinstance(val, (int, float)):
        return float(val)
    if not val:
        return None
    val_str = str(val).strip()
    try:
        return float(val_str)
    except ValueError:
        pass
    # Try ISO formats
    clean_iso = val_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(clean_iso)
        return dt.timestamp()
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            dt = datetime.strptime(val_str, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            continue
    return None


def normalize_record(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize log record fields across JSON, CSV, and Zeek formats."""
    field_map = {
        "timestamp": ["ts", "timestamp", "_time", "@timestamp", "Timestamp", "Time"],
        "src_ip": ["id.orig_h", "src_ip", "source_ip", "src", "LocalIP", "client_ip"],
        "dst_ip": ["id.resp_h", "dst_ip", "dest_ip", "dst", "RemoteIP", "server_ip"],
        "domain": ["query", "domain", "host", "RemoteUrl", "server_name", "dest_host"],
        "dst_port": ["id.resp_p", "dst_port", "dest_port", "dport", "RemotePort", "port"],
        "bytes_sent": ["orig_bytes", "bytes_out", "bytes_sent", "SentBytes", "out_bytes"]
    }

    normalized: Dict[str, Any] = {}
    for canon_key, candidates in field_map.items():
        val = None
        for cand in candidates:
            if cand in raw and raw[cand] not in (None, "", "-"):
                val = raw[cand]
                break
        normalized[canon_key] = val

    ts = parse_timestamp(normalized.get("timestamp"))
    if ts is None:
        return None

    src = str(normalized.get("src_ip") or "").strip()
    dst = str(normalized.get("domain") or normalized.get("dst_ip") or "").strip()
    if not src or not dst:
        return None

    port = str(normalized.get("dst_port") or "0").strip()
    try:
        bytes_sent = int(normalized.get("bytes_sent") or 0)
    except (ValueError, TypeError):
        bytes_sent = 0

    return {
        "timestamp": ts,
        "src": src,
        "dst": dst,
        "port": port,
        "bytes_sent": bytes_sent
    }


def load_connection_logs(file_path: Path) -> List[Dict[str, Any]]:
    """Load connections from JSON, CSV, or tab-delimited Zeek format."""
    events: List[Dict[str, Any]] = []
    suffix = file_path.suffix.lower()

    if suffix == ".json":
        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            raw_list = data if isinstance(data, list) else data.get("events", data.get("records", []))
            for item in raw_list:
                if isinstance(item, dict):
                    norm = normalize_record(item)
                    if norm:
                        events.append(norm)

    elif suffix in (".csv", ".txt"):
        with file_path.open("r", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                norm = normalize_record(row)
                if norm:
                    events.append(norm)

    elif suffix == ".log":  # Typical Zeek log format
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            headers: Optional[List[str]] = None
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    headers = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif headers:
                    vals = line.split("\t")
                    if len(vals) == len(headers):
                        row = dict(zip(headers, vals))
                        norm = normalize_record(row)
                        if norm:
                            events.append(norm)

    return events


def analyze_beaconing_patterns(
    connections: List[Dict[str, Any]],
    min_connections: int = 10,
    max_cv: float = 0.25,
    min_interval: float = 5.0,
    max_interval: float = 86400.0
) -> List[Dict[str, Any]]:
    """Perform deterministic statistical interval analysis to identify C2 beacons."""
    pairs: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for conn in connections:
        src = conn["src"]
        dst = conn["dst"]
        if is_benign_domain(dst):
            continue
        pairs[(src, dst)].append(conn)

    findings: List[Dict[str, Any]] = []

    for (src, dst), conns in pairs.items():
        if len(conns) < min_connections:
            continue

        conns.sort(key=lambda x: x["timestamp"])
        intervals = [
            conns[i]["timestamp"] - conns[i - 1]["timestamp"]
            for i in range(1, len(conns))
            if conns[i]["timestamp"] - conns[i - 1]["timestamp"] > 0
        ]

        if len(intervals) < max(4, min_connections - 1):
            continue

        n = len(intervals)
        avg_interval = sum(intervals) / n
        if not (min_interval <= avg_interval <= max_interval):
            continue

        variance = sum((x - avg_interval) ** 2 for x in intervals) / n
        stdev = math.sqrt(variance)
        cv = stdev / avg_interval if avg_interval > 0 else float("inf")

        if cv > max_cv:
            continue

        # Data consistency analysis
        bytes_list = [c["bytes_sent"] for c in conns if c["bytes_sent"] > 0]
        data_cv = 0.0
        if len(bytes_list) >= 4:
            b_n = len(bytes_list)
            b_avg = sum(bytes_list) / b_n
            if b_avg > 0:
                b_var = sum((x - b_avg) ** 2 for x in bytes_list) / b_n
                data_cv = math.sqrt(b_var) / b_avg

        # Entropy analysis on destination
        dst_entropy = compute_shannon_entropy(dst)

        # Risk scoring
        risk_score = 0
        reasons: List[str] = []

        if cv <= 0.05:
            risk_score += 40
            reasons.append(f"Ultra-regular interval (CV={cv:.4f}, expected periodic beacon)")
        elif cv <= 0.15:
            risk_score += 30
            reasons.append(f"High regularity interval with low jitter (CV={cv:.4f})")
        else:
            risk_score += 20
            reasons.append(f"Moderate regular interval (CV={cv:.4f})")

        if 0 < data_cv <= 0.20:
            risk_score += 20
            reasons.append(f"High data size consistency (Data CV={data_cv:.4f})")

        ports = Counter(c["port"] for c in conns)
        primary_port = ports.most_common(1)[0][0]
        if primary_port not in STANDARD_WEB_PORTS and primary_port != "0":
            risk_score += 20
            reasons.append(f"Non-standard egress port {primary_port}")

        if dst_entropy >= 3.8:
            risk_score += 15
            reasons.append(f"High destination string entropy ({dst_entropy:.2f} bits, DGA/tunneling indicator)")

        if len(conns) >= 50:
            risk_score += 10
            reasons.append(f"High connection volume ({len(conns)} attempts)")

        risk_score = min(100, risk_score)
        severity = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM"

        findings.append({
            "src": src,
            "dst": dst,
            "port": primary_port,
            "total_connections": len(conns),
            "avg_interval_seconds": round(avg_interval, 2),
            "interval_stdev": round(stdev, 2),
            "coefficient_of_variation": round(cv, 4),
            "estimated_jitter_pct": round(cv * 100.0, 2),
            "data_size_cv": round(data_cv, 4),
            "dst_entropy": round(dst_entropy, 2),
            "risk_score": risk_score,
            "severity": severity,
            "mitre_technique": "T1071.001",
            "cwe": "CWE-923",
            "indicators": reasons,
            "earliest_ts": datetime.fromtimestamp(conns[0]["timestamp"], tz=timezone.utc).isoformat(),
            "latest_ts": datetime.fromtimestamp(conns[-1]["timestamp"], tz=timezone.utc).isoformat()
        })

    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic C2 Beaconing Detector for Devia-CyberSecurity")
    parser.add_argument("logfile", type=str, help="Path to connection log file (.json, .csv, .log)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output JSON path")
    parser.add_argument("--min-conns", type=int, default=10, help="Minimum connections threshold (default: 10)")
    parser.add_argument("--max-cv", type=float, default=0.25, help="Maximum CV threshold (default: 0.25)")
    parser.add_argument("--json", action="store_true", help="Print output in JSON format")

    args = parser.parse_args()
    log_path = Path(args.logfile).expanduser().resolve()

    if not log_path.exists():
        print(f"[-] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    connections = load_connection_logs(log_path)
    findings = analyze_beaconing_patterns(
        connections,
        min_connections=args.min_conns,
        max_cv=args.max_cv
    )

    result = {
        "engine": "Devia-CyberSecurity C2 Beaconing Detector",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "input_file": str(log_path),
        "total_connections_parsed": len(connections),
        "total_suspicious_pairs": len(findings),
        "findings": findings
    }

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        if not args.json:
            print(f"[+] Output saved to {out_path}")

    if args.json or not args.output:
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
