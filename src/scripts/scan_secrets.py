#!/usr/bin/env python3
"""Batch Secret Scanner for Devia-CyberSecurity.

Clean-room static scanner to detect exposed credentials, API keys, private keys,
cloud provider tokens, and uncommitted .env configurations across codebases.
Strictly conforms to Devia-CyberSecurity's zero-bias standard (PROACTIVE.md 3.12):
cred exposure severity is NEVER degraded solely due to residing in test directories.
Zero runtime dependencies, pure Python 3.11+ stdlib.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

MAX_FILE_SIZE_KB = 500
MAX_LINE_LENGTH = 2000

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", "target", "Pods", ".gradle",
    "coverage", ".nyc_output", ".cache", "bower_components",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    ".lock", ".map",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "Cargo.lock", "Gemfile.lock",
    "go.sum", "composer.lock",
}

TEST_INDICATORS = {
    "test", "tests", "spec", "specs", "mock", "mocks",
    "fake", "fakes", "fixture", "fixtures", "example", "examples",
    "sample", "samples", "demo", "demos", "dummy", "stub", "stubs", "seed",
}

ALLOWLIST_WORDS = [
    "placeholder", "your_", "your-", "xxx", "todo",
    "changeme", "test_key", "replace_me", "insert_", "<your", "${", "{{",
]

ALLOWLIST_REGEXES = [
    re.compile(r"['\"](?:your|example|fake|dummy|placeholder|xxx|TODO)[_-]", re.IGNORECASE),
    re.compile(r"sk_test_"),
    re.compile(r"pk_test_"),
    re.compile(r"(?i)password\s*[=:]\s*['\"](?:password|changeme|secret|admin|test|example)['\"]"),
]

PLACEHOLDER_RE = re.compile(
    r"(?:example|fake|dummy|sample)[-_](?:key|secret|token|password|api)",
    re.IGNORECASE
)

# Pattern specification: (name, regex, severity, description, cwe)
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}", "critical", "AWS access key ID — direct access to AWS infrastructure", "CWE-798"),
    ("AWS Secret Access Key", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "critical", "AWS secret access key", "CWE-798"),
    ("AWS MWS Key", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "critical", "Amazon MWS auth token", "CWE-798"),

    # GCP
    ("GCP API Key", r"AIza[0-9A-Za-z_-]{35}", "high", "Google Cloud API key", "CWE-798"),
    ("GCP Service Account", r'"type"\s*:\s*"service_account"', "critical", "GCP service account JSON key credentials", "CWE-798"),

    # Azure
    ("Azure Connection String", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical", "Azure Storage connection string with credentials", "CWE-798"),
    ("Azure Cosmos DB Key", r"(?i)AccountEndpoint=https://[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", "critical", "Azure Cosmos DB account key", "CWE-798"),

    # GitHub & GitLab
    ("GitHub PAT (classic)", r"ghp_[A-Za-z0-9_]{36}", "critical", "GitHub Personal Access Token", "CWE-798"),
    ("GitHub OAuth", r"gho_[A-Za-z0-9_]{36}", "critical", "GitHub OAuth access token", "CWE-798"),
    ("GitHub App Token", r"ghu_[A-Za-z0-9_]{36}", "high", "GitHub user-to-server token", "CWE-798"),
    ("GitHub App Install Token", r"ghs_[A-Za-z0-9_]{36}", "high", "GitHub server-to-server token", "CWE-798"),
    ("GitHub Refresh Token", r"ghr_[A-Za-z0-9_]{36}", "critical", "GitHub refresh token", "CWE-798"),
    ("GitHub Fine-Grained PAT", r"github_pat_[A-Za-z0-9_]{22,255}", "critical", "GitHub fine-grained personal access token", "CWE-798"),
    ("GitLab PAT", r"glpat-[A-Za-z0-9_-]{20}", "critical", "GitLab personal access token", "CWE-798"),

    # Slack
    ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}", "critical", "Slack bot token", "CWE-798"),
    ("Slack User Token", r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}", "critical", "Slack user token", "CWE-798"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}", "high", "Slack incoming webhook URL", "CWE-798"),

    # Stripe
    ("Stripe Live Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "critical", "Stripe live secret key capable of financial charges", "CWE-798"),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}", "critical", "Stripe restricted API key", "CWE-798"),
    ("Stripe Live Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", "medium", "Stripe live publishable key", "CWE-798"),

    # Twilio / SendGrid / Mailgun
    ("Twilio API Key", r"SK[0-9a-fA-F]{32}", "high", "Twilio API key", "CWE-798"),
    ("SendGrid API Key", r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "critical", "SendGrid API key", "CWE-798"),
    ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}", "high", "Mailgun API key", "CWE-798"),

    # AI Platforms
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "critical", "OpenAI API legacy secret key", "CWE-798"),
    ("OpenAI Project Key", r"sk-proj-[A-Za-z0-9_-]{40,}", "critical", "OpenAI project API key", "CWE-798"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9_-]{40,}", "critical", "Anthropic Claude API key", "CWE-798"),

    # Database URIs
    ("PostgreSQL Connection String", r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "critical", "PostgreSQL URI with hardcoded credentials", "CWE-798"),
    ("MySQL Connection String", r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "critical", "MySQL URI with hardcoded credentials", "CWE-798"),
    ("MongoDB Connection String", r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+", "critical", "MongoDB URI with hardcoded credentials", "CWE-798"),
    ("Redis Connection String", r"redis://[^\s'\"]*:[^\s'\"]+@[^\s'\"]+", "high", "Redis URI with hardcoded credentials", "CWE-798"),

    # Private Keys
    ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----", "critical", "Unencrypted RSA private key block", "CWE-312"),
    ("EC Private Key", r"-----BEGIN EC PRIVATE KEY-----", "critical", "Unencrypted EC private key block", "CWE-312"),
    ("DSA Private Key", r"-----BEGIN DSA PRIVATE KEY-----", "critical", "Unencrypted DSA private key block", "CWE-312"),
    ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "critical", "PGP private key block", "CWE-312"),
    ("Generic Private Key", r"-----BEGIN PRIVATE KEY-----", "critical", "Generic PKCS#8 private key block", "CWE-312"),
    ("OpenSSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", "critical", "OpenSSH private key block", "CWE-312"),

    # Package Managers & Registries
    ("npm Token", r"(?i)npm_[A-Za-z0-9]{36}", "critical", "npm registry access token", "CWE-798"),
    ("npm Auth Token (.npmrc)", r"//registry\.npmjs\.org/:_authToken=[^\s]+", "critical", "npm registry auth token in configuration", "CWE-798"),
    ("PyPI Token", r"pypi-[A-Za-z0-9_-]{50,}", "critical", "PyPI package upload token", "CWE-798"),

    # Messaging & SaaS
    ("Telegram Bot Token", r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "high", "Telegram Bot API token", "CWE-798"),
    ("Discord Bot Token", r"(?i)(?:discord|bot).*?['\"][A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}['\"]", "high", "Discord bot authentication token", "CWE-798"),
    ("Heroku API Key", r"(?i)heroku.*?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "high", "Heroku API key", "CWE-798"),
    ("Shopify Token", r"shpat_[a-fA-F0-9]{32}", "critical", "Shopify Admin API token", "CWE-798"),
    ("Datadog API Key", r"(?i)dd(?:og)?_?api_?key\s*[=:]\s*['\"]?[a-f0-9]{32}['\"]?", "high", "Datadog API key", "CWE-798"),

    # Generic Patterns
    ("Hardcoded Password", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "high", "Hardcoded password assignment in source code", "CWE-798"),
    ("Hardcoded Secret Key", r"(?i)(?:secret|secret_key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "high", "Hardcoded secret or secret key assignment", "CWE-798"),
    ("Hardcoded API Key", r"(?i)(?:api_key|apikey|api-key)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "high", "Hardcoded API key assignment", "CWE-798"),
    ("Authorization Bearer Header", r"(?i)authorization['\"]?\s*[=:]\s*['\"]?Bearer\s+[A-Za-z0-9_.-]{20,}", "high", "Hardcoded Bearer authentication token in source", "CWE-798"),

    # Environment File Credentials
    ("Env Password", r"(?i)^(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|PASSWORD)\s*=\s*\S{6,}", "high", "Password defined in environment file", "CWE-798"),
    ("Env Secret Key", r"(?i)^(?:SECRET_KEY|JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|APP_SECRET|AUTH_SECRET)\s*=\s*\S{6,}", "high", "Secret key defined in environment file", "CWE-798"),
    ("Env API Key", r"(?i)^(?:API_KEY|APIKEY|API_SECRET|APP_KEY|PRIVATE_KEY)\s*=\s*\S{6,}", "high", "API key defined in environment file", "CWE-798"),
]


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per symbol."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_allowlisted(line: str, matched_text: str = "") -> bool:
    """Check if match is a known false positive or placeholder."""
    lower = line.lower()
    if any(w in lower for w in ALLOWLIST_WORDS):
        return True
    if any(rx.search(line) for rx in ALLOWLIST_REGEXES):
        return True
    if PLACEHOLDER_RE.search(line):
        return True
    return False


def is_test_path(filepath: str, target_root: str = "") -> bool:
    """Check if file resides in a test/mock/fixture directory."""
    check_path = filepath
    if target_root:
        try:
            check_path = os.path.relpath(filepath, target_root)
        except ValueError:
            pass
    parts = check_path.lower().replace("\\", "/").split("/")
    for part in parts:
        segments = re.split(r"[-_./]", part)
        for segment in segments:
            if segment in TEST_INDICATORS:
                return True
    return False


def should_skip_file(filepath: Path) -> bool:
    """Determine if a file should be skipped based on path/size."""
    name = filepath.name
    suffix = filepath.suffix.lower()

    if name in SKIP_FILES:
        return True
    if suffix in SKIP_EXTENSIONS:
        return True
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    if set(filepath.parts) & SKIP_DIRS:
        return True
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE_KB * 1024:
            return True
    except OSError:
        return True
    return False


def scan_file(filepath: Path, compiled_patterns: List[Tuple], target_root: str = "") -> List[Dict[str, Any]]:
    """Scan a single file for exposed credentials with zero test degradation bias."""
    findings = []
    in_test = is_test_path(str(filepath), target_root)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                if len(line) > MAX_LINE_LENGTH:
                    continue
                for name, pattern, severity, description, cwe in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        matched_str = match.group(0)
                        if is_allowlisted(line, matched_str):
                            continue

                        # REDACTION: Never leak full credential in telemetry
                        redacted = line.strip()
                        if len(redacted) > 160:
                            redacted = redacted[:160] + "..."

                        # Crucial PROACTIVE.md 3.12 Invariant:
                        # Preserves native severity (CRITICAL/HIGH) regardless of test file status!
                        findings.append({
                            "type": name,
                            "severity": severity,
                            "cwe": cwe,
                            "file": str(filepath.resolve()),
                            "relativePath": str(PurePosixPath(os.path.relpath(filepath, target_root))) if target_root else filepath.name,
                            "line": line_num,
                            "inTestPath": in_test,
                            "description": description,
                            "evidence": redacted,
                        })
                        break
    except (OSError, UnicodeDecodeError):
        pass
    return findings


def check_gitignore(target_dir: Path) -> List[Dict[str, Any]]:
    """Verify presence of .gitignore and exclusion of sensitive files."""
    findings = []
    gitignore_path = target_dir / ".gitignore"
    sensitive_targets = [".env", ".env.local", ".env.production", "*.pem", "*.key", "credentials.json"]

    if not gitignore_path.exists():
        findings.append({
            "type": "Missing .gitignore Configuration",
            "severity": "medium",
            "cwe": "CWE-1188",
            "file": str(gitignore_path.resolve()),
            "relativePath": ".gitignore",
            "line": 0,
            "inTestPath": False,
            "description": "No .gitignore found; risk of inadvertent credential commits",
            "evidence": "Missing .gitignore file in repository root",
        })
        return findings

    try:
        content = gitignore_path.read_text(encoding="utf-8")
        env_files = [f for f in target_dir.glob(".env*") if f.name not in {".env.example", ".env.sample", ".env.template"}]
        if env_files and ".env" not in content:
            findings.append({
                "type": ".env Excluded from .gitignore",
                "severity": "high",
                "cwe": "CWE-1188",
                "file": str(gitignore_path.resolve()),
                "relativePath": ".gitignore",
                "line": 0,
                "inTestPath": False,
                "description": f"Real .env files exist ({', '.join(f.name for f in env_files)}) but .env is unignored in .gitignore",
                "evidence": f"Unignored environment configuration: {', '.join(f.name for f in env_files)}",
            })
    except OSError:
        pass
    return findings


def get_staged_files() -> List[str]:
    """Retrieve staged files from git diff without shell=True."""
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            return [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def scan_target(target_dir: Path) -> Tuple[List[Dict[str, Any]], int, int]:
    """Scan all files within target directory."""
    compiled = [
        (name, re.compile(pattern), sev, desc, cwe)
        for (name, pattern, sev, desc, cwe) in SECRET_PATTERNS
    ]
    findings = []
    scanned_count = 0
    skipped_count = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            fp = Path(root) / filename
            if should_skip_file(fp):
                skipped_count += 1
                continue
            scanned_count += 1
            findings.extend(scan_file(fp, compiled, str(target_dir)))

    findings.extend(check_gitignore(target_dir))
    return findings, scanned_count, skipped_count


def scan_staged() -> Tuple[List[Dict[str, Any]], int, int]:
    """Scan only staged files for pre-commit verification."""
    compiled = [
        (name, re.compile(pattern), sev, desc, cwe)
        for (name, pattern, sev, desc, cwe) in SECRET_PATTERNS
    ]
    staged = get_staged_files()
    findings = []
    for fp_str in staged:
        fp = Path(fp_str)
        if fp.exists() and not should_skip_file(fp):
            findings.extend(scan_file(fp, compiled))
    return findings, len(staged), 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch Secret Scanner for Devia-CyberSecurity (PROACTIVE.md compliant)."
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory to scan (default: current dir)")
    parser.add_argument("--staged-only", action="store_true", help="Scan only git staged files (pre-commit mode)")
    parser.add_argument("--json", action="store_true", default=True, help="Emit structured JSON output (default: True)")
    parser.add_argument("--summary", action="store_true", help="Emit plain-text executive summary")
    parser.add_argument("-o", "--output", help="Write JSON results to file")

    args = parser.parse_args()

    if args.staged_only:
        findings, scanned, skipped = scan_staged()
    else:
        target_path = Path(args.target).resolve()
        if not target_path.is_dir():
            print(json.dumps({"error": f"Target path is not a directory: {target_path}"}), file=sys.stderr)
            sys.exit(1)
        findings, scanned, skipped = scan_target(target_path)

    result = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": str(Path(args.target).resolve()),
        "metrics": {
            "filesScanned": scanned,
            "filesSkipped": skipped,
            "totalFindings": len(findings),
            "severityBreakdown": {
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
            }
        },
        "findings": findings
    }

    if args.summary:
        print(f"Scanned {scanned} files ({skipped} skipped)")
        print(f"Total potential secret(s): {len(findings)}")
        for sev, count in result["metrics"]["severityBreakdown"].items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")
    else:
        serialized = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            Path(args.output).write_text(serialized, encoding="utf-8")
        else:
            print(serialized)

    if findings:
        sys.exit(1 if not args.staged_only else 2)
    sys.exit(0)


if __name__ == "__main__":
    main()
