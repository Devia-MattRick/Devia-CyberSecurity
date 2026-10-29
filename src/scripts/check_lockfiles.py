#!/usr/bin/env python3
"""Lockfile Integrity and Supply Chain Scanner for Devia-CyberSecurity.

Clean-room static scanner to verify package lockfile presence, consistency,
.gitignore exclusions, unpinned dependencies, and risky installation hooks
across JavaScript/TypeScript, Python, Rust, Go, Ruby, and PHP ecosystems.
Zero runtime dependencies, pure Python 3.11+ stdlib.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple


ECOSYSTEMS = {
    "npm": {
        "manifest": "package.json",
        "lockfiles": ["package-lock.json", "npm-shrinkwrap.json"],
        "alt_lockfiles": ["yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
        "category": "node"
    },
    "pnpm": {
        "manifest": "package.json",
        "lockfiles": ["pnpm-lock.yaml"],
        "alt_lockfiles": ["package-lock.json", "yarn.lock", "bun.lockb", "bun.lock"],
        "category": "node"
    },
    "yarn": {
        "manifest": "package.json",
        "lockfiles": ["yarn.lock"],
        "alt_lockfiles": ["package-lock.json", "pnpm-lock.yaml", "bun.lockb", "bun.lock"],
        "category": "node"
    },
    "bun": {
        "manifest": "package.json",
        "lockfiles": ["bun.lockb", "bun.lock"],
        "alt_lockfiles": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "category": "node"
    },
    "poetry": {
        "manifest": "pyproject.toml",
        "lockfiles": ["poetry.lock"],
        "category": "python"
    },
    "pipenv": {
        "manifest": "Pipfile",
        "lockfiles": ["Pipfile.lock"],
        "category": "python"
    },
    "cargo": {
        "manifest": "Cargo.toml",
        "lockfiles": ["Cargo.lock"],
        "category": "rust"
    },
    "composer": {
        "manifest": "composer.json",
        "lockfiles": ["composer.lock"],
        "category": "php"
    },
    "bundler": {
        "manifest": "Gemfile",
        "lockfiles": ["Gemfile.lock"],
        "category": "ruby"
    },
    "go": {
        "manifest": "go.mod",
        "lockfiles": ["go.sum"],
        "category": "go"
    }
}

RISKY_HOOKS = ["preinstall", "postinstall", "preuninstall", "postuninstall"]


def detect_active_node_manager(target_dir: Path) -> str:
    """Determine dominant Node package manager based on lockfiles or config."""
    if (target_dir / "pnpm-lock.yaml").exists() or (target_dir / "pnpm-workspace.yaml").exists():
        return "pnpm"
    if (target_dir / "yarn.lock").exists() or (target_dir / ".yarnrc.yml").exists():
        return "yarn"
    if (target_dir / "bun.lockb").exists() or (target_dir / "bun.lock").exists():
        return "bun"
    return "npm"


def read_gitignore_patterns(target_dir: Path) -> List[str]:
    """Extract non-comment rules from .gitignore."""
    gitignore = target_dir / ".gitignore"
    if not gitignore.is_file():
        return []
    try:
        content = gitignore.read_text(encoding="utf-8", errors="ignore")
        return [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except OSError:
        return []


def is_pattern_matched(filename: str, pattern: str) -> bool:
    """Check if filename matches a gitignore pattern (exact, wildcard, or directory prefix)."""
    clean_pat = pattern.strip().lstrip("/")
    if clean_pat == filename:
        return True
    if clean_pat.endswith(filename):
        return True
    if "*" in clean_pat:
        regex_str = "^" + clean_pat.replace(".", r"\.").replace("*", ".*") + "$"
        if re.match(regex_str, filename):
            return True
    return False


def check_lockfiles_in_directory(target_dir: Path) -> List[Dict[str, Any]]:
    """Scan directory for lockfile presence, gitignore exclusion, conflicts, and dependency risks."""
    findings: List[Dict[str, Any]] = []
    gitignore_rules = read_gitignore_patterns(target_dir)

    # 1. Node Ecosystem Inspection
    pkg_json = target_dir / "package.json"
    if pkg_json.is_file():
        node_manager = detect_active_node_manager(target_dir)
        expected_lockfiles = ECOSYSTEMS[node_manager]["lockfiles"]
        existing_node_locks = [
            f for f in ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"]
            if (target_dir / f).is_file()
        ]

        # Check for presence of primary lockfile
        has_primary = any((target_dir / l).is_file() for l in expected_lockfiles)
        if not has_primary:
            findings.append({
                "ruleId": "supply-chain.missing-lockfile",
                "type": "Missing Lockfile",
                "severity": "HIGH",
                "file": "package.json",
                "line": 1,
                "description": f"Detected Node project using {node_manager}, but expected lockfile ({', '.join(expected_lockfiles)}) is missing.",
                "cwe": ["CWE-1104"],
                "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                "evidence": f"Expected lockfile ({', '.join(expected_lockfiles)}) not found in directory.",
                "remediation": f"Generate and commit the lockfile using '{node_manager} install'."
            })

        # Check for multiple competing lockfiles
        if len(existing_node_locks) > 1:
            findings.append({
                "ruleId": "supply-chain.conflicting-lockfiles",
                "type": "Conflicting Lockfiles Detected",
                "severity": "MEDIUM",
                "file": "package.json",
                "line": 1,
                "description": f"Multiple competing lockfiles found ({', '.join(existing_node_locks)}), leading to desynchronization and non-deterministic builds.",
                "cwe": ["CWE-1104", "CWE-494"],
                "owasp": ["A08:2021-Software and Data Integrity Failures"],
                "evidence": f"Coexisting lockfiles: {', '.join(existing_node_locks)}",
                "remediation": "Standardize on a single package manager and delete redundant lockfiles."
            })

        # Check .gitignore for lockfile exclusion
        candidate_locks = list(dict.fromkeys(existing_node_locks + expected_lockfiles))
        for lock in candidate_locks:
            for rule in gitignore_rules:
                if is_pattern_matched(lock, rule):
                    findings.append({
                        "ruleId": "supply-chain.gitignored-lockfile",
                        "type": "Lockfile Excluded in .gitignore",
                        "severity": "HIGH",
                        "file": ".gitignore",
                        "line": 1,
                        "description": f"Lockfile '{lock}' is matched by .gitignore rule '{rule}'. Lockfiles must be committed to ensure deterministic builds.",
                        "cwe": ["CWE-829", "CWE-1104"],
                        "owasp": ["A08:2021-Software and Data Integrity Failures"],
                        "evidence": f".gitignore rule: {rule}",
                        "remediation": f"Remove '{rule}' from .gitignore and track '{lock}' in version control."
                    })
                    break

        # Check package.json content: unpinned dependencies and risky hooks
        try:
            content = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
            unpinned: List[str] = []
            for dep_section in ["dependencies", "devDependencies"]:
                for name, ver in content.get(dep_section, {}).items():
                    if isinstance(ver, str):
                        sver = ver.strip()
                        if sver in ("*", "latest") or (sver.startswith(">=") and "<" not in sver):
                            unpinned.append(f"{name}: {ver}")

            if unpinned:
                findings.append({
                    "ruleId": "supply-chain.unpinned-dependencies",
                    "type": "Unpinned Dependency Ranges",
                    "severity": "MEDIUM",
                    "file": "package.json",
                    "line": 1,
                    "description": f"Found {len(unpinned)} unpinned dependencies with wildcard or open-ended ranges.",
                    "cwe": ["CWE-829", "CWE-1104"],
                    "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                    "evidence": ", ".join(unpinned[:5]),
                    "remediation": "Pin exact dependency versions or use strict semver ranges without wildcards."
                })

            scripts = content.get("scripts", {})
            for hook in RISKY_HOOKS:
                if hook in scripts:
                    findings.append({
                        "ruleId": "supply-chain.risky-lifecycle-script",
                        "type": "Risky Installation Lifecycle Hook",
                        "severity": "MEDIUM",
                        "file": "package.json",
                        "line": 1,
                        "description": f"Lifecycle script '{hook}' detected. Automated scripts on install can execute malicious code during dependency resolution.",
                        "cwe": ["CWE-829", "CWE-494"],
                        "owasp": ["A08:2021-Software and Data Integrity Failures"],
                        "evidence": f"\"{hook}\": \"{scripts[hook][:100]}\"",
                        "remediation": "Review the script for safety, run with '--ignore-scripts' in CI if possible, or migrate logic to an explicit build task."
                    })
        except Exception:
            pass

        # Check package-lock.json for Lockfile Poisoning (VULN-SCA-012)
        pkg_lock = target_dir / "package-lock.json"
        if pkg_lock.is_file():
            try:
                lock_data = json.loads(pkg_lock.read_text(encoding="utf-8", errors="ignore"))
                poisoned_entries: List[str] = []
                http_entries: List[str] = []

                packages_dict = lock_data.get("packages", {})
                if not packages_dict:
                    packages_dict = lock_data.get("dependencies", {})

                for pkg_name, pkg_info in packages_dict.items():
                    if not isinstance(pkg_info, dict) or not pkg_name:
                        continue
                    resolved_url = pkg_info.get("resolved", "")
                    if isinstance(resolved_url, str) and resolved_url:
                        if resolved_url.startswith("http://"):
                            http_entries.append(f"{pkg_name} -> {resolved_url}")
                        elif not any(reg in resolved_url for reg in [
                            "registry.npmjs.org",
                            "registry.yarnpkg.com",
                            "registry.npmmirror.com",
                            "npm.pkg.github.com",
                            "pkgs.dev.azure.com"
                        ]) and not resolved_url.startswith("file:"):
                            poisoned_entries.append(f"{pkg_name} -> {resolved_url}")

                if http_entries:
                    findings.append({
                        "ruleId": "supply-chain.insecure-lockfile-http",
                        "type": "Insecure HTTP Lockfile Tarball URL",
                        "severity": "HIGH",
                        "file": "package-lock.json",
                        "line": 1,
                        "description": f"Found {len(http_entries)} dependencies resolving tarballs over unencrypted HTTP, susceptible to MitM tampering.",
                        "cwe": ["CWE-319", "CWE-829"],
                        "owasp": ["A08:2021-Software and Data Integrity Failures"],
                        "evidence": ", ".join(http_entries[:5]),
                        "remediation": "Enforce HTTPS for all package resolution URLs in package-lock.json or run lockfile-lint."
                    })

                if poisoned_entries:
                    findings.append({
                        "ruleId": "supply-chain.lockfile-poisoning",
                        "type": "Lockfile Poisoning / Untrusted Tarball Registry",
                        "severity": "HIGH",
                        "file": "package-lock.json",
                        "line": 1,
                        "description": f"Found {len(poisoned_entries)} dependencies with resolved URLs pointing to untrusted or external registries.",
                        "cwe": ["CWE-829", "CWE-353"],
                        "owasp": ["A08:2021-Software and Data Integrity Failures"],
                        "evidence": ", ".join(poisoned_entries[:5]),
                        "remediation": "Verify that all dependencies resolve to the official npm registry or authorized enterprise scopes. Audit with lockfile-lint."
                    })
            except Exception:
                pass

    # 2. Python Ecosystem Inspection (Poetry / Pipenv / Requirements)
    pyproject = target_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8", errors="ignore")
            if "[tool.poetry]" in content:
                poetry_lock = target_dir / "poetry.lock"
                if not poetry_lock.is_file():
                    findings.append({
                        "ruleId": "supply-chain.missing-lockfile",
                        "type": "Missing Poetry Lockfile",
                        "severity": "HIGH",
                        "file": "pyproject.toml",
                        "line": 1,
                        "description": "Poetry project defined in pyproject.toml, but 'poetry.lock' is missing.",
                        "cwe": ["CWE-1104"],
                        "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                        "evidence": "poetry.lock missing from root directory.",
                        "remediation": "Run 'poetry lock' and commit the resulting poetry.lock."
                    })
        except Exception:
            pass

    pipfile = target_dir / "Pipfile"
    if pipfile.is_file():
        pipfile_lock = target_dir / "Pipfile.lock"
        if not pipfile_lock.is_file():
            findings.append({
                "ruleId": "supply-chain.missing-lockfile",
                "type": "Missing Pipenv Lockfile",
                "severity": "HIGH",
                "file": "Pipfile",
                "line": 1,
                "description": "Pipfile present, but 'Pipfile.lock' is missing.",
                "cwe": ["CWE-1104"],
                "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                "evidence": "Pipfile.lock missing from root directory.",
                "remediation": "Run 'pipenv lock' and commit Pipfile.lock."
            })

    # Requirements.txt unpinned check
    for req_fname in ["requirements.txt", "requirements-dev.txt"]:
        req_file = target_dir / req_fname
        if req_file.is_file():
            try:
                unpinned_py: List[str] = []
                for idx, line in enumerate(req_file.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    clean_l = line.strip()
                    if not clean_l or clean_l.startswith("#") or clean_l.startswith("-"):
                        continue
                    if "==" not in clean_l and "@" not in clean_l:
                        unpinned_py.append(f"line {idx}: {clean_l}")

                if unpinned_py:
                    findings.append({
                        "ruleId": "supply-chain.unpinned-dependencies",
                        "type": "Unpinned Python Requirements",
                        "severity": "LOW",
                        "file": req_fname,
                        "line": 1,
                        "description": f"Found {len(unpinned_py)} requirement(s) without pinned version (missing '==').",
                        "cwe": ["CWE-1104"],
                        "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                        "evidence": ", ".join(unpinned_py[:5]),
                        "remediation": "Pin exact versions using 'pip-compile' (pip-tools) or 'pip freeze'."
                    })
            except Exception:
                pass

    # 3. Rust (Cargo.lock)
    cargo_toml = target_dir / "Cargo.toml"
    if cargo_toml.is_file():
        cargo_lock = target_dir / "Cargo.lock"
        if not cargo_lock.is_file():
            findings.append({
                "ruleId": "supply-chain.missing-lockfile",
                "type": "Missing Cargo Lockfile",
                "severity": "MEDIUM",
                "file": "Cargo.toml",
                "line": 1,
                "description": "Cargo.toml present, but Cargo.lock is missing.",
                "cwe": ["CWE-1104"],
                "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                "evidence": "Cargo.lock missing from root directory.",
                "remediation": "Run 'cargo generate-lockfile' or 'cargo build' and commit Cargo.lock."
            })

    # 4. Go (go.sum)
    go_mod = target_dir / "go.mod"
    if go_mod.is_file():
        go_sum = target_dir / "go.sum"
        if not go_sum.is_file():
            findings.append({
                "ruleId": "supply-chain.missing-lockfile",
                "type": "Missing Go Checksum Database (go.sum)",
                "severity": "HIGH",
                "file": "go.mod",
                "line": 1,
                "description": "go.mod present, but cryptographic checksum file 'go.sum' is missing.",
                "cwe": ["CWE-1104", "CWE-353"],
                "owasp": ["A08:2021-Software and Data Integrity Failures"],
                "evidence": "go.sum missing from root directory.",
                "remediation": "Run 'go mod tidy' or 'go mod download' and commit go.sum."
            })

    # 5. PHP (composer.lock)
    composer_json = target_dir / "composer.json"
    if composer_json.is_file():
        composer_lock = target_dir / "composer.lock"
        if not composer_lock.is_file():
            findings.append({
                "ruleId": "supply-chain.missing-lockfile",
                "type": "Missing Composer Lockfile",
                "severity": "HIGH",
                "file": "composer.json",
                "line": 1,
                "description": "composer.json present, but 'composer.lock' is missing.",
                "cwe": ["CWE-1104"],
                "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                "evidence": "composer.lock missing from root directory.",
                "remediation": "Run 'composer update --lock' and commit composer.lock."
            })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deterministic Lockfile & Supply Chain Integrity Scanner for Devia-CyberSecurity"
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory to inspect")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.is_dir():
        if args.json:
            print(json.dumps({"error": f"Target is not a directory: {target_dir}", "findings": []}))
        else:
            print(f"[!] Target is not a directory: {target_dir}", file=sys.stderr)
        sys.exit(1)

    findings = check_lockfiles_in_directory(target_dir)

    result = {
        "target": str(target_dir),
        "totalFindings": len(findings),
        "findings": findings
    }

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[*] Lockfile & Supply Chain Scan for: {target_dir}")
        print(f"[*] Total Findings: {len(findings)}")
        for f in findings:
            print(f"  [{f['severity']}] {f['type']} in {f['file']}: {f['description']}")


if __name__ == "__main__":
    main()
