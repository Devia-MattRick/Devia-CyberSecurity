#!/usr/bin/env python3
"""Deep Static Analyzer of K:\\Skills_Pack\\.agent\\skills\\Cybersecurity
"""

import os
import re
import sys
from pathlib import Path
from collections import defaultdict, Counter

sys.stdout.reconfigure(encoding="utf-8")

TARGET = Path(r"K:\Skills_Pack\.agent\skills\Cybersecurity")

skills = []
dimension_counts = Counter()

# Mapping heuristic from folder / content to the 8 Canonical Dimensions
DIMENSION_KEYWORDS = {
    "THREAT_MODELING_ATTACK_SURFACE": [
        "threat-model", "threat_model", "threat-mitigation", "stride", "attack-tree", "007",
        "ethical-hacking", "ethical_hacking", "reconnaissance", "shodan", "scanning-tools",
        "ownership-map"
    ],
    "SOURCE_CODE_SAST": [
        "sast", "injection", "xss", "sql", "traversal", "backend-security", "frontend-security",
        "mobile-security", "solidity", "laravel", "wordpress", "secure-code", "burpsuite-project-parser"
    ],
    "SECRETS_CRYPTOGRAPHY": [
        "keyvault", "azure-keyvault", "azure-security-keyvault", "crypto", "cipher", "secret",
        "zeroize", "token"
    ],
    "IDENTITY_ACCESS_SESSION": [
        "privilege-escalation", "privesc", "active-directory", "broken-authentication", "idor",
        "ssh-penetration"
    ],
    "SUPPLY_CHAIN_SCA": [
        "dependency", "dependencies", "supply-chain", "package", "community_maintainers", "gha-security-review"
    ],
    "ARCHITECTURE_BOUNDARIES_ZERO_TRUST": [
        "boundaries", "zero-trust", "reverse-engineer", "anti-reversing", "burp-suite", "wireshark",
        "metasploit", "red-team"
    ],
    "CONFIGURATION_HARDENING": [
        "hardening", "configuration", "shellcheck", "cloud-infrastructure", "aws-penetration",
        "cloud-penetration", "smtp", "compliance", "gdpr", "pci", "bluebook"
    ],
    "RESILIENCE_LOGGING_TELEMETRY": [
        "incident", "responder", "runbook", "memory-forensics", "smart-fix", "resilience",
        "audit_log", "logging"
    ]
}

def classify_skill(folder_name: str, text: str) -> str:
    fn_lower = folder_name.lower()
    text_lower = text.lower()
    
    # Direct folder name match
    scores = Counter()
    for dim, kw_list in DIMENSION_KEYWORDS.items():
        for kw in kw_list:
            if kw in fn_lower:
                scores[dim] += 5
            if kw in text_lower:
                scores[dim] += 1
                
    if scores:
        return scores.most_common(1)[0][0]
    return "THREAT_MODELING_ATTACK_SURFACE"

for skill_dir in sorted(TARGET.iterdir()):
    if not skill_dir.is_dir():
        continue
    skill_md = skill_dir / "SKILL.md"
    name = skill_dir.name
    desc = ""
    author = ""
    content = ""
    files = [f.relative_to(skill_dir).as_posix() for f in skill_dir.rglob("*") if f.is_file()]
    py_files = [f for f in files if f.endswith(".py")]
    
    if skill_md.exists():
        content = skill_md.read_text(encoding="utf-8", errors="replace")
        fm_match = re.search(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
        if fm_match:
            fm = fm_match.group(1)
            m_name = re.search(r"name:\s*[\"']?([^\"'\n]+)", fm)
            if m_name:
                name = m_name.group(1).strip()
            m_desc = re.search(r"description:\s*[\"']?([^\"'\n]+)", fm)
            if m_desc:
                desc = m_desc.group(1).strip()
            m_author = re.search(r"author:\s*[\"']?([^\"'\n]+)", fm)
            if m_author:
                author = m_author.group(1).strip()

    dim = classify_skill(skill_dir.name, content)
    dimension_counts[dim] += 1
    
    skills.append({
        "folder": skill_dir.name,
        "name": name,
        "author": author,
        "desc": desc,
        "dim": dim,
        "file_count": len(files),
        "files": files,
        "py_files": py_files,
        "content_length": len(content)
    })

print(f"Total skills parsed: {len(skills)}")
print("\nDistribution across 8 Canonical Dimensions:")
for dim, cnt in dimension_counts.most_common():
    print(f"\n=== {dim} ({cnt} skills) ===")
    for s in skills:
        if s["dim"] == dim:
            desc_snip = s["desc"][:80] + "..." if len(s["desc"]) > 80 else s["desc"]
            py_flag = " [PY CODE]" if s["py_files"] else ""
            print(f"  - {s['folder']}{py_flag}: {desc_snip}")

import json
output_json = Path(r"K:\Devia-CyberSecurity\audits\skills-pack-cybersecurity\skills_analysis.json")
output_json.write_text(json.dumps(skills, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"\nSaved analysis to {output_json}")

