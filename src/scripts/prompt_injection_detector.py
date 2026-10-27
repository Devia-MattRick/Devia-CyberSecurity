#!/usr/bin/env python3
"""Prompt Injection & Delimiter Neutralization Engine (Capa 3: Python Determinista).

Features:
1. Special-Token Literal Neutralization (GHSA-g5f9-3xfg-p9mf):
   Defangs chat-template special tokens (<|im_start|>, [INST], <start_of_turn>, <<SYS>>,
   and fullwidth unicode variants U+FF5C) by inserting a Zero-Width Space (U+200B).
2. Deterministic Pattern Detector:
   Detects instruction overrides, role hijacks, tool hijacks, markdown exfiltration,
   cypher injections, shell injection hints, and FQDN trailing-dot bypass attempts.
3. Zero-dependency CLI with --json output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

_ZWSP = "\u200b"

# Delimiter pattern covering ChatML, Llama-3, Gemma, Mistral, and fullwidth U+FF5C
_SPECIAL_TOKEN_RE = re.compile(
    r"""
      (?P<vbar> < [|\uff5c] [A-Za-z0-9_]{1,48} [|\uff5c] > )   # <|im_start|>, <|eot_id|>, <｜…｜>
    | (?P<gemma> < /? (?:start|end)_of_turn > )                # <start_of_turn>, <end_of_turn>
    | (?P<inst> \[ /? INST \] )                                # [INST], [/INST]
    | (?P<sys> << /? SYS >> )                                  # <<SYS>>, <</SYS>>
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _defang(match: re.Match[str]) -> str:
    tok = match.group(0)
    return f"{tok[0]}{_ZWSP}{tok[1:]}"


def neutralize_special_tokens(text: str) -> str:
    """Render chat-template special tokens inert via zero-width space insertion."""
    if not text or ("<" not in text and "[" not in text):
        return text
    return _SPECIAL_TOKEN_RE.sub(_defang, text)


class InjectionCategory(StrEnum):
    INSTRUCTION_OVERRIDE = "instruction-override"
    ROLE_HIJACK = "role-hijack"
    TOOL_CALL_HIJACK = "tool-call-hijack"
    EXFIL_MARKDOWN = "exfil-markdown"
    SYSTEM_PROMPT_LEAK = "system-prompt-leak"
    CYPHER_INJECTION = "cypher-injection"
    SHELL_INJECTION_HINT = "shell-injection-hint"
    INVISIBLE_TEXT = "invisible-text"
    FQDN_TRAILING_DOT_BYPASS = "fqdn-trailing-dot-bypass"


_FLAGS = re.IGNORECASE | re.MULTILINE

_PATTERNS: tuple[tuple[InjectionCategory, str, re.Pattern[str]], ...] = (
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "ignore-previous",
        re.compile(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|preceding|above)\s+"
            r"(?:instructions?|messages?|prompts?|rules?|directives?|context|system\s+prompt)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "disregard",
        re.compile(
            r"\b(?:disregard|forget|override|set\s+aside|cancel)\s+"
            r"(?:all\s+)?(?:previous|prior|earlier|above|system|safety|alignment|roe|rules)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.INSTRUCTION_OVERRIDE,
        "new-instructions",
        re.compile(
            r"\b(?:new|updated|revised|corrected|important|critical|urgent)\s+"
            r"(?:instructions?|directives?|orders?|rules?)\s*[:\-]",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "you-are-now",
        re.compile(
            r"\byou\s+are\s+(?:now|actually|really|in\s+fact)\s+"
            r"(?:a|an|the)?\s*[\w\- ]{3,40}\b",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "act-as",
        re.compile(
            r"\b(?:act|behave|roleplay|pretend\s+to\s+be)\s+as\s+"
            r"(?:a|an|the)?\s*[\w\- ]{3,40}\b",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.ROLE_HIJACK,
        "special-role-tags",
        re.compile(
            r"(?:<\|im_start\|>|<start_of_turn>|\[INST\]|<<SYS>>)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.TOOL_CALL_HIJACK,
        "call-tool",
        re.compile(
            r"\b(?:call|invoke|use|run|execute)\s+"
            r"(?:the\s+)?(?:tool|function|api|endpoint)\s+(?:named\s+)?"
            r"['\"`]?[\w_]+['\"`]?",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.EXFIL_MARKDOWN,
        "image-or-link-exfil",
        re.compile(
            r"(?:!\[[^\]]*\]|\[[^\]]*\])\(\s*https?://[^)\s]+\?[^)\s]*"
            r"(?:secret|token|key|password|cred|session|auth|cookie|exfil|q=)",
            _FLAGS,
        ),
    ),
    (
        InjectionCategory.CYPHER_INJECTION,
        "apoc-file-io",
        re.compile(r"\bapoc\.(?:cypher\.runFile|load\.|import\.|export\.)", _FLAGS),
    ),
    (
        InjectionCategory.SHELL_INJECTION_HINT,
        "exec-with-curl-or-bash",
        re.compile(
            r"\b(?:execute|run|launch)\b.{0,60}?"
            r"(?:curl\s|wget\s|nc\s|bash\s|sh\s|python\s|powershell|cmd\.exe|rm\s+-rf)",
            _FLAGS | re.DOTALL,
        ),
    ),
    (
        InjectionCategory.INVISIBLE_TEXT,
        "zero-width-cluster",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}"),
    ),
    (
        InjectionCategory.FQDN_TRAILING_DOT_BYPASS,
        "fqdn-trailing-dot",
        re.compile(r"\b(?:169\.254\.169\.254\.|[a-zA-Z0-9.-]+\.(?:gov|mil|edu|int)\.)", _FLAGS),
    ),
)


@dataclass(frozen=True)
class InjectionMatch:
    category: str
    pattern_name: str
    offset: int
    length: int
    excerpt: str


def detect_injection(text: str) -> dict[str, Any]:
    """Scan text for prompt injection signals and return structured findings."""
    if not text or len(text) < 6:
        return {
            "has_injection": False,
            "risk": "low",
            "matches_count": 0,
            "categories": [],
            "matches": []
        }

    matches: list[dict[str, Any]] = []
    found_categories: set[str] = set()

    for category, name, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            found_categories.add(category.value)
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            matches.append({
                "category": category.value,
                "pattern_name": name,
                "offset": m.start(),
                "length": m.end() - m.start(),
                "excerpt": text[start:end].replace("\n", " ")
            })

    # Determine risk level
    if (
        InjectionCategory.TOOL_CALL_HIJACK in found_categories
        or InjectionCategory.CYPHER_INJECTION in found_categories
        or InjectionCategory.EXFIL_MARKDOWN in found_categories
        or InjectionCategory.FQDN_TRAILING_DOT_BYPASS in found_categories
    ):
        risk = "high"
    elif (
        InjectionCategory.INSTRUCTION_OVERRIDE in found_categories
        or InjectionCategory.ROLE_HIJACK in found_categories
    ):
        risk = "high" if len(matches) >= 2 else "medium"
    elif found_categories:
        risk = "medium"
    else:
        risk = "low"

    return {
        "has_injection": len(matches) > 0,
        "risk": risk,
        "matches_count": len(matches),
        "categories": sorted(list(found_categories)),
        "matches": matches
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prompt Injection & Special Token Neutralization Utility")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # scan command
    scan_p = subparsers.add_parser("scan", help="Scan a string for injection patterns")
    scan_p.add_argument("text", help="Text to inspect")
    scan_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # scan-file command
    file_p = subparsers.add_parser("scan-file", help="Scan file contents for injection patterns")
    file_p.add_argument("path", help="Path to the file to inspect")
    file_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # defang command
    defang_p = subparsers.add_parser("defang", help="Neutralize chat-template special tokens")
    defang_p.add_argument("text", help="Text containing potential special tokens")
    defang_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if args.subcommand == "scan":
        result = detect_injection(args.text)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Risk: {result['risk'].upper()} | Matches: {result['matches_count']}")
            for m in result["matches"]:
                print(f"  - [{m['category']}] ({m['pattern_name']}) at pos {m['offset']}: '{m['excerpt']}'")
        return 1 if result["risk"] == "high" else 0

    elif args.subcommand == "scan-file":
        if not os.path.isfile(args.path):
            print(f"Error: file not found: {args.path}", file=sys.stderr)
            return 2
        with open(args.path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        result = detect_injection(content)
        result["file"] = args.path
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"File: {args.path} | Risk: {result['risk'].upper()} | Matches: {result['matches_count']}")
            for m in result["matches"]:
                print(f"  - [{m['category']}] ({m['pattern_name']}): '{m['excerpt']}'")
        return 1 if result["risk"] == "high" else 0

    elif args.subcommand == "defang":
        neutralized = neutralize_special_tokens(args.text)
        has_modified = (neutralized != args.text)
        if args.json:
            print(json.dumps({"original": args.text, "defanged": neutralized, "modified": has_modified}, indent=2, ensure_ascii=False))
        else:
            print(neutralized)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
