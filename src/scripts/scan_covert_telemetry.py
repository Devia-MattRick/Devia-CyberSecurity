#!/usr/bin/env python3
"""Deterministic Static Scanner for Covert Telemetry, Obfuscated Shell Pipelines, and Exfiltration Beacons.

Scans source code repositories and scripts for clandestine communication channels:
1. Obfuscated shell pipelines: base64 -d | bash, base64 --decode | sh, eval $(echo ... | base64)
2. SMS and messaging dispatchers: TextBelt (textbelt.com), Twilio, Nexmo, Plivo
3. Webhook exfiltration endpoints: Discord webhooks, Telegram bot API, Slack webhooks
4. Cyrillic homoglyph obfuscation used in payload strings
5. Inline base64 payload decoding and recursive intent analysis

Pure Python 3.11+ stdlib, contract-first design with JSON output support.
Conforms to Devia-CyberSecurity standards (Capa 3).
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

MAX_FILE_SIZE_KB = 1024
MAX_LINE_LENGTH = 4000

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "vendor", "target", "Pods", ".gradle",
    "coverage", ".nyc_output", ".cache", "audits",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dylib", ".dll",
    ".exe", ".bin", ".dat", ".db", ".sqlite", ".sqlite3",
    ".lock", ".map", ".flf", ".tlf"
}

# Regex patterns for obfuscated shell pipelines
OBFUSCATED_PIPE_PATTERNS = [
    (
        re.compile(r"""(?:echo\s+['"]?[A-Za-z0-9+/=]{16,}['"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh|dash))""", re.IGNORECASE),
        "OBFUSCATED_BASE64_SHELL_PIPE",
        "Pipeline shell ofuscado decodificando Base64 directamente a un intérprete (bash/sh)",
        "CRITICAL",
        "CWE-1027",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""(?:eval\s+["']?\$\(\s*echo\s+['"]?[A-Za-z0-9+/=]{16,}['"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\)["']?)""", re.IGNORECASE),
        "OBFUSCATED_EVAL_BASE64_COMMAND",
        "Evaluación dinámica de comando ofuscado en Base64 mediante eval $()",
        "CRITICAL",
        "CWE-1027",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""(?:\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh|dash|python|python2|python3|perl))""", re.IGNORECASE),
        "GENERIC_BASE64_EXEC_PIPE",
        "Canalización directa de Base64 decodificado hacia intérprete de comandos o lenguaje",
        "HIGH",
        "CWE-1027",
        "VULN-CRYP-005"
    )
]

# Patterns for clandestine communication / messaging APIs
TELEMETRY_ENDPOINT_PATTERNS = [
    (
        re.compile(r"""https?://(?:www\.)?textbelt\.com/text""", re.IGNORECASE),
        "TEXTBELT_SMS_BEACON",
        "Llamada a la API de SMS TextBelt para envío clandestino de notificaciones/telemetría",
        "CRITICAL",
        "CWE-359",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""https?://api\.twilio\.com/2010-04-01/Accounts/[A-Za-z0-9]+/Messages""", re.IGNORECASE),
        "TWILIO_SMS_DISPATCHER",
        "Despacho no autorizado de SMS mediante API de Twilio",
        "HIGH",
        "CWE-359",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""https?://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+""", re.IGNORECASE),
        "DISCORD_WEBHOOK_EXFILTRATION",
        "Endpoint de Discord Webhook utilizado como canal de exfiltración de telemetría",
        "CRITICAL",
        "CWE-200",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""https?://api\.telegram\.org/bot[0-9]+:[A-Za-z0-9_-]+/sendMessage""", re.IGNORECASE),
        "TELEGRAM_BOT_EXFILTRATION",
        "Envío de mensajes hacia un bot de Telegram utilizado como beacon de exfiltración",
        "CRITICAL",
        "CWE-200",
        "VULN-CRYP-005"
    ),
    (
        re.compile(r"""https?://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+""", re.IGNORECASE),
        "SLACK_WEBHOOK_EXFILTRATION",
        "Webhook entrante de Slack utilizado para telemetría no supervisada",
        "HIGH",
        "CWE-200",
        "VULN-CRYP-005"
    )
]

# Pattern for inline Base64 tokens
BASE64_TOKEN_PATTERN = re.compile(r"""(?:[A-Za-z0-9+/]{24,}={0,2})""")

# Pattern for Cyrillic homoglyphs within strings
CYRILLIC_HOMOGLYPH_CHARS = {
    '\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
    '\u041d': 'H', '\u0456': 'i', '\u0406': 'I', '\u041a': 'K',
    '\u041c': 'M', '\u041e': 'O', '\u0420': 'P', '\u0422': 'T',
    '\u0425': 'X', '\u0430': 'a', '\u0441': 'c', '\u0435': 'e',
    '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y',
    '\u0445': 'x'
}
CYRILLIC_HOMOGLYPH_PATTERN = re.compile(r"""[\u0410\u0412\u0421\u0415\u041d\u0456\u0406\u041a\u041c\u041e\u0420\u0422\u0425\u0430\u0441\u0435\u043e\u0440\u0443\u0445]""")


class CovertTelemetryFinding:
    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        cwe: str,
        vuln_id: str,
        file_path: str,
        line_number: int,
        line_content: str,
        decoded_payload: Optional[str] = None,
        recommendation: str = ""
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.cwe = cwe
        self.vuln_id = vuln_id
        self.file_path = file_path
        self.line_number = line_number
        self.line_content = line_content.strip()
        self.decoded_payload = decoded_payload
        self.recommendation = recommendation
        self.fingerprint = self._compute_fingerprint()

    def _compute_fingerprint(self) -> str:
        anchor = f"{self.rule_id}:{self.file_path}:{self.line_number}:{self.cwe}"
        digest = hashlib.sha256(anchor.encode("utf-8")).hexdigest()
        return f"devia/v1:sha256:{digest}"

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "fingerprint": self.fingerprint,
            "ruleId": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "vulnerabilityId": self.vuln_id,
            "dimension": "SECRETS_CRYPTOGRAPHY",
            "location": {
                "path": self.file_path,
                "line": self.line_number
            },
            "evidence": {
                "snippet": self.line_content[:200]
            },
            "recommendation": self.recommendation
        }
        if self.decoded_payload:
            data["evidence"]["decodedPayload"] = self.decoded_payload[:300]
        return data


def try_decode_base64_payload(raw_candidate: str) -> Optional[str]:
    clean = raw_candidate.strip("'\"")
    # Padding if needed
    missing_padding = len(clean) % 4
    if missing_padding:
        clean += "=" * (4 - missing_padding)
    try:
        decoded_bytes = base64.b64decode(clean, validate=True)
        if len(decoded_bytes) < 8:
            return None
        text = decoded_bytes.decode("utf-8", errors="replace")
        # Check if text looks like script / command / curl / http
        if any(keyword in text.lower() for keyword in ["curl", "wget", "http", "bash", "sh", "python", "rm ", "echo", "exec"]):
            return text
        return None
    except Exception:
        return None


def inspect_homoglyphs(text: str) -> Optional[str]:
    """Detect words that maliciously mix ASCII Latin and Cyrillic homoglyphs within the same token."""
    # Split text into tokens / words
    tokens = re.findall(r'[^\s"\'\\/]+', text)
    mixed_tokens = []
    for token in tokens:
        has_latin = bool(re.search(r'[a-zA-Z]', token))
        has_cyrillic = bool(CYRILLIC_HOMOGLYPH_PATTERN.search(token))
        if has_latin and has_cyrillic:
            normalized = "".join(CYRILLIC_HOMOGLYPH_CHARS.get(c, c) for c in token)
            mixed_tokens.append(f"{token} -> {normalized}")

    if mixed_tokens:
        return "Tokens mezclando Latin y Cirílico: " + ", ".join(mixed_tokens)
    return None


def scan_file(file_path: Path, rel_path: str) -> List[CovertTelemetryFinding]:
    findings: List[CovertTelemetryFinding] = []
    
    try:
        size_kb = file_path.stat().st_size / 1024
        if size_kb > MAX_FILE_SIZE_KB:
            return findings
    except OSError:
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, start=1):
                if len(line) > MAX_LINE_LENGTH:
                    continue

                # 1. Check for Obfuscated Shell Pipelines
                for pattern, rule_id, title, sev, cwe, vuln_id in OBFUSCATED_PIPE_PATTERNS:
                    if pattern.search(line):
                        decoded = None
                        # Extract potential base64 tokens
                        for candidate in BASE64_TOKEN_PATTERN.findall(line):
                            d = try_decode_base64_payload(candidate)
                            if d:
                                decoded = d
                                break
                        findings.append(CovertTelemetryFinding(
                            rule_id=rule_id,
                            title=title,
                            severity=sev,
                            cwe=cwe,
                            vuln_id=vuln_id,
                            file_path=rel_path,
                            line_number=idx,
                            line_content=line,
                            decoded_payload=decoded,
                            recommendation="Erradicar tuberías que canalicen Base64 directamente a intérpretes. Declarar scripts en texto plano verificable."
                        ))

                # 2. Check for Telemetry / Exfiltration Endpoints
                for pattern, rule_id, title, sev, cwe, vuln_id in TELEMETRY_ENDPOINT_PATTERNS:
                    if pattern.search(line):
                        findings.append(CovertTelemetryFinding(
                            rule_id=rule_id,
                            title=title,
                            severity=sev,
                            cwe=cwe,
                            vuln_id=vuln_id,
                            file_path=rel_path,
                            line_number=idx,
                            line_content=line,
                            recommendation="Eliminar llamadas no autorizadas a pasarelas de mensajería (SMS/Webhooks). Requerir consentimiento explícito para cualquier telemetría."
                        ))

                # 3. Check for Cyrillic Homoglyphs in suspect payload lines
                if "echo" in line or "curl" in line or "wget" in line:
                    homo_res = inspect_homoglyphs(line)
                    if homo_res:
                        findings.append(CovertTelemetryFinding(
                            rule_id="HOMOGLYPH_OBFUSCATED_STRING",
                            title="Homóglifos cirílicos detectados en cadena de comando para evasión de firmas",
                            severity="HIGH",
                            cwe="CWE-1027",
                            vuln_id="VULN-CRYP-005",
                            file_path=rel_path,
                            line_number=idx,
                            line_content=line,
                            decoded_payload=homo_res,
                            recommendation="Normalizar cadenas Unicode a caracteres ASCII puros y auditar la procedencia de homóglifos cirílicos."
                        ))

                # 4. Check raw Base64 strings to see if they decode into hidden curl/SMS commands
                for token in BASE64_TOKEN_PATTERN.findall(line):
                    decoded = try_decode_base64_payload(token)
                    if decoded and any(ep in decoded.lower() for ep in ["textbelt.com", "api.twilio.com", "discord.com/api/webhooks", "api.telegram.org", "hooks.slack.com"]):
                        findings.append(CovertTelemetryFinding(
                            rule_id="EMBEDDED_BASE64_EXFILTRATION_BEACON",
                            title="Beacon de telemetría / exfiltración oculto dentro de payload Base64",
                            severity="CRITICAL",
                            cwe="CWE-359",
                            vuln_id="VULN-CRYP-005",
                            file_path=rel_path,
                            line_number=idx,
                            line_content=line,
                            decoded_payload=decoded,
                            recommendation="Remover el bloque Base64 malicioso e inspeccionar el origen del script."
                        ))
    except Exception:
        pass

    return findings


def scan_target(target_path: Path) -> List[CovertTelemetryFinding]:
    all_findings: List[CovertTelemetryFinding] = []
    
    if target_path.is_file():
        return scan_file(target_path, target_path.name)

    for root, dirs, files in os.walk(target_path):
        # Only skip known safe build/dependency/git directories, do NOT skip arbitrary dot-folders (.check, .temp, .settings)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            full_path = Path(root) / file
            rel_path = str(full_path.relative_to(target_path)).replace("\\", "/")
            findings = scan_file(full_path, rel_path)
            all_findings.extend(findings)

    return all_findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic Scanner for Covert Telemetry, Obfuscated Shell Pipelines, and Exfiltration Beacons"
    )
    parser.add_argument("target", help="Ruta del archivo o directorio a escanear")
    parser.add_argument("--json", action="store_true", help="Emitir resultados en formato JSON estandarizado")
    parser.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filtrar severidad mínima")

    args = parser.parse_args()
    target_path = Path(args.target).resolve()

    if not target_path.exists():
        print(f"Error: La ruta especificada no existe: {target_path}", file=sys.stderr)
        return 1

    findings = scan_target(target_path)

    # Filter severity if requested
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if args.severity:
        min_rank = severity_order[args.severity]
        findings = [f for f in findings if severity_order.get(f.severity, 0) >= min_rank]

    # Deduplicate findings by fingerprint
    unique_findings: Dict[str, CovertTelemetryFinding] = {}
    for f in findings:
        if f.fingerprint not in unique_findings:
            unique_findings[f.fingerprint] = f
    deduped = list(unique_findings.values())

    if args.json:
        output = {
            "target": str(target_path),
            "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "totalFindings": len(deduped),
            "findings": [f.to_dict() for f in deduped]
        }
        print(json.dumps(output, indent=2, ensure_ascii=True))
    else:
        print(f"\n[+] Devia-CyberSecurity - Covert Telemetry Scanner")
        print(f"Target: {target_path}")
        print(f"Total Hallazgos Detectados: {len(deduped)}\n")
        for f in deduped:
            safe_content = f.line_content[:120].encode("ascii", errors="backslashreplace").decode("ascii")
            print(f"[{f.severity}] {f.title} ({f.cwe})")
            print(f"  Ruta: {f.file_path}:{f.line_number}")
            print(f"  Regla: {f.rule_id} | Ref: {f.vuln_id}")
            print(f"  Evidencia: {safe_content}")
            if f.decoded_payload:
                safe_payload = f.decoded_payload[:120].encode("ascii", errors="backslashreplace").decode("ascii")
                print(f"  Payload Decodificado: {safe_payload}")
            print(f"  Mitigacion: {f.recommendation}\n")

    return 0 if len(deduped) == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
