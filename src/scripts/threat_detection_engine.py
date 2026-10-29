#!/usr/bin/env python3
"""Threat Detection & Multi-Source Event Correlation Engine for Devia-CyberSecurity.

Analyzes security event logs deterministically across multiple engines:
1. WINDOWS_SECURITY_EVENT: Kerberos Golden Ticket (4768/4769), NTLM Relay (4624 Type 3), DCSync (4662).
2. SYSMON: Process Injection T1055 (Event 10 GrantedAccess 0x1F0FFF / 0x0020), CreateRemoteThread (Event 8).
3. ZEEK: C2 Beaconing (conn.log interval CV < 0.30), DNS Exfiltration (entropy >= 3.5 or length >= 40).
4. OT_ICS_PROTOCOL: Modbus TCP unauthorized write function codes (5, 6, 15, 16, 22, 23).
5. AI_GUARDRAIL: Direct prompt injection, Unicode Tag smuggling (0xE0000-0xE007F) and zero-width characters.

Outputs deterministic JSON matching ThreatDetectionReportSchema.
Zero external dependencies (Python 3.11+ stdlib only).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import math
import os
import re
import sys
import uuid

# Windows UTF-8 stdout configuration
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

# Unicode Tag range for ASCII smuggling (0xE0000 to 0xE007F)
UNICODE_TAG_RANGE = set(range(0xE0000, 0xE0080))
ZERO_WIDTH_CHARS = set("\u200B\u200C\u200D\u200E\u200F\uFEFF")

# Modbus dangerous write function codes
DANGEROUS_MODBUS_FUNCTIONS = {5, 6, 15, 16, 22, 23}

# Sysmon injection access masks
INJECTION_ACCESS_MASKS = {
    "0x1f0fff": "PROCESS_ALL_ACCESS",
    "0x001f0fff": "PROCESS_ALL_ACCESS",
    "0x0020": "PROCESS_VM_WRITE",
    "0x0008": "PROCESS_VM_OPERATION",
    "0x0010": "PROCESS_VM_READ"
}

# Prompt injection core regexes
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|system|initial)\b.{0,20}\b(instructions?|prompts?|rules?|directives?)\b"),
    re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|simulate\s+being|switch\s+to|enter\s+.{0,10}mode)\b"),
    re.compile(r"(?i)\b(do\s+not\s+follow|new\s+instructions?|instead\s+(do|say|output|respond))\b"),
    re.compile(r"(?i)\b(reveal|print|leak|exfiltrate)\b.{0,25}\b(system\s+prompt|secret|api_key|password|token)\b")
]


def calculate_entropy(text: str) -> float:
    """Calcula la entropía de Shannon en bits por símbolo para detección de empaquetado/cifrado."""
    if not text:
        return 0.0
    length = len(text)
    counts = defaultdict(int)
    for char in text:
        counts[char] += 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class ThreatDetectionEngine:
    def __init__(self, scan_target: str = "default-environment"):
        self.scan_target = scan_target
        self.alerts: list[dict] = []
        self.total_events_processed = 0
        self.engines_evaluated: set[str] = set()
        self.dimensions_evaluated: set[str] = set()

    def add_alert(
        self,
        rule_id: str,
        engine: str,
        dimension: str,
        severity: str,
        confidence_score: float,
        evidence_snippet: str,
        source_host: str | None = None,
        target_host: str | None = None,
        user_account: str | None = None,
        process_name: str | None = None,
        command_line: str | None = None,
        correlated_event_count: int = 1,
        correlation_details: dict | None = None,
        timestamp: str | None = None
    ) -> dict:
        alert = {
            "alertId": str(uuid.uuid4()),
            "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ruleId": rule_id,
            "engine": engine,
            "dimension": dimension,
            "severity": severity,
            "confidenceScore": round(confidence_score, 1),
            "evidenceSnippet": evidence_snippet,
            "correlatedEventCount": correlated_event_count
        }
        if source_host:
            alert["sourceHost"] = source_host
        if target_host:
            alert["targetHost"] = target_host
        if user_account:
            alert["userAccount"] = user_account
        if process_name:
            alert["processName"] = process_name
        if command_line:
            alert["commandLine"] = command_line
        if correlation_details:
            alert["correlationDetails"] = correlation_details

        self.alerts.append(alert)
        self.engines_evaluated.add(engine)
        self.dimensions_evaluated.add(dimension)
        return alert

    # 1. WINDOWS SECURITY EVENTS EVALUATOR
    def evaluate_windows_events(self, events: list[dict]) -> None:
        self.engines_evaluated.add("WINDOWS_SECURITY_EVENT")
        self.total_events_processed += len(events)

        # Track Kerberos 4768 (TGT) and 4769 (TGS)
        tgt_accounts = set()
        ntlm_auth_sequence: defaultdict[str, list[dict]] = defaultdict(list)

        for ev in events:
            event_id = ev.get("EventID") or ev.get("eventId")
            ts = ev.get("TimeCreated") or ev.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # A. Kerberos TGT (4768)
            if event_id == 4768:
                account = ev.get("TargetUserName") or ev.get("userName")
                if account:
                    tgt_accounts.add(account.lower())

            # B. Kerberos TGS (4769) - Golden Ticket & RC4 Forgery
            elif event_id == 4769:
                account = (ev.get("TargetUserName") or ev.get("userName") or "").lower()
                service = ev.get("ServiceName") or ev.get("service")
                ticket_etype = (ev.get("TicketEncryptionType") or "").lower()
                
                # Check for weak RC4 ticket encryption (0x17)
                if ticket_etype == "0x17":
                    self.add_alert(
                        rule_id="win-kerberos-rc4-ticket-01",
                        engine="WINDOWS_SECURITY_EVENT",
                        dimension="RESILIENCE_LOGGING_TELEMETRY",
                        severity="HIGH",
                        confidence_score=9.0,
                        evidence_snippet=f"Event 4769 solicitó ticket TGS con cifrado débil RC4 (0x17) para el servicio '{service}' por cuenta '{account}'.",
                        user_account=account,
                        target_host=ev.get("Computer") or ev.get("host"),
                        correlation_details={"encryptionType": ticket_etype, "service": service},
                        timestamp=ts
                    )

                # Check for Orphan TGS (no prior TGT request recorded)
                if account and account not in tgt_accounts and not account.endswith("$"):
                    self.add_alert(
                        rule_id="win-kerberos-golden-ticket-orphan-01",
                        engine="WINDOWS_SECURITY_EVENT",
                        dimension="RESILIENCE_LOGGING_TELEMETRY",
                        severity="CRITICAL",
                        confidence_score=9.5,
                        evidence_snippet=f"Event 4769 TGS huérfano: cuenta '{account}' solicitó servicio '{service}' sin solicitud TGT previa (4768), indicativo de Golden Ticket.",
                        user_account=account,
                        target_host=ev.get("Computer") or ev.get("host"),
                        correlation_details={"orphanTGS": True, "service": service},
                        timestamp=ts
                    )

            # C. Event 4624 (Logon Type 3) - NTLM Relay & Discrepancies
            elif event_id == 4624:
                logon_type = ev.get("LogonType")
                auth_pkg = ev.get("AuthenticationPackageName") or ev.get("authPackage")
                if logon_type == 3 and auth_pkg and "NTLM" in str(auth_pkg):
                    src_ip = ev.get("IpAddress") or ev.get("sourceIp")
                    account = ev.get("TargetUserName") or ev.get("userName")
                    target = ev.get("Computer") or ev.get("host")
                    if src_ip and account:
                        key = f"{src_ip}:{account}"
                        ntlm_auth_sequence[key].append({
                            "target": target,
                            "timestamp": ts,
                            "event": ev
                        })

            # D. Event 4662 (DCSync Directory Replication)
            elif event_id == 4662:
                access_mask = (ev.get("AccessMask") or "").lower()
                account = ev.get("SubjectUserName") or ev.get("userName")
                obj_server = ev.get("ObjectServer")
                # DCSync rights: DS-Replication-Get-Changes-All (0x100)
                if "0x100" in access_mask or "100" in access_mask:
                    self.add_alert(
                        rule_id="win-activedirectory-dcsync-01",
                        engine="WINDOWS_SECURITY_EVENT",
                        dimension="IDENTITY_ACCESS_SESSION",
                        severity="CRITICAL",
                        confidence_score=9.8,
                        evidence_snippet=f"Event 4662: Cuenta '{account}' ejerció derechos de replicación DS-Replication (DCSync) con máscara 0x100.",
                        user_account=account,
                        target_host=ev.get("Computer") or ev.get("host"),
                        correlation_details={"accessMask": access_mask, "objectServer": obj_server},
                        timestamp=ts
                    )

        # Correlate rapid multi-host NTLM Relay
        for key, entries in ntlm_auth_sequence.items():
            unique_targets = set(e["target"] for e in entries if e["target"])
            if len(unique_targets) >= 3:
                src_ip, account = key.split(":", 1)
                self.add_alert(
                    rule_id="win-ntlm-relay-multihost-01",
                    engine="WINDOWS_SECURITY_EVENT",
                    dimension="RESILIENCE_LOGGING_TELEMETRY",
                    severity="CRITICAL",
                    confidence_score=9.2,
                    evidence_snippet=f"Retransmisión NTLM detectada: Cuenta '{account}' autenticó desde '{src_ip}' contra {len(unique_targets)} destinos únicos ({', '.join(list(unique_targets)[:3])}).",
                    source_host=src_ip,
                    user_account=account,
                    correlated_event_count=len(entries),
                    correlation_details={"uniqueTargets": list(unique_targets)}
                )

    # 2. SYSMON EVALUATOR
    def evaluate_sysmon_events(self, events: list[dict]) -> None:
        self.engines_evaluated.add("SYSMON")
        self.total_events_processed += len(events)

        for ev in events:
            event_id = ev.get("EventID") or ev.get("eventId")
            ts = ev.get("TimeCreated") or ev.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Sysmon Event 10: ProcessAccess (Injection T1055)
            if event_id == 10:
                granted_access = (ev.get("GrantedAccess") or "").lower()
                source_image = ev.get("SourceImage") or ev.get("sourceProcess") or ""
                target_image = ev.get("TargetImage") or ev.get("targetProcess") or ""

                if any(mask in granted_access for mask in ["0x1f0fff", "0x001f0fff", "0x0020"]):
                    severity = "CRITICAL" if "lsass.exe" in target_image.lower() else "HIGH"
                    self.add_alert(
                        rule_id="sysmon-process-injection-t1055-01",
                        engine="SYSMON",
                        dimension="RESILIENCE_LOGGING_TELEMETRY",
                        severity=severity,
                        confidence_score=9.6,
                        evidence_snippet=f"Sysmon Event 10: Proceso '{source_image}' abrió '{target_image}' con máscara de inyección '{granted_access}'.",
                        process_name=os.path.basename(source_image),
                        target_host=ev.get("Computer") or ev.get("host"),
                        correlation_details={
                            "grantedAccess": granted_access,
                            "sourceImage": source_image,
                            "targetImage": target_image
                        },
                        timestamp=ts
                    )

            # Sysmon Event 8: CreateRemoteThread
            elif event_id == 8:
                source_image = ev.get("SourceImage") or ""
                target_image = ev.get("TargetImage") or ""
                if source_image.lower() != target_image.lower():
                    self.add_alert(
                        rule_id="sysmon-create-remote-thread-01",
                        engine="SYSMON",
                        dimension="RESILIENCE_LOGGING_TELEMETRY",
                        severity="HIGH",
                        confidence_score=9.1,
                        evidence_snippet=f"Sysmon Event 8: Hilo remoto creado desde '{source_image}' en el espacio de memoria de '{target_image}'.",
                        process_name=os.path.basename(source_image),
                        target_host=ev.get("Computer") or ev.get("host"),
                        correlation_details={"sourceImage": source_image, "targetImage": target_image},
                        timestamp=ts
                    )

            # Sysmon Event 1: Process Creation (LOLBAS & Execution)
            elif event_id == 1:
                cmdline = ev.get("CommandLine") or ""
                image = ev.get("Image") or ""
                # Check for suspicious PowerShell execution patterns
                if "powershell" in image.lower():
                    if any(flag in cmdline.lower() for flag in ["-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex"]):
                        self.add_alert(
                            rule_id="sysmon-powershell-encoded-execution-01",
                            engine="SYSMON",
                            dimension="RESILIENCE_LOGGING_TELEMETRY",
                            severity="HIGH",
                            confidence_score=8.8,
                            evidence_snippet=f"Sysmon Event 1: Invocación de PowerShell con comando ofuscado o descarga en memoria: {cmdline[:120]}...",
                            process_name=os.path.basename(image),
                            command_line=cmdline,
                            target_host=ev.get("Computer") or ev.get("host"),
                            timestamp=ts
                        )

    # 3. ZEEK LOGS EVALUATOR
    def evaluate_zeek_logs(self, conn_events: list[dict], dns_events: list[dict]) -> None:
        self.engines_evaluated.add("ZEEK")
        self.total_events_processed += len(conn_events) + len(dns_events)

        # A. C2 Beaconing in conn.log
        grouped_conns: defaultdict[tuple, list[float]] = defaultdict(list)
        for c in conn_events:
            src = c.get("id.orig_h") or c.get("sourceIp")
            dst = c.get("id.resp_h") or c.get("destIp")
            port = c.get("id.resp_p") or c.get("destPort")
            ts = c.get("ts") or c.get("timestamp")
            if src and dst and port and ts is not None:
                try:
                    ts_float = float(ts) if not isinstance(ts, (int, float)) else float(ts)
                    grouped_conns[(src, dst, port)].append(ts_float)
                except ValueError:
                    continue

        for (src, dst, port), timestamps in grouped_conns.items():
            if len(timestamps) >= 5:
                timestamps.sort()
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                mean_int = sum(intervals) / len(intervals)
                if mean_int > 0:
                    variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
                    std_dev = math.sqrt(variance)
                    cv = std_dev / mean_int
                    if cv < 0.30:  # High regularity beacon
                        score = max(0, 1.0 - cv) * 100
                        self.add_alert(
                            rule_id="zeek-c2-beaconing-detected-01",
                            engine="ZEEK",
                            dimension="RESILIENCE_LOGGING_TELEMETRY",
                            severity="HIGH",
                            confidence_score=9.3,
                            evidence_snippet=f"Zeek conn.log balizamiento C2: {src} -> {dst}:{port} ({len(timestamps)} conexiones, intervalo medio={mean_int:.1f}s, CV={cv:.3f}, BeaconScore={score:.1f}).",
                            source_host=str(src),
                            target_host=str(dst),
                            correlated_event_count=len(timestamps),
                            correlation_details={"cv": cv, "meanInterval": mean_int, "beaconScore": score}
                        )

        # B. DNS Exfiltration & Tunneling in dns.log
        for d in dns_events:
            query = d.get("query") or d.get("domain") or ""
            ts = d.get("ts") or d.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            src = d.get("id.orig_h") or d.get("sourceIp")
            if query:
                entropy = calculate_entropy(query)
                length = len(query)
                if entropy >= 3.5 or length >= 40:
                    self.add_alert(
                        rule_id="zeek-dns-exfiltration-tunneling-01",
                        engine="ZEEK",
                        dimension="RESILIENCE_LOGGING_TELEMETRY",
                        severity="HIGH",
                        confidence_score=9.0,
                        evidence_snippet=f"Zeek dns.log consulta anómala: '{query[:60]}' (Entropía={entropy:.2f}, Longitud={length}).",
                        source_host=str(src) if src else None,
                        correlation_details={"entropy": entropy, "length": length, "query": query},
                        timestamp=str(ts)
                    )

    # 4. OT / ICS PROTOCOL EVALUATOR
    def evaluate_ot_ics_events(self, events: list[dict]) -> None:
        self.engines_evaluated.add("OT_ICS_PROTOCOL")
        self.total_events_processed += len(events)

        for ev in events:
            proto = (ev.get("protocol") or "").upper()
            func_code = ev.get("functionCode") or ev.get("func_code")
            src = ev.get("sourceIp") or ev.get("src")
            dst = ev.get("destIp") or ev.get("dst")
            ts = ev.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            if proto == "MODBUS" and func_code is not None:
                try:
                    f_int = int(func_code)
                    if f_int in DANGEROUS_MODBUS_FUNCTIONS:
                        self.add_alert(
                            rule_id="ot-modbus-command-injection-01",
                            engine="OT_ICS_PROTOCOL",
                            dimension="ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
                            severity="CRITICAL",
                            confidence_score=9.4,
                            evidence_snippet=f"Modbus TCP comando de escritura peligroso (Función {f_int}) transmitido desde {src} hacia PLC {dst}.",
                            source_host=src,
                            target_host=dst,
                            correlation_details={"functionCode": f_int, "protocol": proto},
                            timestamp=ts
                        )
                except ValueError:
                    continue

    # 5. AI GUARDRAIL EVALUATOR
    def evaluate_ai_prompts(self, prompt_events: list[dict]) -> None:
        self.engines_evaluated.add("AI_GUARDRAIL")
        self.total_events_processed += len(prompt_events)

        for pe in prompt_events:
            text = pe.get("promptText") or pe.get("content") or ""
            source = pe.get("sourceUser") or pe.get("user")
            ts = pe.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Check for Unicode Tag Smuggling (ASCII smuggling 0xE0000 - 0xE007F)
            tag_chars = [ch for ch in text if ord(ch) in UNICODE_TAG_RANGE]
            if tag_chars:
                self.add_alert(
                    rule_id="ai-unicode-tag-smuggling-01",
                    engine="AI_GUARDRAIL",
                    dimension="THREAT_MODELING_ATTACK_SURFACE",
                    severity="CRITICAL",
                    confidence_score=9.9,
                    evidence_snippet=f"Contrabando de texto ASCII detectado: {len(tag_chars)} caracteres del bloque Unicode Tags (0xE0000-0xE007F) incrustados en el prompt.",
                    user_account=source,
                    correlation_details={"tagCharCount": len(tag_chars)},
                    timestamp=ts
                )

            # Check for Zero-Width text obfuscation
            zw_chars = [ch for ch in text if ch in ZERO_WIDTH_CHARS]
            if len(zw_chars) >= 3:
                self.add_alert(
                    rule_id="ai-zero-width-obfuscation-01",
                    engine="AI_GUARDRAIL",
                    dimension="THREAT_MODELING_ATTACK_SURFACE",
                    severity="HIGH",
                    confidence_score=9.1,
                    evidence_snippet=f"Texto camuflado con caracteres invisibles de ancho cero ({len(zw_chars)} caracteres zero-width identificados).",
                    user_account=source,
                    correlation_details={"zeroWidthCount": len(zw_chars)},
                    timestamp=ts
                )

            # Check for Direct Injection patterns
            for pat in PROMPT_INJECTION_PATTERNS:
                m = pat.search(text)
                if m:
                    self.add_alert(
                        rule_id="ai-direct-prompt-injection-01",
                        engine="AI_GUARDRAIL",
                        dimension="THREAT_MODELING_ATTACK_SURFACE",
                        severity="HIGH",
                        confidence_score=9.2,
                        evidence_snippet=f"Firma de inyección de prompt detectada: '{m.group(0)[:80]}'.",
                        user_account=source,
                        correlation_details={"matchedPattern": m.group(0)},
                        timestamp=ts
                    )
                    break

    def generate_report(self) -> dict:
        """Construye el reporte estructurado consolidado conforme a ThreatDetectionReportSchema."""
        alerts_by_sev = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFORMATIONAL": 0
        }
        alerts_by_dim = {
            "THREAT_MODELING_ATTACK_SURFACE": 0,
            "SOURCE_CODE_SAST": 0,
            "SECRETS_CRYPTOGRAPHY": 0,
            "IDENTITY_ACCESS_SESSION": 0,
            "SUPPLY_CHAIN_SCA": 0,
            "ARCHITECTURE_BOUNDARIES_ZERO_TRUST": 0,
            "CONFIGURATION_HARDENING": 0,
            "RESILIENCE_LOGGING_TELEMETRY": 0
        }

        for alert in self.alerts:
            sev = alert["severity"]
            dim = alert["dimension"]
            if sev in alerts_by_sev:
                alerts_by_sev[sev] += 1
            if dim in alerts_by_dim:
                alerts_by_dim[dim] += 1

        all_canonical_engines = [
            "WINDOWS_SECURITY_EVENT",
            "SYSMON",
            "ZEEK",
            "FALCO",
            "CLOUDTRAIL",
            "GUARDDUTY",
            "AI_GUARDRAIL",
            "OT_ICS_PROTOCOL"
        ]
        active_engines = [e for e in all_canonical_engines if e in self.engines_evaluated]
        if not active_engines:
            active_engines = ["WINDOWS_SECURITY_EVENT"]

        all_canonical_dims = list(alerts_by_dim.keys())
        active_dims = [d for d in all_canonical_dims if d in self.dimensions_evaluated]
        if not active_dims:
            active_dims = ["RESILIENCE_LOGGING_TELEMETRY"]

        report = {
            "reportId": str(uuid.uuid4()),
            "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scanTarget": self.scan_target,
            "enginesEvaluated": active_engines,
            "evaluatedDimensions": active_dims,
            "totalEventsProcessed": self.total_events_processed,
            "totalAlertsTriggered": len(self.alerts),
            "alertsBySeverity": alerts_by_sev,
            "alertsByDimension": alerts_by_dim,
            "alerts": self.alerts
        }
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Threat Detection & Event Correlation Engine")
    parser.add_argument("-i", "--input", help="Path to input JSON file containing event streams")
    parser.add_argument("-o", "--output", help="Path to output JSON report file")
    parser.add_argument("--target", default="scanned-environment", help="Name of scanned target or cluster")
    parser.add_argument("--json", action="store_true", help="Emit report as formatted JSON to stdout")
    args = parser.parse_args()

    engine = ThreatDetectionEngine(scan_target=args.target)

    if args.input and os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)

        if "windowsEvents" in data:
            engine.evaluate_windows_events(data["windowsEvents"])
        if "sysmonEvents" in data:
            engine.evaluate_sysmon_events(data["sysmonEvents"])
        if "zeekConn" in data or "zeekDns" in data:
            engine.evaluate_zeek_logs(data.get("zeekConn", []), data.get("zeekDns", []))
        if "otEvents" in data:
            engine.evaluate_ot_ics_events(data["otEvents"])
        if "aiPrompts" in data:
            engine.evaluate_ai_prompts(data["aiPrompts"])

    report = engine.generate_report()

    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Report written to {args.output}")

    if args.json or not args.output:
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    sys.exit(main())
