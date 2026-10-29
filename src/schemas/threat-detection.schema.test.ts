import test from "node:test";
import assert from "node:assert/strict";
import {
  DetectionEngineTypeSchema,
  DetectionRuleSchema,
  DetectionAlertSchema,
  ThreatDetectionReportSchema
} from "./threat-detection.schema.js";

test("ThreatDetectionSchema: validates detection engine types", () => {
  const validEngines = [
    "WINDOWS_SECURITY_EVENT",
    "SYSMON",
    "ZEEK",
    "FALCO",
    "CLOUDTRAIL",
    "GUARDDUTY",
    "AI_GUARDRAIL",
    "OT_ICS_PROTOCOL"
  ];
  for (const eng of validEngines) {
    const res = DetectionEngineTypeSchema.safeParse(eng);
    assert.equal(res.success, true);
  }

  const invalid = DetectionEngineTypeSchema.safeParse("UNKNOWN_ENGINE");
  assert.equal(invalid.success, false);
});

test("ThreatDetectionSchema: validates a Golden Ticket correlation rule", () => {
  const goldenTicketRule = {
    ruleId: "rule-kerberos-golden-ticket-01",
    title: "Detección de Forja de Golden Ticket Kerberos",
    engine: "WINDOWS_SECURITY_EVENT",
    dimension: "RESILIENCE_LOGGING_TELEMETRY",
    mitreTechnique: "T1558.001",
    cwe: ["CWE-287", "CWE-327"],
    severity: "CRITICAL",
    description: "Identifica solicitudes TGS con cifrado RC4 (0x17) o sin TGT previo en Event 4769",
    correlationWindow: {
      windowSeconds: 3600,
      minOccurrences: 1,
      groupBy: ["userAccount", "targetHost"]
    },
    detectionLogic: "EventID == 4769 && TicketEncryptionType == '0x17' && OrphanTGS == true"
  };

  const parsed = DetectionRuleSchema.safeParse(goldenTicketRule);
  assert.equal(parsed.success, true);
});

test("ThreatDetectionSchema: validates a detection alert and consolidated report", () => {
  const alert = {
    alertId: "123e4567-e89b-12d3-a456-426614174000",
    timestamp: "2026-10-29T16:00:00Z",
    ruleId: "rule-sysmon-process-injection-01",
    engine: "SYSMON",
    dimension: "RESILIENCE_LOGGING_TELEMETRY",
    severity: "HIGH",
    confidenceScore: 9.5,
    sourceHost: "HOST-FINANCE-01",
    targetHost: "HOST-FINANCE-01",
    userAccount: "CORP\\jsmith",
    processName: "powershell.exe",
    commandLine: "powershell.exe -enc AAAA...",
    evidenceSnippet: "Sysmon Event 10: GrantedAccess=0x1F0FFF Source=powershell.exe Target=lsass.exe",
    correlatedEventCount: 2,
    correlationDetails: {
      grantedAccess: "0x1F0FFF",
      callTrace: "ntdll.dll+0x1234|kernel32.dll+0x5678"
    }
  };

  const alertParsed = DetectionAlertSchema.safeParse(alert);
  assert.equal(alertParsed.success, true);

  const report = {
    reportId: "987fcdeb-51a2-43d7-9012-345678901234",
    generatedAt: "2026-10-29T16:05:00Z",
    scanTarget: "corp-domain-controllers-cluster",
    enginesEvaluated: ["WINDOWS_SECURITY_EVENT", "SYSMON", "ZEEK"],
    evaluatedDimensions: ["RESILIENCE_LOGGING_TELEMETRY", "ARCHITECTURE_BOUNDARIES_ZERO_TRUST"],
    totalEventsProcessed: 145000,
    totalAlertsTriggered: 1,
    alertsBySeverity: {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 0,
      LOW: 0,
      INFORMATIONAL: 0
    },
    alertsByDimension: {
      THREAT_MODELING_ATTACK_SURFACE: 0,
      SOURCE_CODE_SAST: 0,
      SECRETS_CRYPTOGRAPHY: 0,
      IDENTITY_ACCESS_SESSION: 0,
      SUPPLY_CHAIN_SCA: 0,
      ARCHITECTURE_BOUNDARIES_ZERO_TRUST: 0,
      CONFIGURATION_HARDENING: 0,
      RESILIENCE_LOGGING_TELEMETRY: 1
    },
    alerts: [alert]
  };

  const reportParsed = ThreatDetectionReportSchema.safeParse(report);
  assert.equal(reportParsed.success, true);
});

test("ThreatDetectionSchema: rejects invalid MITRE technique identifier", () => {
  const invalidRule = {
    ruleId: "bad-rule",
    title: "Bad Rule",
    engine: "ZEEK",
    dimension: "RESILIENCE_LOGGING_TELEMETRY",
    mitreTechnique: "INVALID_MITRE_FORMAT",
    severity: "LOW",
    description: "Testing regex validation on technique format",
    detectionLogic: "true"
  };

  const parsed = DetectionRuleSchema.safeParse(invalidRule);
  assert.equal(parsed.success, false);
});
