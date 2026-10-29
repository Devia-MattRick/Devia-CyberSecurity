import test from "node:test";
import assert from "node:assert/strict";
import {
  ThreatHuntFindingSchema,
  ThreatHuntReportSchema,
  C2BeaconMetricsSchema
} from "./threat-hunt.schema.js";

test("C2BeaconMetricsSchema: validates valid statistical beaconing metrics", () => {
  const metrics = {
    totalConnections: 25,
    avgIntervalSeconds: 60.12,
    intervalStdev: 0.85,
    coefficientOfVariation: 0.0141,
    estimatedJitterPct: 1.41,
    dataSizeCv: 0.02,
    destinationEntropy: 4.12
  };
  const parsed = C2BeaconMetricsSchema.safeParse(metrics);
  assert.equal(parsed.success, true);
});

test("ThreatHuntFindingSchema: validates a canonical C2 beaconing finding", () => {
  const finding = {
    findingId: "TH-FIND-001",
    huntId: "HUNT-C2-2026-10",
    technique: "T1071.001",
    dimension: "RESILIENCE_LOGGING_TELEMETRY",
    cwe: ["CWE-923"],
    severity: "HIGH",
    confidenceScore: 9.2,
    sourceEntity: "192.168.1.100",
    targetEntity: "c2-domain-evil-98z7q.xyz",
    beaconMetrics: {
      totalConnections: 25,
      avgIntervalSeconds: 60.12,
      intervalStdev: 0.85,
      coefficientOfVariation: 0.0141,
      estimatedJitterPct: 1.41,
      dataSizeCv: 0.02,
      destinationEntropy: 4.12
    },
    indicators: [
      "Ultra-regular interval (CV=0.0141)",
      "High destination string entropy (4.12 bits)"
    ],
    firstSeen: "2026-10-28T12:00:00Z",
    lastSeen: "2026-10-28T12:24:00Z",
    evidenceSnippet: "conn.log line 402: 192.168.1.100 -> c2-domain-evil-98z7q.xyz:8443"
  };

  const parsed = ThreatHuntFindingSchema.safeParse(finding);
  assert.equal(parsed.success, true);
});

test("ThreatHuntFindingSchema: rejects invalid technique format", () => {
  const finding = {
    findingId: "TH-FIND-002",
    huntId: "HUNT-01",
    technique: "INVALID_TECHNIQUE",
    dimension: "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    severity: "MEDIUM",
    confidenceScore: 7.0,
    sourceEntity: "host-01",
    targetEntity: "file.exe",
    indicators: ["suspicious file"],
    firstSeen: "2026-10-28T12:00:00Z",
    lastSeen: "2026-10-28T12:00:00Z"
  };

  const parsed = ThreatHuntFindingSchema.safeParse(finding);
  assert.equal(parsed.success, false);
});

test("ThreatHuntReportSchema: validates a consolidated threat hunting campaign report", () => {
  const report = {
    reportId: "a2b0c1d2-3e4f-4a6b-8c8d-9e0f1a2b3c4d",
    generatedAt: "2026-10-28T14:30:00Z",
    huntObjective: "Proactive Hunting for C2 Beaconing and UEFI Bootkit Persistence",
    evaluatedDimensions: [
      "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
      "RESILIENCE_LOGGING_TELEMETRY",
      "IDENTITY_ACCESS_SESSION"
    ],
    telemetrySources: ["zeek:conn.log", "windows:sysmon:eid3"],
    findings: [
      {
        findingId: "TH-FIND-001",
        huntId: "HUNT-C2-2026-10",
        technique: "T1071.001",
        dimension: "RESILIENCE_LOGGING_TELEMETRY",
        cwe: ["CWE-923"],
        severity: "HIGH",
        confidenceScore: 9.2,
        sourceEntity: "192.168.1.100",
        targetEntity: "c2-domain-evil-98z7q.xyz",
        indicators: ["Ultra-regular interval (CV=0.0141)"],
        firstSeen: "2026-10-28T12:00:00Z",
        lastSeen: "2026-10-28T12:24:00Z"
      }
    ],
    metrics: {
      totalFindings: 1,
      criticalFindings: 0,
      highFindings: 1
    }
  };

  const parsed = ThreatHuntReportSchema.safeParse(report);
  assert.equal(parsed.success, true);
});
