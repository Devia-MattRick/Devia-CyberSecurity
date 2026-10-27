import test from "node:test";
import assert from "node:assert/strict";
import {
  IncidentTriageRequestSchema,
  IncidentTriageEvaluationSchema
} from "./incident-triage.schema.js";

test("IncidentTriageRequestSchema validates a valid critical triage request", () => {
  const req = {
    incidentId: "INC-2026-001",
    title: "Active Ransomware Encryption on Production DB Cluster",
    incidentType: "ransomware",
    assetCriticality: "critical",
    dataSensitivity: "pii_phi",
    threatStatus: "active",
    scope: "enterprise",
    affectedAssets: ["db-prod-01.corp", "db-prod-02.corp"],
    indicatorsOfCompromise: ["sha256:abcd1234ef567890", "198.51.100.24"],
    detectedAt: "2026-10-27T19:00:00Z"
  };

  const parsed = IncidentTriageRequestSchema.safeParse(req);
  assert.equal(parsed.success, true);
});

test("IncidentTriageEvaluationSchema validates a valid evaluation response", () => {
  const res = {
    incidentId: "INC-2026-001",
    evaluatedAt: "2026-10-27T19:02:00Z",
    severity: "CRITICAL",
    score: 9.8,
    assignedPlaybook: "ransomware-ir-playbook-v3",
    assignedTeam: "Tier 3 Incident Response Team + Legal",
    slaResponseHours: 0.25,
    dimension: "RESILIENCE_LOGGING_TELEMETRY",
    nistCsfCategory: "RS.MA-01",
    sansPicerlPhase: "IDENTIFICATION_AND_TRIAGE",
    escalationRequired: true,
    containmentRecommendations: [
      "Isolate affected hosts from the internal network immediately via EDR network containment",
      "Revoke compromised Kerberos tickets and session tokens for high-privilege service accounts",
      "Preserve memory dump and volatile forensic evidence before rebooting"
    ]
  };

  const parsed = IncidentTriageEvaluationSchema.safeParse(res);
  assert.equal(parsed.success, true);
});

test("IncidentTriageRequestSchema rejects invalid incident type", () => {
  const req = {
    incidentId: "INC-2026-002",
    title: "Invalid incident type test",
    incidentType: "crypto_mining_arbitrary_unmapped",
    assetCriticality: "low",
    dataSensitivity: "public",
    threatStatus: "recon",
    scope: "single_system",
    affectedAssets: ["laptop-01"]
  };

  const parsed = IncidentTriageRequestSchema.safeParse(req);
  assert.equal(parsed.success, false);
});
