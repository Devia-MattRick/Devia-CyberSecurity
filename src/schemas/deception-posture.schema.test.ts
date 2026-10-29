import test from "node:test";
import assert from "node:assert/strict";
import {
  DeceptionAssetSchema,
  CanaryFileAlertSchema,
  SpaPacketVerificationSchema,
  MitreEngageMappingSchema,
  DeceptionPostureReportSchema
} from "./deception-posture.schema.js";

test("DeceptionPostureSchema: validates a compliant deception asset", () => {
  const asset = {
    id: "DEC-001",
    name: "svc-canary-prod-aws",
    type: "DECOY_PRINCIPAL",
    environment: "CLOUD_AWS",
    placement: ".env files + CI secret store",
    denyAllPolicyEnforced: true,
    detectionWiring: {
      telemetrySource: "CloudTrail",
      alertRule: "CanaryKeyUsedAlert",
      notificationSink: "sns:arn:aws:sns:us-east-1:123456789012:soc-deception",
      playbookRef: "IR-PLAYBOOK-CLOUD-04"
    },
    internalTagPresent: true,
    lastValidatedAt: "2026-10-29T12:00:00Z"
  };

  const parsed = DeceptionAssetSchema.safeParse(asset);
  assert.equal(parsed.success, true);
});

test("DeceptionPostureSchema: validates a ransomware canary alert", () => {
  const alert = {
    type: "HIGH_ENTROPY_DETECTED",
    severity: "CRITICAL",
    path: "C:\\Shares\\Finance\\_AAAA_Financial_Report_2026.docx",
    entropy: 7.94,
    detectedProcess: {
      pid: 4892,
      name: "vssadmin_encrypt.exe",
      cmdline: "vssadmin_encrypt.exe /dir=C:\\Shares"
    },
    timestamp: "2026-10-29T12:30:15Z"
  };

  const parsed = CanaryFileAlertSchema.safeParse(alert);
  assert.equal(parsed.success, true);
});

test("DeceptionPostureSchema: validates SPA packet verification with replay detection", () => {
  const spaResult = {
    sourceIp: "192.168.10.45",
    serviceRequested: "ssh-admin-controller",
    timestamp: 1793280000,
    nonce: "a8f3b9c1d2e4f5a6",
    hmacVerified: true,
    ageSeconds: 12.4,
    replayDetected: true,
    valid: false,
    errors: ["Replay attack detected: nonce already processed in current time window"]
  };

  const parsed = SpaPacketVerificationSchema.safeParse(spaResult);
  assert.equal(parsed.success, true);
  if (parsed.success) {
    assert.equal(parsed.data.valid, false);
    assert.equal(parsed.data.replayDetected, true);
  }
});

test("DeceptionPostureSchema: validates MITRE Engage mapping", () => {
  const engageMap = {
    operationName: "Operation Dark Lure",
    strategicGoal: "EXPOSE",
    targetActor: "FIN7 / Carbon Spider",
    mappedAttackTechniques: ["T1078", "T1558.003", "T1486"],
    engageActivities: ["Decoy Credentials", "Lures", "Network Diversity"],
    coverageGaps: ["T1046"]
  };

  const parsed = MitreEngageMappingSchema.safeParse(engageMap);
  assert.equal(parsed.success, true);
});

test("DeceptionPostureSchema: validates full DeceptionPostureReport", () => {
  const report = {
    reportId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    generatedAt: "2026-10-29T13:00:00Z",
    dimension: "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
    totalAssets: 1,
    postureScore: 92.5,
    assets: [
      {
        id: "DEC-002",
        name: "ad-honeyroast-svc",
        type: "DECOY_SPN",
        environment: "ON_PREM_AD",
        placement: "OU=ServiceAccounts,DC=corp,DC=internal",
        denyAllPolicyEnforced: true,
        detectionWiring: {
          telemetrySource: "Windows Security Event ID 4769",
          alertRule: "DetectHoneyroastTgsRequest",
          notificationSink: "siem-sentinel-webhook"
        },
        internalTagPresent: true
      }
    ],
    canaryAlerts: [],
    summary: {
      compliantAssets: 1,
      nonCompliantAssets: 0,
      criticalAlertsCount: 0,
      replayAttacksBlocked: 2
    }
  };

  const parsed = DeceptionPostureReportSchema.safeParse(report);
  assert.equal(parsed.success, true);
});
