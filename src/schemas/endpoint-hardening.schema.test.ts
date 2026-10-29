import test from "node:test";
import assert from "node:assert/strict";
import {
  AsrRuleGuidSchema,
  AsrRuleModeSchema,
  DefenderPreferencesSchema,
  EndpointHardeningReportSchema
} from "./endpoint-hardening.schema.js";


test("EndpointHardeningSchema: validates canonical ASR rule GUIDs and modes", () => {
  const validGuid = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2"; // LSASS protection
  assert.equal(AsrRuleGuidSchema.parse(validGuid), validGuid);

  assert.throws(() => {
    AsrRuleGuidSchema.parse("INVALID-GUID-0000");
  });

  assert.equal(AsrRuleModeSchema.parse("BLOCK"), "BLOCK");
  assert.equal(AsrRuleModeSchema.parse("AUDIT"), "AUDIT");
  assert.throws(() => {
    AsrRuleModeSchema.parse("UNKNOWN_MODE");
  });
});

test("EndpointHardeningSchema: validates DefenderPreferences correctly", () => {
  const validPrefs = {
    realTimeProtection: true,
    behaviorMonitoring: true,
    ioavProtection: true,
    networkProtection: "BLOCK" as const,
    controlledFolderAccess: "BLOCK" as const,
    cloudBlockLevel: "HIGH" as const,
    puaProtection: "ENABLED" as const,
    tamperProtection: true,
    signatureAgeHours: 2.5
  };

  const parsed = DefenderPreferencesSchema.parse(validPrefs);
  assert.equal(parsed.realTimeProtection, true);
  assert.equal(parsed.cloudBlockLevel, "HIGH");
});

test("EndpointHardeningSchema: validates complete EndpointHardeningReport", () => {
  const sampleReport = {
    reportId: "a2b9f561-2678-43d9-9524-70a256f1dc77",
    evaluatedAt: "2026-10-29T13:20:00Z",
    hostId: "WIN-SEC-WORKSTATION-01",
    osPlatform: "WINDOWS_11" as const,
    defenderPreferences: {
      realTimeProtection: true,
      behaviorMonitoring: true,
      ioavProtection: true,
      networkProtection: "BLOCK" as const,
      controlledFolderAccess: "AUDIT" as const,
      cloudBlockLevel: "HIGH_PLUS" as const,
      puaProtection: "ENABLED" as const,
      tamperProtection: true
    },
    asrRules: [
      {
        guid: "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" as const,
        name: "Block credential stealing from LSASS",
        currentMode: "BLOCK" as const,
        expectedMode: "BLOCK" as const,
        isCompliant: true,
        mitreTechnique: "T1003.001"
      },
      {
        guid: "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" as const,
        name: "Block Office child processes",
        currentMode: "DISABLED" as const,
        expectedMode: "BLOCK" as const,
        isCompliant: false,
        mitreTechnique: "T1059.001"
      }
    ],
    complianceScore: 85,
    criticalGaps: [
      "Rule D4F940AB-401B-4EFC-AADC-AD5F3C50688A (Office child processes) is DISABLED."
    ],
    verdict: "WARN" as const,
    remediationGuidance: [
      "Set-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled"
    ]
  };

  const parsed = EndpointHardeningReportSchema.parse(sampleReport);
  assert.equal(parsed.hostId, "WIN-SEC-WORKSTATION-01");
  assert.equal(parsed.complianceScore, 85);
  assert.equal(parsed.verdict, "WARN");
  assert.equal(parsed.asrRules.length, 2);
});
