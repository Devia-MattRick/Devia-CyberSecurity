import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RedTeamActivitySchema,
  DetectionGapReportSchema,
  DetectionVerdictSchema
} from "./detection-gap.schema.js";

describe("DetectionGapSchema Contract Test", () => {
  it("valida una actividad ofensiva del Red Team", () => {
    const validActivity = {
      activityId: "ACT-001",
      name: "Kerberoasting contra cuentas de servicio",
      techniqueId: "T1558.003",
      tactic: "Credential Access",
      timestamp: "2026-10-29T10:15:00Z",
      sourceHost: "workstation-04.corp.local",
      targetHost: "dc01.corp.local",
      toolOrMethod: "Rubeus kerberoast /nowrap",
      executionEvidence: "Solicitud de TGS con cifrado RC4 para SPN MSSQLSvc/db01.corp.local:1433",
      tags: ["kerberos", "internal-recon"]
    };

    const parsed = RedTeamActivitySchema.safeParse(validActivity);
    assert.equal(parsed.success, true);
  });

  it("valida un reporte completo de brechas de detección", () => {
    const validReport = {
      engagementId: "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      campaignName: "Simulación de Adversario APT29 Q3",
      evaluatedPeriod: {
        start: "2026-10-20T00:00:00Z",
        end: "2026-10-29T23:59:59Z"
      },
      totalActivities: 2,
      metrics: {
        detectedCount: 1,
        missedCount: 1,
        loggedOnlyCount: 0,
        detectionRatePercent: 50.0,
        meanDetectionLagSeconds: 120.0
      },
      blindSpotTechniques: ["T1003.006"],
      gaps: [
        {
          gapId: "GAP-001",
          activityId: "ACT-001",
          techniqueId: "T1003.006",
          verdict: "MISSED_SILENT",
          rootCause: "El registro de eventos de replicación de AD (Event ID 4662) no está reenviándose al SIEM.",
          remediationRecommendation: "Habilitar Sysmon y reenviar eventos de seguridad del DC con regla Sigma para replicación anómala."
        }
      ]
    };

    const parsed = DetectionGapReportSchema.safeParse(validReport);
    assert.equal(parsed.success, true);
  });

  it("rechaza veredictos de detección inválidos", () => {
    const invalidVerdict = DetectionVerdictSchema.safeParse("IGNORED");
    assert.equal(invalidVerdict.success, false);
  });
});
