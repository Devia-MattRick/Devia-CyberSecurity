import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ThreatEventSchema,
  RiskAssessmentReportSchema,
  ThreatSourceTypeSchema,
  RiskLevelSchema
} from "./cyber-risk-assessment.schema.js";

describe("CyberRiskAssessmentSchema Contract Test", () => {
  it("valida un evento de amenaza válido según NIST SP 800-30", () => {
    const validEvent = {
      id: "RISK-001",
      title: "Exfiltración de credenciales mediante ataque DCSync",
      description: "Un atacante con derechos DS-Replication-Get-Changes solicita la replicación del hash de krbtgt.",
      threatSource: "ADVERSARIAL",
      threatActorOrCapability: "APT con persistencia en red interna",
      vulnerabilityOrPredisposingCondition: "Delegación excesiva de permisos de replicación sobre la raíz de AD",
      cwe: ["CWE-269", "CWE-285"],
      mitreTechniques: ["T1003.006"],
      likelihoodLevel: 4,
      impactLevel: 5,
      qualitativeLikelihood: "HIGH",
      qualitativeImpact: "VERY_HIGH",
      riskLevel: "VERY_HIGH",
      riskScore: 90.0,
      mitigationControls: [
        "Revocar permisos de replicación a cuentas no controladoras de dominio",
        "Habilitar auditoría de eventos de acceso a objetos (Event ID 4662)"
      ],
      status: "OPEN"
    };

    const parsed = ThreatEventSchema.safeParse(validEvent);
    assert.equal(parsed.success, true);
  });

  it("valida un reporte completo de evaluación de riesgos NIST SP 800-30", () => {
    const validReport = {
      assessmentId: "550e8400-e29b-41d4-a716-446655440000",
      name: "Evaluación de Riesgo de Infraestructura Crítica Q4",
      scope: "Controladores de dominio e infraestructura de autenticación híbrida",
      tier: 3,
      conductedAt: "2026-10-29T12:00:00Z",
      conductedBy: "Devia-CyberSecurity Lead Threat Modeler",
      threatEvents: [
        {
          id: "EVT-001",
          title: "SSRF hacia AWS IMDSv1",
          description: "Endpoint vulnerable a SSRF permite robar tokens de rol IAM temporales.",
          threatSource: "ADVERSARIAL",
          vulnerabilityOrPredisposingCondition: "Falta de requerimiento de tokens IMDSv2 en instancias EC2",
          likelihoodLevel: 3,
          impactLevel: 4,
          qualitativeLikelihood: "MODERATE",
          qualitativeImpact: "HIGH",
          riskLevel: "HIGH",
          riskScore: 65.0,
          mitigationControls: ["Configurar HttpTokens=required en metadatos"],
          status: "MITIGATING"
        }
      ],
      metrics: {
        totalEvents: 1,
        veryHighCount: 0,
        highCount: 1,
        moderateCount: 0,
        lowCount: 0,
        veryLowCount: 0,
        averageRiskScore: 65.0
      },
      topRisks: ["EVT-001"]
    };

    const parsed = RiskAssessmentReportSchema.safeParse(validReport);
    assert.equal(parsed.success, true);
  });

  it("rechaza fuentes de amenaza inválidas", () => {
    const invalidSource = ThreatSourceTypeSchema.safeParse("UNKNOWN_SOURCE");
    assert.equal(invalidSource.success, false);
  });

  it("rechaza niveles de riesgo fuera del enum canónico", () => {
    const invalidLevel = RiskLevelSchema.safeParse("CRITICAL");
    assert.equal(invalidLevel.success, false);
  });
});
