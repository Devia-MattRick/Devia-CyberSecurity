import { z } from "zod";

/**
 * Fuentes de amenaza según NIST SP 800-30 Rev 1.
 */
export const ThreatSourceTypeSchema = z.enum([
  "ADVERSARIAL",    // Atacantes humanos, APTs, insiders maliciosos, competidores
  "ACCIDENTAL",     // Errores de operadores, configuraciones erróneas, fallas de usuario
  "STRUCTURAL",     // Fallos de hardware, envejecimiento de equipos, bugs de software
  "ENVIRONMENTAL"   // Desastres naturales, cortes de energía, fallas de infraestructura externa
]);

export type ThreatSourceType = z.infer<typeof ThreatSourceTypeSchema>;

/**
 * Niveles discretos cualitativos/semi-cuantitativos de Verosimilitud (Likelihood) 1-5.
 */
export const QualitativeLikelihoodSchema = z.enum([
  "VERY_LOW",   // Nivel 1 (0.0 - 0.19)
  "LOW",        // Nivel 2 (0.2 - 0.39)
  "MODERATE",   // Nivel 3 (0.4 - 0.59)
  "HIGH",       // Nivel 4 (0.6 - 0.79)
  "VERY_HIGH"   // Nivel 5 (0.8 - 1.0)
]);

export type QualitativeLikelihood = z.infer<typeof QualitativeLikelihoodSchema>;

/**
 * Niveles discretos cualitativos/semi-cuantitativos de Impacto (Impact) 1-5.
 */
export const QualitativeImpactSchema = z.enum([
  "VERY_LOW",   // Nivel 1
  "LOW",        // Nivel 2
  "MODERATE",   // Nivel 3
  "HIGH",       // Nivel 4
  "VERY_HIGH"   // Nivel 5
]);

export type QualitativeImpact = z.infer<typeof QualitativeImpactSchema>;

/**
 * Niveles finales de Riesgo según matriz 5x5 NIST SP 800-30 Rev 1.
 */
export const RiskLevelSchema = z.enum([
  "VERY_LOW",
  "LOW",
  "MODERATE",
  "HIGH",
  "VERY_HIGH"
]);

export type RiskLevel = z.infer<typeof RiskLevelSchema>;

/**
 * Definición individual de evento de amenaza evaluado.
 */
export const ThreatEventSchema = z.object({
  id: z.string().regex(/^(EVT|THREAT|RISK)-\d+$/, "El ID debe cumplir con el formato EVT-XXX o RISK-XXX"),
  title: z.string().min(5).max(200),
  description: z.string().min(10),
  threatSource: ThreatSourceTypeSchema,
  threatActorOrCapability: z.string().nullable().optional(),
  vulnerabilityOrPredisposingCondition: z.string().min(5),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).optional(),
  mitreTechniques: z.array(z.string().regex(/^T\d+(\.\d+)?$/)).optional(),
  likelihoodLevel: z.number().int().min(1).max(5),
  impactLevel: z.number().int().min(1).max(5),
  qualitativeLikelihood: QualitativeLikelihoodSchema,
  qualitativeImpact: QualitativeImpactSchema,
  riskLevel: RiskLevelSchema,
  riskScore: z.number().min(0).max(100),
  mitigationControls: z.array(z.string()).default([]),
  residualRiskLevel: RiskLevelSchema.optional(),
  status: z.enum(["OPEN", "MITIGATING", "ACCEPTED", "CLOSED"]).default("OPEN")
});

export type ThreatEvent = z.infer<typeof ThreatEventSchema>;

/**
 * Registro y reporte formal de evaluación de riesgos NIST SP 800-30 Rev 1.
 */
export const RiskAssessmentReportSchema = z.object({
  assessmentId: z.string().uuid(),
  name: z.string().min(3).max(150),
  scope: z.string().min(5),
  tier: z.number().int().min(1).max(3).describe("Tier organizacional: Tier 1 (Estratégico), Tier 2 (Procesos/Misiones), Tier 3 (Sistemas de TI)"),
  conductedAt: z.string().datetime(),
  conductedBy: z.string().min(3),
  threatEvents: z.array(ThreatEventSchema),
  metrics: z.object({
    totalEvents: z.number().int().nonnegative(),
    veryHighCount: z.number().int().nonnegative(),
    highCount: z.number().int().nonnegative(),
    moderateCount: z.number().int().nonnegative(),
    lowCount: z.number().int().nonnegative(),
    veryLowCount: z.number().int().nonnegative(),
    averageRiskScore: z.number().min(0).max(100)
  }),
  topRisks: z.array(z.string()).describe("IDs de los eventos con mayor criticidad priorizados para tratamiento inmediato")
});

export type RiskAssessmentReport = z.infer<typeof RiskAssessmentReportSchema>;
