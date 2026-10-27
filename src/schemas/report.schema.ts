import { z } from "zod";
import { SecurityFindingSchema, SecurityDimensionSchema } from "./finding.schema.js";

export const AuditScopeSchema = z.object({
  targetRepository: z.string(),
  commitHash: z.string().optional(),
  scannedPaths: z.array(z.string()),
  excludedPaths: z.array(z.string()).default([]),
  dimensionsAudited: z.array(SecurityDimensionSchema)
});

export const AuditMetricsSchema = z.object({
  totalFilesScanned: z.number().int().nonnegative(),
  findingsCount: z.object({
    critical: z.number().int().nonnegative(),
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    informational: z.number().int().nonnegative()
  }),
  durationSeconds: z.number().nonnegative()
});

export const AuditReportSchema = z.object({
  id: z.string().uuid(),
  title: z.string(),
  auditDate: z.string().datetime(),
  engineVersion: z.string(),
  scope: AuditScopeSchema,
  executiveSummary: z.object({
    riskScore: z.number().min(0).max(100).describe("0 = Seguro / Postura Impecable, 100 = Crítico"),
    keyRisks: z.array(z.string()),
    postureOverview: z.string()
  }),
  metrics: AuditMetricsSchema,
  findings: z.array(SecurityFindingSchema),
  recommendationsRoadmap: z.array(z.object({
    phase: z.enum(["IMMEDIATE_HOTFIX", "SHORT_TERM", "ARCHITECTURAL_LONG_TERM"]),
    action: z.string(),
    associatedFindingIds: z.array(z.string())
  }))
});

export type AuditReport = z.infer<typeof AuditReportSchema>;
