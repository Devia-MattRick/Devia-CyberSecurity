import { z } from "zod";
import { SecurityDimensionSchema } from "./finding.schema.js";

/**
 * Vocabulario canónico de fases de artefactos en pipelines de reconciliación.
 */
export const ArtifactKindSchema = z.enum([
  "producer-observations",
  "supplemental-observations",
  "task-formation",
  "fixed-tasks"
]);

export type ArtifactKind = z.infer<typeof ArtifactKindSchema>;

/**
 * Entrada en el linaje criptográfico de un artefacto: registra el tipo de artefacto
 * y el hash SHA-256 exacto del insumo previo.
 */
export const ArtifactInputDigestSchema = z.object({
  artifactKind: ArtifactKindSchema,
  sha256: z.string().regex(/^[a-f0-9]{64}$/i, "El hash SHA-256 debe tener 64 caracteres hexadecimales")
});

export type ArtifactInputDigest = z.infer<typeof ArtifactInputDigestSchema>;

/**
 * Referencia inmutable y sellada de un artefacto en el linaje de auditoría.
 */
export const ArtifactRefSchema = z.object({
  path: z.string().min(1),
  artifactKind: ArtifactKindSchema,
  vulnerabilityClass: z.string().min(1),
  schemaVersion: z.literal(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/i, "El hash SHA-256 debe tener 64 caracteres hexadecimales"),
  inputs: z.array(ArtifactInputDigestSchema),
  counts: z.record(z.string(), z.number().int().nonnegative())
});

export type ArtifactRef = z.infer<typeof ArtifactRefSchema>;

/**
 * Ubicación de código fuente autoritativa extraída del análisis estático (SAST).
 */
export const SastSourceLocationSchema = z.object({
  file: z.string().min(1),
  line: z.number().int().positive(),
  column: z.number().int().positive(),
  ruleId: z.string().min(1)
});

export type SastSourceLocation = z.infer<typeof SastSourceLocationSchema>;

/**
 * Origen de la observación dentro del flujo híbrido de auditoría.
 */
export const ScanSourceSchema = z.enum([
  "sast",
  "vulnerability_analysis",
  "audit_agent",
  "manual"
]);

export type ScanSource = z.infer<typeof ScanSourceSchema>;

/**
 * Prioridad operativa asignada al hallazgo.
 */
export const PrioritySchema = z.enum(["P1", "P2", "P3"]);

export type Priority = z.infer<typeof PrioritySchema>;

/**
 * Observación previa a la formación de tareas de explotación o reporte final.
 */
export const ReconciliationObservationSchema = z.object({
  producerId: z.string().min(1),
  scanSource: ScanSourceSchema,
  primaryPreference: z.enum(["default", "preferred"]),
  priority: PrioritySchema,
  title: z.string().min(1),
  dimension: SecurityDimensionSchema,
  cwe: z.string().regex(/^CWE-\d+$/).optional(),
  sastSourceLocation: SastSourceLocationSchema.optional(),
  dynamicEvidence: z.record(z.string(), z.unknown()).optional()
});

export type ReconciliationObservation = z.infer<typeof ReconciliationObservationSchema>;

/**
 * Tarea o hallazgo reconciliado y consolidado.
 * Tras la deduplicación, primaryPreference se descarta y las observaciones secundarias
 * se anexan en mergedObservations.
 */
export const ReconciliationTaskSchema = z.object({
  taskId: z.string().min(1),
  producerId: z.string().min(1),
  scanSource: ScanSourceSchema,
  priority: PrioritySchema,
  title: z.string().min(1),
  dimension: SecurityDimensionSchema,
  cwe: z.string().regex(/^CWE-\d+$/).optional(),
  sastSourceLocation: SastSourceLocationSchema.optional(),
  dynamicEvidence: z.record(z.string(), z.unknown()).optional(),
  mergedObservations: z.array(
    ReconciliationObservationSchema.omit({ primaryPreference: true })
  ).optional()
});

export type ReconciliationTask = z.infer<typeof ReconciliationTaskSchema>;
