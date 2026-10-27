import { z } from "zod";

/**
 * Modos de destino soportados para snapshots deterministas de objetivos de auditoría.
 */
export const SnapshotKindSchema = z.enum([
  "git_revision",
  "git_worktree",
  "git_diff",
  "directory_snapshot"
]);

export type SnapshotKind = z.infer<typeof SnapshotKindSchema>;

/**
 * Estados terminales posibles para una auditoría sellada.
 */
export const ScanStatusSchema = z.enum([
  "completed",
  "failed",
  "canceled",
  "interrupted"
]);

export type ScanStatus = z.infer<typeof ScanStatusSchema>;

/**
 * Recibo criptográfico de artefacto sellado en el paquete de auditoría.
 */
export const ArtifactReceiptSchema = z.object({
  path: z.string().describe("Ruta relativa del archivo dentro del bundle de auditoría"),
  sha256: z.string().regex(/^[a-f0-9]{64}$/, "Debe ser un digest SHA-256 hexadecimal de 64 caracteres"),
  mediaType: z.string().default("application/json")
});

export type ArtifactReceipt = z.infer<typeof ArtifactReceiptSchema>;

/**
 * Definición del objetivo y su snapshot determinista.
 */
export const TargetSnapshotSchema = z.object({
  kind: SnapshotKindSchema,
  targetId: z.string().describe("Identificador estable del repositorio o espacio de trabajo"),
  displayName: z.string().optional(),
  remote: z.string().url().optional(),
  revision: z.string().optional().describe("Commit hash de Git si aplica"),
  snapshotDigest: z.string().describe("Digest determinista con prefijo de algoritmo (e.g. devia-snapshot/v1:sha256:...)"),
  baseRevision: z.string().optional(),
  headRevision: z.string().optional()
});

export type TargetSnapshot = z.infer<typeof TargetSnapshotSchema>;

/**
 * Alcance autorizado de inspección.
 */
export const ScanScopeSchema = z.object({
  includePaths: z.array(z.string()).min(1).default(["."]),
  excludePaths: z.array(z.string()).default([])
});

export type ScanScope = z.infer<typeof ScanScopeSchema>;

/**
 * Manifiesto canónico terminal de auditoría sellada (Sealed Scan Manifest).
 * Constituye la Fuente Única de Verdad inmutable y a prueba de manipulaciones.
 */
export const SealedScanManifestSchema = z.object({
  documentType: z.literal("devia.scan-manifest"),
  schemaVersion: z.literal("1.0"),
  scan: z.object({
    id: z.string().min(1).describe("ID único de la sesión de escaneo"),
    producer: z.object({
      name: z.string().default("devia-cybersecurity"),
      version: z.string()
    }),
    status: ScanStatusSchema,
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime(),
    sealedAt: z.string().datetime(),
    target: TargetSnapshotSchema,
    scope: ScanScopeSchema,
    findingsRef: z.string().default("findings.json"),
    coverageRef: z.string().default("coverage.json"),
    artifacts: z.array(ArtifactReceiptSchema).min(2).describe("Recibos SHA-256 obligatorios para findings.json y coverage.json")
  })
});

export type SealedScanManifest = z.infer<typeof SealedScanManifestSchema>;

/**
 * Superficie individual de cobertura de auditoría.
 */
export const CoverageSurfaceSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  disposition: z.enum(["reported", "rejected", "deferred", "excluded"]),
  receiptRefs: z.array(z.string()).default([])
});

export type CoverageSurface = z.infer<typeof CoverageSurfaceSchema>;

/**
 * Resumen canónico de cobertura de auditoría.
 */
export const CoverageSummarySchema = z.object({
  documentType: z.literal("devia.coverage"),
  schemaVersion: z.literal("1.0"),
  scanId: z.string().min(1),
  mode: z.enum(["repository", "scoped_path"]),
  completeness: z.enum(["complete", "partial"]),
  inventoryStrategy: z.enum(["repository", "directory"]),
  includePaths: z.array(z.string()),
  excludePaths: z.array(z.string()),
  surfaces: z.array(CoverageSurfaceSchema),
  explicitExclusions: z.array(z.string()).default([]),
  deferred: z.array(z.object({
    id: z.string(),
    reason: z.string()
  })).default([])
});

export type CoverageSummary = z.infer<typeof CoverageSummarySchema>;
