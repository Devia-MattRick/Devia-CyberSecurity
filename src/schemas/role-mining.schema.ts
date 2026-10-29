import { z } from "zod";

/**
 * Esquema para asignación individual de permisos o privilegios de usuario.
 */
export const EntitlementAssignmentSchema = z.object({
  user: z.string().min(1).describe("Identificador único del usuario o principal"),
  system: z.string().min(1).describe("Sistema, servicio o aplicación donde reside el permiso"),
  entitlement: z.string().min(1).describe("Permiso, rol técnico o derecho de acceso asignado"),
  grantedAt: z.string().datetime().optional().describe("Fecha y hora de concesión si está disponible")
});

export type EntitlementAssignment = z.infer<typeof EntitlementAssignmentSchema>;

/**
 * Esquema de rol minado y consolidado mediante algoritmos bottom-up o clustering de Jaccard.
 */
export const MinedRoleSchema = z.object({
  roleId: z.string().regex(/^ROLE-\d{3,}$/).describe("Identificador normalizado del rol sintético (ROLE-XXX)"),
  name: z.string().min(3).max(150).describe("Nombre descriptivo o sugerido para el rol de negocio"),
  permissions: z.array(z.string().min(1)).min(1).describe("Lista canónica de permisos ('sistema:permiso') que componen el rol"),
  assignedUsers: z.array(z.string().min(1)).min(1).describe("Usuarios que comparten este patrón de acceso"),
  userCount: z.number().int().positive().describe("Total de usuarios asignables a este rol"),
  algorithm: z.enum(["BOTTOM_UP_EXACT", "TOP_DOWN_JACCARD"]).describe("Método algorítmico utilizado para descubrir el rol"),
  jaccardSimilarity: z.number().min(0).max(1).optional().describe("Puntaje de similitud de Jaccard si fue generado por clustering")
});

export type MinedRole = z.infer<typeof MinedRoleSchema>;

/**
 * Métricas cuantitativas de optimización de RBAC y erradicación de Role Explosion.
 */
export const RoleMiningMetricsSchema = z.object({
  totalUsers: z.number().int().nonnegative().describe("Total de usuarios evaluados en el conjunto de datos"),
  totalUniquePermissions: z.number().int().nonnegative().describe("Total de permisos únicos catalogados"),
  totalOriginalAssignments: z.number().int().nonnegative().describe("Total de asignaciones atómicas usuario-entitlement iniciales"),
  minedRolesCount: z.number().int().nonnegative().describe("Cantidad de roles consolidados sugeridos"),
  roleExplosionRatio: z.number().nonnegative().describe("Ratio de conjuntos únicos de permisos por usuario (1.0 = máxima dispersión/explosión)"),
  assignmentReductionPercent: z.number().min(0).max(100).describe("Porcentaje de reducción de asignaciones individuales mediante roles")
});

export type RoleMiningMetrics = z.infer<typeof RoleMiningMetricsSchema>;

/**
 * Contrato Maestro de Auditoría de Minería de Roles y Optimización de RBAC.
 */
export const RoleMiningAnalysisSchema = z.object({
  analysisId: z.string().uuid().describe("UUID identificador del informe de minería"),
  analyzedAt: z.string().datetime().describe("Marca de tiempo UTC de ejecución"),
  targetSystem: z.string().min(1).describe("Sistema de gestión de identidades o repositorio evaluado"),
  minUsersThreshold: z.number().int().positive().default(2).describe("Umbral mínimo de usuarios para justificar la creación de un rol"),
  similarityThreshold: z.number().min(0).max(1).default(0.75).describe("Umbral de similitud de Jaccard para clustering top-down"),
  minedRoles: z.array(MinedRoleSchema).describe("Roles óptimos sugeridos"),
  residualDirectPermissions: z.array(z.object({
    user: z.string(),
    permissions: z.array(z.string())
  })).describe("Permisos únicos que no alcanzaron el umbral de consolidación (requieren justificación de excepción)"),
  metrics: RoleMiningMetricsSchema.describe("Métricas consolidadas de reducción de superficie y menor privilegio")
});

export type RoleMiningAnalysis = z.infer<typeof RoleMiningAnalysisSchema>;
