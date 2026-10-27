import { z } from "zod";
import { SecurityDimensionSchema } from "./finding.schema.js";

/**
 * Destinos canónicos hacia donde se puede absorber conocimiento o utilidades
 * dentro del stack híbrido Tri-Tier de Devia-CyberSecurity.
 */
export const AbsorptionDestinationSchema = z.enum([
  "NEW_SKILL",            // Capa 1: Nueva Skill autónoma en .agent/skills/<name>/SKILL.md
  "SKILL_REFERENCE",     // Capa 1: Documento de referencia en .agent/skills/<skill>/references/
  "PYTHON_SCRIPT",       // Capa 3: Utilidad determinista en src/scripts/ (o dentro de una skill)
  "ZOD_SCHEMA",          // Capa 2: Esquema autoritativo en src/schemas/ y tipos en src/types/
  "MCP_TOOL_OR_ENGINE",  // Capa 2: Runner, CLI o herramienta MCP en src/engine/
  "UPDATE_EXISTING"      // Refactor/mejora in-place sobre componente existente
]);

export type AbsorptionDestination = z.infer<typeof AbsorptionDestinationSchema>;

export const TargetTypeSchema = z.enum([
  "REPOSITORY",
  "SKILL",
  "PLUGIN",
  "STANDALONE_FOLDER",
  "BINARY_PACKAGE",
  "SPECIFICATION"
]);

export type TargetType = z.infer<typeof TargetTypeSchema>;

export const EpistemicTierSchema = z.enum([
  "OBSERVED",  // Verificado mediante lectura estricta de código, manifest o ejecución controlada
  "DERIVED",   // Deducido rigurosamente mediante análisis formal de relaciones o tipos
  "INFERRED",  // Hipótesis basada en patrones o heurísticas de diseño
  "UNKNOWN"    // Asunción pendiente de evidencia concluyente
]);

export type EpistemicTier = z.infer<typeof EpistemicTierSchema>;

/**
 * Intención evolutiva de la acción de absorción.
 * Permite evaluar si se debe crear, absorber, actualizar, robustecer, refinar o corregir
 * componentes o vulnerabilidades ya existentes en el repositorio.
 */
export const EvolutionaryIntentSchema = z.enum([
  "CREATE_NEW",        // Crear un nuevo componente o regla desde cero
  "ABSORB_EXPAND",     // Absorber y expandir metodología dentro de un contenedor existente
  "UPDATE_ENHANCE",    // Actualizar / mejorar componente con técnicas más avanzadas
  "ROBUSTIFY_HARDEN",  // Robustecer heurística, filtro de falsos positivos o mitigación existente
  "REFINE_OPTIMIZE",   // Refinar rendimiento, precisión o tipado
  "CORRECT_FIX"        // Corregir discrepancia, falso positivo o regla desactualizada
]);

export type EvolutionaryIntent = z.infer<typeof EvolutionaryIntentSchema>;

/**
 * Unidad de conocimiento, técnica, metodología o heurística extraída del objetivo.
 */
export const ExtractedKnowledgeItemSchema = z.object({
  id: z.string().regex(/^KNOW-\d+$/, "El ID debe cumplir con el formato KNOW-XXX"),
  title: z.string().min(5).max(200),
  description: z.string().min(10),
  dimension: SecurityDimensionSchema,
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).optional(),
  owasp: z.array(z.string()).optional(),
  sourceLocations: z.array(z.string()).min(1).describe("Rutas o referencias dentro del objetivo auditado"),
  authority: EpistemicTierSchema,
  valueProposition: z.string().describe("Utilidad concreta y solución que aporta a Devia-CyberSecurity")
});

export type ExtractedKnowledgeItem = z.infer<typeof ExtractedKnowledgeItemSchema>;

/**
 * Propuesta concreta de adopción y absorción hacia el repositorio.
 */
export const AbsorptionActionSchema = z.object({
  id: z.string().regex(/^ABS-\d+$/, "El ID debe cumplir con el formato ABS-XXX"),
  knowledgeId: z.string().describe("ID del conocimiento extraído asociado (KNOW-XXX)"),
  title: z.string().min(5).max(200),
  destination: AbsorptionDestinationSchema,
  intent: EvolutionaryIntentSchema.describe("Propósito evolutivo de la acción (crear, absorber, actualizar, robustecer, refinar, corregir)"),
  existingVulnerabilityId: z.string().optional().describe("ID de la vulnerabilidad en docs/VULNERABILITIES.md si aplica (e.g. VULN-SAST-001)"),
  targetPathInRepo: z.string().describe("Ruta exacta en Devia-CyberSecurity donde se materializará el componente"),
  architecturalRationale: z.string().describe("Justificación técnica de la selección de capa en el modelo Tri-Tier"),
  priority: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  implementationSteps: z.array(z.string()).min(1).describe("Pasos detallados de implementación y prueba")
});

export type AbsorptionAction = z.infer<typeof AbsorptionActionSchema>;

/**
 * Esquema Autoritativo del Plan de Absorción de Ingeniería Inversa Forense.
 * Modela el proceso determinista de ingesta de conocimiento externo en Devia-CyberSecurity.
 */
export const AbsorptionPlanSchema = z.object({
  planId: z.string().uuid(),
  createdAt: z.string().datetime(),
  target: z.object({
    path: z.string(),
    canonicalPath: z.string(),
    name: z.string(),
    type: TargetTypeSchema,
    commitOrSnapshot: z.string().optional(),
    archetypeDescription: z.string()
  }),
  scopeSummary: z.object({
    totalEntriesScanned: z.number().int().nonnegative(),
    primaryLanguages: z.array(z.string()),
    securityDimensionsEvaluated: z.array(SecurityDimensionSchema)
  }),
  extractedKnowledge: z.array(ExtractedKnowledgeItemSchema),
  absorptionActions: z.array(AbsorptionActionSchema),
  metrics: z.object({
    totalKnowledgeItems: z.number().int().nonnegative(),
    destinationsBreakdown: z.record(z.string(), z.number().int().nonnegative())
  }),
  ledgerPaths: z.object({
    inventoryJsonl: z.string(),
    coverageJsonl: z.string(),
    evidenceJsonl: z.string(),
    unknownsJsonl: z.string()
  }).optional()
});

export type AbsorptionPlan = z.infer<typeof AbsorptionPlanSchema>;
