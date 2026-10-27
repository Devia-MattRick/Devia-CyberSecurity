import { z } from "zod";

/**
 * Tipos de reglas de alcance admitidas por el evaluador de guardrails.
 */
export const ScopeRuleKindSchema = z.enum([
  "auto",
  "cidr",
  "domain-glob",
  "host",
  "ip"
]);

export type ScopeRuleKind = z.infer<typeof ScopeRuleKindSchema>;

/**
 * Regla individual de alcance (in-scope o out-of-scope).
 */
export const ScopeRuleSchema = z.object({
  pattern: z.string().min(1).describe("Patrón literal, CIDR, hostname o glob de dominio"),
  kind: ScopeRuleKindSchema.default("auto")
});

export type ScopeRule = z.infer<typeof ScopeRuleSchema>;

/**
 * Ventana temporal autorizada o de blackout para pruebas.
 */
export const TimeWindowSchema = z.object({
  start: z.string().datetime().describe("Inicio de la ventana en formato ISO 8601 UTC"),
  end: z.string().datetime().describe("Fin de la ventana en formato ISO 8601 UTC")
});

export type TimeWindow = z.infer<typeof TimeWindowSchema>;

/**
 * Contrato de cumplimiento automático de Reglas de Compromiso (MachineEnforcement).
 * Rige tanto el guardrail advisory del parser como la compilación a nftables/DNS.
 */
export const MachineEnforcementSchema = z.object({
  configured: z.boolean().default(true),
  in_scope: z.array(ScopeRuleSchema).default([]),
  out_of_scope: z.array(ScopeRuleSchema).default([]),
  forbidden_destinations: z.array(z.string()).default([
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200"
  ]),
  forbidden_command_patterns: z.array(z.string()).default([]),
  allow_cloud_metadata: z.boolean().default(false),
  allow_sensitive_tlds: z.boolean().default(false),
  max_concurrent_connections: z.number().int().positive().optional(),
  min_inter_request_delay_ms: z.number().int().nonnegative().default(0),
  authorized_windows: z.array(TimeWindowSchema).default([]),
  blackout_windows: z.array(TimeWindowSchema).default([])
});

export type MachineEnforcement = z.infer<typeof MachineEnforcementSchema>;

/**
 * Veredicto determinista de evaluación de objetivo o comando contra las RoE.
 */
export const DecisionSchema = z.object({
  allow: z.boolean(),
  reason_code: z.string().min(1),
  reason_detail: z.string().min(1),
  risk: z.enum(["low", "medium", "high", "critical"]).default("low"),
  matched_targets: z.array(z.string()).default([])
});

export type Decision = z.infer<typeof DecisionSchema>;

/**
 * Registro individual del ledger append-only con encadenamiento criptográfico HMAC.
 */
export const AuditChainRecordSchema = z.object({
  seq: z.number().int().nonnegative().describe("Contador monótono secuencial por sesión"),
  ts: z.string().datetime().describe("Marca de tiempo UTC"),
  prev_hash: z.string().regex(/^[0-9a-f]{64}$/, "Debe ser un digest SHA-256 hexadecimal de 64 caracteres"),
  hash: z.string().regex(/^[0-9a-f]{64}$/, "Debe ser el hash SHA-256 canónico del registro + prev_hash"),
  hmac: z.string().regex(/^([0-9a-f]{64})?$/, "HMAC-SHA256 opcional vinculado a la clave del operador"),
  tool: z.string().min(1).describe("Nombre normalizado de la herramienta invocada"),
  command: z.string().optional().describe("Comando o argumento evaluado"),
  decision: DecisionSchema
});

export type AuditChainRecord = z.infer<typeof AuditChainRecordSchema>;
