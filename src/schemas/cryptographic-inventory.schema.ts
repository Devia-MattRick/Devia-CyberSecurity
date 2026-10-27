import { z } from "zod";

/**
 * Ámbitos de uso de criptografía en aplicaciones y sistemas.
 */
export const CryptographicUsageSchema = z.enum([
  "TRANSPORT_TLS",
  "DATA_AT_REST",
  "KEY_EXCHANGE",
  "DIGITAL_SIGNATURE",
  "AUTHENTICATION_TOKEN",
  "PASSWORD_HASHING",
  "MESSAGE_INTEGRITY"
]);

export type CryptographicUsage = z.infer<typeof CryptographicUsageSchema>;

/**
 * Categorías de primitivas y algoritmos criptográficos.
 */
export const CryptographicCategorySchema = z.enum([
  "SYMMETRIC_CIPHER",
  "ASYMMETRIC_KEY_EXCHANGE",
  "ASYMMETRIC_SIGNATURE",
  "HASH_FUNCTION",
  "KEY_DERIVATION_FUNCTION",
  "HYBRID_CLASSICAL_PQC"
]);

export type CryptographicCategory = z.infer<typeof CryptographicCategorySchema>;

/**
 * Estado de vulnerabilidad frente a computación cuántica (Algoritmo de Shor / Grover).
 */
export const QuantumVulnerabilityStatusSchema = z.enum([
  "VULNERABLE_CLASSICAL",       // Vulnerable a Shor (RSA, DH, ECDH, ECDSA, Ed25519)
  "TRANSITIONAL_HYBRID",       // Híbrido clásico + PQC (e.g. X25519MLKEM768)
  "QUANTUM_SAFE_STANDARDIZED", // PQC estandarizado por NIST (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205)
  "ADEQUATE_SYMMETRIC"         // Simétrico con margen seguro (AES-256, SHA-384, SHA-512)
]);

export type QuantumVulnerabilityStatus = z.infer<typeof QuantumVulnerabilityStatusSchema>;

/**
 * Prioridad de migración basada en la longevidad del activo (confidencialidad vs firma).
 */
export const PqcMigrationPrioritySchema = z.enum([
  "CRITICAL_LONG_TERM_CONFIDENTIALITY", // Exposición HNDL en datos o transporte
  "HIGH_LONG_TERM_TRUST",               // Firmas de código, certificados o firmware
  "MEDIUM_SCHEDULED",                   // Dependencias gestionadas por proveedor
  "LOW_SHORT_LIVED"                     // Tokens efímeros o sesiones de muy corta duración
]);

export type PqcMigrationPriority = z.infer<typeof PqcMigrationPrioritySchema>;

/**
 * Entrada autoritativa del inventario criptográfico (Etapa 1 PQC).
 */
export const CryptographicInventoryEntrySchema = z.object({
  id: z.string().regex(/^CRYPTO-\d+$/, "El ID debe cumplir con el formato CRYPTO-XXX"),
  purpose: z.string().min(5),
  usage: CryptographicUsageSchema,
  category: CryptographicCategorySchema,
  algorithm: z.string().min(2),
  keyLengthBits: z.number().int().positive().optional(),
  quantumStatus: QuantumVulnerabilityStatusSchema,
  migrationPriority: PqcMigrationPrioritySchema,
  standard: z.string().optional(),
  sourceLocations: z.array(z.string()).min(1),
  dependencies: z.array(z.string()).optional(),
  owner: z.string().optional()
});

export type CryptographicInventoryEntry = z.infer<typeof CryptographicInventoryEntrySchema>;

/**
 * Reporte consolidado de inventario criptográfico y madurez PQC.
 */
export const CryptographicInventoryReportSchema = z.object({
  reportId: z.string().uuid(),
  scannedAt: z.string().datetime(),
  target: z.string().min(1),
  metrics: z.object({
    totalPrimitives: z.number().int().nonnegative(),
    vulnerableClassicalCount: z.number().int().nonnegative(),
    transitionalHybridCount: z.number().int().nonnegative(),
    quantumSafeCount: z.number().int().nonnegative(),
    adequateSymmetricCount: z.number().int().nonnegative()
  }),
  entries: z.array(CryptographicInventoryEntrySchema)
});

export type CryptographicInventoryReport = z.infer<typeof CryptographicInventoryReportSchema>;
