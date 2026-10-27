import test from "node:test";
import assert from "node:assert/strict";
import {
  CryptographicInventoryEntrySchema,
  CryptographicInventoryReportSchema
} from "./cryptographic-inventory.schema.js";


test("CryptographicInventoryEntrySchema validates classical vulnerable entries", () => {
  const entry = {
    id: "CRYPTO-001",
    purpose: "Intercambio de claves en canal TLS legado",
    usage: "KEY_EXCHANGE",
    category: "ASYMMETRIC_KEY_EXCHANGE",
    algorithm: "RSA-2048",
    keyLengthBits: 2048,
    quantumStatus: "VULNERABLE_CLASSICAL",
    migrationPriority: "CRITICAL_LONG_TERM_CONFIDENTIALITY",
    standard: "PKCS#1 v1.5",
    sourceLocations: ["src/tls/transport.ts"],
    dependencies: ["node:tls"],
    owner: "Core Platform Team"
  };

  const parsed = CryptographicInventoryEntrySchema.safeParse(entry);
  assert.equal(parsed.success, true);
});

test("CryptographicInventoryEntrySchema validates standardized PQC entries", () => {
  const entry = {
    id: "CRYPTO-002",
    purpose: "Encapsulación de clave post-cuántica para almacenamiento",
    usage: "KEY_EXCHANGE",
    category: "HYBRID_CLASSICAL_PQC",
    algorithm: "X25519MLKEM768",
    quantumStatus: "TRANSITIONAL_HYBRID",
    migrationPriority: "MEDIUM_SCHEDULED",
    standard: "RFC 10024 / FIPS 203",
    sourceLocations: ["src/crypto/hybrid_kem.ts"]
  };

  const parsed = CryptographicInventoryEntrySchema.safeParse(entry);
  assert.equal(parsed.success, true);
});

test("CryptographicInventoryReportSchema validates complete report snapshot", () => {
  const report = {
    reportId: "1e5db3a8-4228-48b2-b4c6-43ad88f17bc1",
    scannedAt: "2026-10-27T18:00:00Z",
    target: "K:/sample/service",
    metrics: {
      totalPrimitives: 3,
      vulnerableClassicalCount: 2,
      transitionalHybridCount: 1,
      quantumSafeCount: 0,
      adequateSymmetricCount: 0
    },
    entries: [
      {
        id: "CRYPTO-001",
        purpose: "Firma de tokens JWT",
        usage: "DIGITAL_SIGNATURE",
        category: "ASYMMETRIC_SIGNATURE",
        algorithm: "ECDSA-P256",
        quantumStatus: "VULNERABLE_CLASSICAL",
        migrationPriority: "HIGH_LONG_TERM_TRUST",
        sourceLocations: ["auth/jwt.ts"]
      },
      {
        id: "CRYPTO-002",
        purpose: "Canal TLS",
        usage: "TRANSPORT_TLS",
        category: "HYBRID_CLASSICAL_PQC",
        algorithm: "X25519MLKEM768",
        quantumStatus: "TRANSITIONAL_HYBRID",
        migrationPriority: "MEDIUM_SCHEDULED",
        sourceLocations: ["network/client.ts"]
      },
      {
        id: "CRYPTO-003",
        purpose: "Intercambio DH",
        usage: "KEY_EXCHANGE",
        category: "ASYMMETRIC_KEY_EXCHANGE",
        algorithm: "Diffie-Hellman-2048",
        quantumStatus: "VULNERABLE_CLASSICAL",
        migrationPriority: "CRITICAL_LONG_TERM_CONFIDENTIALITY",
        sourceLocations: ["vpn/session.ts"]
      }
    ]
  };

  const parsed = CryptographicInventoryReportSchema.safeParse(report);
  assert.equal(parsed.success, true);
});
