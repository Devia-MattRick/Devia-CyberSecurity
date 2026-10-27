import test from "node:test";
import assert from "node:assert/strict";
import { AbsorptionPlanSchema } from "./absorption-plan.schema.js";

test("AbsorptionPlanSchema validates a valid plan correctly", () => {
  const samplePlan = {
    planId: "750d9463-961c-4996-b165-1ac1b10896bd",
    createdAt: "2026-10-27T06:24:46Z",
    target: {
      path: "/sample/repo",
      canonicalPath: "K:/sample/repo",
      name: "sample-repo",
      type: "REPOSITORY",
      archetypeDescription: "POLYGLOT_SOURCE_REPOSITORY"
    },
    scopeSummary: {
      totalEntriesScanned: 42,
      primaryLanguages: [".ts", ".py"],
      securityDimensionsEvaluated: [
        "THREAT_MODELING_ATTACK_SURFACE",
        "SOURCE_CODE_SAST",
        "SECRETS_CRYPTOGRAPHY",
        "IDENTITY_ACCESS_SESSION",
        "SUPPLY_CHAIN_SCA",
        "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
        "CONFIGURATION_HARDENING",
        "RESILIENCE_LOGGING_TELEMETRY"
      ]
    },
    extractedKnowledge: [
      {
        id: "KNOW-001",
        title: "Taint Analysis y Sanitización",
        description: "Validación de flujos de taint desde entradas no confiables hasta sumideros de ejecución.",
        dimension: "SOURCE_CODE_SAST",
        sourceLocations: ["src/index.ts"],
        authority: "OBSERVED",
        valueProposition: "Detección estática de inyecciones y caminos vulnerables."
      }
    ],
    absorptionActions: [
      {
        id: "ABS-001",
        knowledgeId: "KNOW-001",
        title: "Guía de referencia de SAST",
        destination: "SKILL_REFERENCE",
        intent: "UPDATE_ENHANCE",
        existingVulnerabilityId: "VULN-SAST-001",
        targetPathInRepo: ".agent/skills/security-reverse-engineering/references/security-dimensions-mapping.md",
        architecturalRationale: "Capa 1: Referencias metodológicas para análisis estático.",
        priority: "MEDIUM",
        implementationSteps: ["Actualizar catálogo de sinks y flujos de taint."]
      }
    ],
    metrics: {
      totalKnowledgeItems: 1,
      destinationsBreakdown: {
        NEW_SKILL: 0,
        SKILL_REFERENCE: 1,
        PYTHON_SCRIPT: 0,
        ZOD_SCHEMA: 0,
        MCP_TOOL_OR_ENGINE: 0,
        UPDATE_EXISTING: 0
      }
    }
  };

  const parsed = AbsorptionPlanSchema.safeParse(samplePlan);
  assert.equal(parsed.success, true);
});

test("AbsorptionPlanSchema validates audits/h4cker-master/absorption-plan.json", async (t) => {
  const fs = await import("node:fs/promises");
  const { existsSync } = await import("node:fs");
  const path = await import("node:path");
  const planPath = path.resolve(process.cwd(), "audits/h4cker-master/absorption-plan.json");
  if (!existsSync(planPath)) {
    t.skip("Audit file not present on disk");
    return;
  }
  const raw = await fs.readFile(planPath, "utf-8");
  const planData = JSON.parse(raw);
  const parsed = AbsorptionPlanSchema.safeParse(planData);
  if (!parsed.success) {
    console.error("Validation error:", parsed.error);
  }
  assert.equal(parsed.success, true);
});

test("AbsorptionPlanSchema validates audits/web-check-master/absorption-plan.json", async (t) => {
  const fs = await import("node:fs/promises");
  const { existsSync } = await import("node:fs");
  const path = await import("node:path");
  const planPath = path.resolve(process.cwd(), "audits/web-check-master/absorption-plan.json");
  if (!existsSync(planPath)) {
    t.skip("Audit file not present on disk");
    return;
  }
  const raw = await fs.readFile(planPath, "utf-8");
  const planData = JSON.parse(raw);
  const parsed = AbsorptionPlanSchema.safeParse(planData);
  if (!parsed.success) {
    console.error("Validation error:", parsed.error);
  }
  assert.equal(parsed.success, true);
});

test("AbsorptionPlanSchema validates audits/CheatSheetSeries-master/absorption-plan.json", async (t) => {
  const fs = await import("node:fs/promises");
  const { existsSync } = await import("node:fs");
  const path = await import("node:path");
  const planPath = path.resolve(process.cwd(), "audits/CheatSheetSeries-master/absorption-plan.json");
  if (!existsSync(planPath)) {
    t.skip("Audit file not present on disk");
    return;
  }
  const raw = await fs.readFile(planPath, "utf-8");
  const planData = JSON.parse(raw);
  const parsed = AbsorptionPlanSchema.safeParse(planData);
  if (!parsed.success) {
    console.error("Validation error:", parsed.error);
  }
  assert.equal(parsed.success, true);
});

test("AbsorptionPlanSchema validates audits/security-extras-skills/absorption-plan.json", async (t) => {
  const fs = await import("node:fs/promises");
  const { existsSync } = await import("node:fs");
  const path = await import("node:path");
  const planPath = path.resolve(process.cwd(), "audits/security-extras-skills/absorption-plan.json");
  if (!existsSync(planPath)) {
    t.skip("Audit file not present on disk");
    return;
  }
  const raw = await fs.readFile(planPath, "utf-8");
  const planData = JSON.parse(raw);
  const parsed = AbsorptionPlanSchema.safeParse(planData);
  if (!parsed.success) {
    console.error("Validation error:", parsed.error);
  }
  assert.equal(parsed.success, true);
});



