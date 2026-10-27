import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  MitreTechniqueIdSchema,
  NistCsfFunctionSchema,
  OwaspTop10_2025Schema,
  AttackNavigatorLayerSchema,
  CrossFrameworkMappingEntrySchema
} from "./framework-mapping.schema.js";

test("AttackNavigatorLayerSchema validates the external attack-navigator-layer.json", () => {
  const candidatePaths = [
    path.resolve(process.cwd(), "external-reps/mappings/attack-navigator-layer.json"),
    path.resolve(process.cwd(), "external-reps/Anthropic-Cybersecurity-Skills-main/mappings/attack-navigator-layer.json"),
    path.resolve(process.cwd(), "external-reps/1_READY_SUCESS/mappings/attack-navigator-layer.json")
  ];
  const layerPath = candidatePaths.find(p => fs.existsSync(p));
  assert.ok(layerPath, "No attack-navigator-layer.json file found in candidate paths");
  const rawData = fs.readFileSync(layerPath, "utf-8");
  const parsed = JSON.parse(rawData);

  const result = AttackNavigatorLayerSchema.safeParse(parsed);
  assert.equal(result.success, true, `Validation failed: ${JSON.stringify(result.error?.issues)}`);
  if (result.success) {
    assert.equal(result.data.domain, "enterprise-attack");
    assert.equal(result.data.techniques.length, 218);
  }
});

test("CrossFrameworkMappingEntrySchema validates canonical dimension mapping", () => {
  const entry = {
    dimension: "THREAT_MODELING_ATTACK_SURFACE",
    mitreTactics: ["TA0043", "TA0042", "TA0001", "TA0007"],
    mitreTechniquesSample: ["T1566", "T1190", "T1046"],
    nistCsfFunctions: ["ID", "GV"],
    nistCsfCategories: ["ID.AM", "ID.RA", "GV.RM"],
    owasp2025Categories: ["A04:2025-Insecure Design"],
    cweCatalog: ["CWE-1059", "CWE-1021"],
    defensiveFocus: "Identificación proactiva de superficies de ataque y modelado de amenazas STRIDE."
  };

  const result = CrossFrameworkMappingEntrySchema.safeParse(entry);
  assert.equal(result.success, true);
});

test("MitreTechniqueIdSchema enforces exact technique format", () => {
  assert.equal(MitreTechniqueIdSchema.safeParse("T1059").success, true);
  assert.equal(MitreTechniqueIdSchema.safeParse("T1059.001").success, true);
  assert.equal(MitreTechniqueIdSchema.safeParse("INVALID").success, false);
  assert.equal(NistCsfFunctionSchema.safeParse("PR").success, true);
  assert.equal(OwaspTop10_2025Schema.safeParse("A01:2025-Broken Access Control").success, true);
});

