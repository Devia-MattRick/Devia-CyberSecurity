import test from "node:test";
import assert from "node:assert/strict";
import {
  DangerousFormulaPrefixSchema,
  FormulaInjectionFindingSchema,
  FormulaInjectionAuditReportSchema
} from "./formula-injection.schema.js";

test("FormulaInjectionSchema validates canonical formula prefixes", () => {
  const prefixes = ["=", "+", "-", "@", "\t", "\r", "|", "%"];
  for (const p of prefixes) {
    const res = DangerousFormulaPrefixSchema.safeParse(p);
    assert.equal(res.success, true);
  }
  assert.equal(DangerousFormulaPrefixSchema.safeParse("a").success, false);
});

test("FormulaInjectionFindingSchema validates a vulnerable export finding", () => {
  const finding = {
    id: "FORMULA-EXP-001",
    filePath: "src/services/csv-exporter.ts",
    line: 42,
    format: "CSV",
    verdict: "VULNERABLE_DIRECT_RAW",
    functionOrMethod: "exportLeadsToCsv",
    codeSnippet: 'const row = leads.map(l => `${l.name},${l.company}`).join("\\n");',
    missingPrefixes: ["=", "+", "-", "@", "\t", "\r", "|", "%"],
    bomEnforced: false,
    explanation: "Concatenación cruda de celdas sin neutralizar caracteres que activan comandos DDE o fórmulas en Excel.",
    remediationSnippet: "if (/^[=+\\-@\\t\\r|%]/.test(s)) { s = `'${s}`; }"
  };

  const parsed = FormulaInjectionFindingSchema.safeParse(finding);
  assert.equal(parsed.success, true);
});

test("FormulaInjectionAuditReportSchema validates a full consolidated report", () => {
  const report = {
    targetPath: "K:/DeepSearch_LeadsResearch",
    scannedAt: "2026-10-30T06:30:00Z",
    totalExportFunctionsAnalyzed: 4,
    vulnerableCount: 1,
    findings: [
      {
        id: "FORMULA-EXP-001",
        filePath: "src/services/csv-exporter.ts",
        line: 42,
        format: "CSV",
        verdict: "VULNERABLE_DIRECT_RAW",
        functionOrMethod: "exportLeadsToCsv",
        codeSnippet: 'const row = leads.map(l => `${l.name},${l.company}`).join("\\n");',
        missingPrefixes: ["=", "+", "-", "@", "\t", "\r", "|", "%"],
        bomEnforced: false,
        explanation: "Concatenación cruda de celdas sin neutralizar caracteres que activan comandos DDE o fórmulas en Excel.",
        remediationSnippet: "if (/^[=+\\-@\\t\\r|%]/.test(s)) { s = `'${s}`; }"
      }
    ],
    overallStatus: "NON_COMPLIANT"
  };

  const parsed = FormulaInjectionAuditReportSchema.safeParse(report);
  assert.equal(parsed.success, true);
});
