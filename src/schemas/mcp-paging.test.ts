import test from "node:test";
import assert from "node:assert/strict";
import {
  McpPagingBudgetConfigSchema,
  McpPagedResponseSchema,
  McpExecutionReportSchema
} from "./mcp-paging.schema.js";

test("McpPagingBudgetConfigSchema: valida configuración por defecto y personalizada", () => {
  const defaultCfg = McpPagingBudgetConfigSchema.parse({});
  assert.equal(defaultCfg.maxBytesPerPage, 262144);
  assert.equal(defaultCfg.maxItemsPerPage, 100);
  assert.equal(defaultCfg.sseLimitBytes, 1048576);
  assert.equal(defaultCfg.antiStarvation, true);

  const customCfg = McpPagingBudgetConfigSchema.parse({
    maxBytesPerPage: 131072,
    maxItemsPerPage: 50,
    sseLimitBytes: 524288,
    antiStarvation: false
  });
  assert.equal(customCfg.maxBytesPerPage, 131072);
  assert.equal(customCfg.maxItemsPerPage, 50);
});

test("McpPagedResponseSchema: valida sobre estructurado de página", () => {
  const samplePage = {
    executionId: "exec-test-001",
    items: [
      { id: "find-1", severity: "HIGH", title: "SQLi" },
      { id: "find-2", severity: "MEDIUM", title: "CORS" }
    ],
    cursor: 0,
    nextCursor: 2,
    done: false,
    byteSize: 1240,
    itemCount: 2
  };

  const parsed = McpPagedResponseSchema.safeParse(samplePage);
  assert.equal(parsed.success, true);
});

test("McpExecutionReportSchema: valida reportes de ejecuciones en curso y fallidas", () => {
  const runningReport = {
    executionId: "exec-99",
    status: "running",
    startedAt: "2026-10-31T02:00:00Z"
  };
  const parsedRunning = McpExecutionReportSchema.safeParse(runningReport);
  assert.equal(parsedRunning.success, true);

  const failedReport = {
    executionId: "exec-100",
    status: "failed",
    error: "Connection timeout to Kali runner",
    timedOut: true,
    cancelled: false
  };
  const parsedFailed = McpExecutionReportSchema.safeParse(failedReport);
  assert.equal(parsedFailed.success, true);
  if (parsedFailed.success) {
    assert.equal(parsedFailed.data.timedOut, true);
  }
});
