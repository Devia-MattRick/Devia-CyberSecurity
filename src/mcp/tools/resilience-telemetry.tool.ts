import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerResilienceTelemetryTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_resilience_telemetry",
    "Dimensión 8: Escaneo de telemetría clandestina/encubierta, exfiltración en cargas Base64 y procesamiento de reportes normalizados SARIF 2.1.0.",
    {
      targetPath: z.string().describe("Ruta al archivo de código, script o reporte SARIF"),
      action: z
        .enum(["COVERT_TELEMETRY", "SARIF_SUMMARY"])
        .default("COVERT_TELEMETRY")
        .describe("Acción de resiliencia y telemetría: COVERT_TELEMETRY (detección de fugas/balizas) o SARIF_SUMMARY (resumen de reporte SARIF)"),
    },
    async ({ targetPath, action }) => {
      const resolvedTarget = path.resolve(targetPath);

      if (action === "COVERT_TELEMETRY") {
        return executePythonTool(ctx, {
          scriptName: "scan_covert_telemetry.py",
          args: [resolvedTarget, "--json"],
          toolName: "devia_resilience_telemetry:COVERT_TELEMETRY",
          cwd: resolvedTarget,
        });
      }

      // SARIF_SUMMARY
      return executePythonTool(ctx, {
        scriptName: "sarif_toolkit.py",
        args: ["summary", resolvedTarget],
        toolName: "devia_resilience_telemetry:SARIF_SUMMARY",
      });
    }
  );
}
