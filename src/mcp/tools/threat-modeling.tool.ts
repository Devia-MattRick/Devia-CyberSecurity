import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerThreatModelingTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_threat_modeling",
    "Dimensión 1: Modelado de amenazas, superficie de ataque, snapshots deterministas de repositorios y riesgo cibernético (STRIDE/NIST SP 800-30).",
    {
      targetPath: z.string().describe("Ruta canónica al repositorio, archivo o directorio objetivo"),
      action: z
        .enum(["SNAPSHOT", "RISK_ASSESSMENT", "PROMPT_INJECTION"])
        .default("SNAPSHOT")
        .describe("Acción de modelado de amenazas: SNAPSHOT (huellas O(1) y estructura), RISK_ASSESSMENT (evaluador cuantitativo NIST), PROMPT_INJECTION (detección de inyecciones indirectas)"),
      inputFile: z.string().optional().describe("Archivo JSON de eventos de amenaza de entrada (para RISK_ASSESSMENT)"),
    },
    async ({ targetPath, action, inputFile }) => {
      const resolvedTarget = path.resolve(targetPath);

      if (action === "SNAPSHOT") {
        return executePythonTool(ctx, {
          scriptName: "target_snapshot.py",
          args: ["snapshot", resolvedTarget, "--json"],
          toolName: "devia_threat_modeling:SNAPSHOT",
          cwd: resolvedTarget,
        });
      }

      if (action === "RISK_ASSESSMENT") {
        const input = inputFile ? path.resolve(inputFile) : resolvedTarget;
        return executePythonTool(ctx, {
          scriptName: "risk_assessment_engine.py",
          args: ["-i", input, "--json"],
          toolName: "devia_threat_modeling:RISK_ASSESSMENT",
        });
      }

      // PROMPT_INJECTION
      return executePythonTool(ctx, {
        scriptName: "prompt_injection_detector.py",
        args: ["scan-file", resolvedTarget, "--json"],
        toolName: "devia_threat_modeling:PROMPT_INJECTION",
      });
    }
  );
}
