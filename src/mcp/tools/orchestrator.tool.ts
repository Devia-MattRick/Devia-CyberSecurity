import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerOrchestratorTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_orchestrate_audit",
    "Orquestador Maestro de Ciberseguridad: Fase 1 (Reconocimiento determinista del stack y mapeo dimensional) o barrido multi-motor.",
    {
      targetPath: z.string().describe("Ruta canónica al repositorio o proyecto objetivo a auditar"),
      phase: z.enum(["RECON", "FULL"]).default("RECON").describe("Fase a ejecutar: RECON (Stack y mapeo) o FULL (multi-motor)"),
      outputDir: z.string().optional().describe("Ruta opcional para persistir reportes de salida"),
    },
    async ({ targetPath, phase, outputDir }) => {
      const resolvedTarget = path.resolve(targetPath);
      const args = [resolvedTarget, "--json"];
      if (outputDir) {
        const reportName = phase === "FULL" ? "full-recon-report.json" : "recon-report.json";
        args.push("-o", path.resolve(outputDir, reportName));
      }

      return executePythonTool(ctx, {
        scriptName: "stack_detector_mapper.py",
        args,
        toolName: `devia_orchestrate_audit:${phase}`,
        cwd: resolvedTarget,
      });
    }
  );
}
