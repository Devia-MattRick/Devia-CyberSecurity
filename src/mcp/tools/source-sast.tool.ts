import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerSourceSastTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_source_sast",
    "Dimensión 2: Análisis estático de código fuente (SAST), detección de inyecciones de fórmulas CSV/Excel (CWE-1236), cálculo de rutas de ataque y oráculos diferenciales.",
    {
      targetPath: z.string().describe("Ruta al código fuente, archivo CSV o repositorio objetivo"),
      action: z
        .enum(["FORMULA_INJECTION", "ATTACK_VECTORS", "SSTI_ORACLE"])
        .default("FORMULA_INJECTION")
        .describe("Acción SAST a ejecutar: FORMULA_INJECTION (escaneo CSV/Excel), ATTACK_VECTORS (análisis de rutas de explotación), SSTI_ORACLE (generación de oráculos no destructivos)"),
    },
    async ({ targetPath, action }) => {
      const resolvedTarget = path.resolve(targetPath);

      if (action === "FORMULA_INJECTION") {
        return executePythonTool(ctx, {
          scriptName: "scan_formula_injection.py",
          args: [resolvedTarget, "--json"],
          toolName: "devia_source_sast:FORMULA_INJECTION",
          cwd: resolvedTarget,
        });
      }

      if (action === "ATTACK_VECTORS") {
        return executePythonTool(ctx, {
          scriptName: "attack_vector_assessment_engine.py",
          args: ["--target", resolvedTarget, "--json"],
          toolName: "devia_source_sast:ATTACK_VECTORS",
        });
      }

      // SSTI_ORACLE
      return executePythonTool(ctx, {
        scriptName: "differential_exploit_verifier.py",
        args: ["ssti-generate"],
        toolName: "devia_source_sast:SSTI_ORACLE",
      });
    }
  );
}
