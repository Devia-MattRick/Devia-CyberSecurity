import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerConfigHardeningTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_config_hardening",
    "Dimensión 7: Bastionado de configuración de endpoints, reglas de reducción de superficie de ataque (Microsoft Defender ASR) y mitigaciones de seguridad.",
    {
      inputFile: z.string().describe("Ruta al archivo de configuración JSON de Defender / ASR a evaluar"),
      generateSample: z.boolean().default(false).describe("Si es true, genera una plantilla JSON de muestra para auditoría"),
    },
    async ({ inputFile, generateSample }) => {
      const args: string[] = ["--json"];
      if (generateSample) {
        args.push("--generate-sample");
      } else {
        args.push("--input", path.resolve(inputFile));
      }

      return executePythonTool(ctx, {
        scriptName: "endpoint_hardening_auditor.py",
        args,
        toolName: "devia_config_hardening",
      });
    }
  );
}
