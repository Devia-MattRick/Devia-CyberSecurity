import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerIdentityAccessTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_identity_access",
    "Dimensión 4: Análisis y minería de matrices de asignación de permisos RBAC/ABAC para optimización de privilegios mínimos y roles huérfanos.",
    {
      inputFile: z.string().describe("Ruta al archivo CSV o JSON con asignaciones de usuarios y permisos/entitlements"),
      systemName: z.string().optional().describe("Nombre del sistema o entorno evaluado"),
      minUsers: z.number().int().min(1).default(2).describe("Mínimo de usuarios para justificar un rol agrupado"),
    },
    async ({ inputFile, systemName, minUsers }) => {
      const resolvedInput = path.resolve(inputFile);
      const args = [resolvedInput, "--json", "--min-users", minUsers.toString()];
      if (systemName) {
        args.push("--system", systemName);
      }

      return executePythonTool(ctx, {
        scriptName: "role_mining_analyzer.py",
        args,
        toolName: "devia_identity_access",
      });
    }
  );
}
