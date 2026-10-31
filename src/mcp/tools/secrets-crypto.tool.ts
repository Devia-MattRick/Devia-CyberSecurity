import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerSecretsCryptoTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_secrets_crypto",
    "Dimensión 3: Detección exhaustiva de secretos con entropía de Shannon (CWE-798) y auditoría de inventario criptográfico / postura Post-Cuántica (PQC FIPS 203/204).",
    {
      targetPath: z.string().describe("Ruta canónica al repositorio, archivo o directorio a escanear"),
      action: z
        .enum(["SECRETS", "PQC_INVENTORY"])
        .default("SECRETS")
        .describe("Acción criptográfica: SECRETS (escáner determinista de claves con entropía) o PQC_INVENTORY (auditoría de preparación post-cuántica)"),
    },
    async ({ targetPath, action }) => {
      const resolvedTarget = path.resolve(targetPath);

      if (action === "SECRETS") {
        return executePythonTool(ctx, {
          scriptName: "scan_secrets.py",
          args: [resolvedTarget, "--json"],
          toolName: "devia_secrets_crypto:SECRETS",
          cwd: resolvedTarget,
        });
      }

      // PQC_INVENTORY
      return executePythonTool(ctx, {
        scriptName: "pqc_inventory_scanner.py",
        args: [resolvedTarget, "--json"],
        toolName: "devia_secrets_crypto:PQC_INVENTORY",
        cwd: resolvedTarget,
      });
    }
  );
}
