import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import { ToolContext, executePythonTool } from "../tool-context.js";

export function registerSupplyChainTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_supply_chain",
    "Dimensión 5: Auditoría estática de integridad de composición de software (SCA), verificación de lockfiles (npm, pnpm, yarn, cargo, poetry) y detección de lifecycle hooks maliciosos.",
    {
      targetPath: z.string().describe("Ruta canónica al repositorio o directorio con manifiestos y lockfiles"),
    },
    async ({ targetPath }) => {
      const resolvedTarget = path.resolve(targetPath);
      return executePythonTool(ctx, {
        scriptName: "check_lockfiles.py",
        args: [resolvedTarget, "--json"],
        toolName: "devia_supply_chain",
        cwd: resolvedTarget,
      });
    }
  );
}
