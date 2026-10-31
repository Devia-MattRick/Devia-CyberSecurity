import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";
import { ToolContext } from "../tool-context.js";
import { sanitizeUntrustedText } from "../sanitizer.js";

interface ScriptEntry {
  name: string;
  path: string;
  dimension: string;
  skill: string;
  description: string;
  schema: string;
  test: string;
  vulnerabilities: string[];
}

export function registerSearchTool(server: McpServer, ctx: ToolContext): void {
  server.tool(
    "devia_search_tools",
    "Búsqueda léxica offline de herramientas deterministas, dimensiones de seguridad y referencias técnicas de Devia-CyberSecurity.",
    {
      query: z.string().describe("Términos clave de búsqueda (ej. 'secretos', 'ssrf', 'lockfiles', 'pqc', 'mcp poisoning', 'jwt')"),
      limit: z.number().int().min(1).max(20).default(5).describe("Número máximo de resultados"),
    },
    async ({ query, limit }) => {
      try {
        const manifestPath = path.join(ctx.scriptsDir, "scripts_manifest.json");
        if (!fs.existsSync(manifestPath)) {
          return {
            content: [{ type: "text", text: "Error: scripts_manifest.json not found." }],
            isError: true,
          };
        }

        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8")) as { scripts: ScriptEntry[] };
        const queryTerms = query.toLowerCase().split(/\s+/).filter(Boolean);

        const scored = manifest.scripts.map((entry) => {
          let score = 0;
          const searchCorpus = [
            entry.name,
            entry.dimension,
            entry.skill,
            entry.description,
            entry.schema,
            ...entry.vulnerabilities,
          ].join(" ").toLowerCase();

          for (const term of queryTerms) {
            if (entry.name.toLowerCase().includes(term)) score += 10;
            if (entry.vulnerabilities.some((v) => v.toLowerCase().includes(term))) score += 8;
            if (entry.dimension.toLowerCase().includes(term)) score += 5;
            if (searchCorpus.includes(term)) score += 2;
          }

          return { entry, score };
        });

        const topMatches = scored
          .filter((item) => item.score > 0)
          .sort((a, b) => b.score - a.score)
          .slice(0, limit)
          .map((item) => ({
            name: item.entry.name,
            dimension: item.entry.dimension,
            skill: item.entry.skill,
            description: item.entry.description,
            vulnerabilities: item.entry.vulnerabilities,
            schema: item.entry.schema,
          }));

        const resultHeader = `🔍 Devia Tool Search Results for: "${query}" (Found ${topMatches.length} matches)`;
        const resultBody = JSON.stringify(topMatches, null, 2);

        return {
          content: [{ type: "text", text: sanitizeUntrustedText(`${resultHeader}\n\n${resultBody}`) }],
        };
      } catch (err: unknown) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: "text", text: `Search Error: ${errMsg}` }],
        };
      }
    }
  );
}
