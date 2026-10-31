import { z } from "zod";

/**
 * Configuración autoritativa del presupuesto de paginación para transporte MCP.
 * Diseñado para proteger el canal streamable-http frente al límite duro de 1 MiB de eventos SSE.
 */
export const McpPagingBudgetConfigSchema = z.object({
  maxBytesPerPage: z.number().int().positive().default(262144).describe("Tope en bytes por página (default 256 KiB)"),
  maxItemsPerPage: z.number().int().positive().default(100).describe("Tope de elementos por página (default 100)"),
  sseLimitBytes: z.number().int().positive().default(1048576).describe("Límite absoluto de transporte SSE (1 MiB)"),
  antiStarvation: z.boolean().default(true).describe("Garantiza la entrega de al menos 1 elemento si este excede el presupuesto individual")
});

export type McpPagingBudgetConfig = z.infer<typeof McpPagingBudgetConfigSchema>;

/**
 * Estados canónicos de una ejecución o escaneo asíncrono en un runner MCP.
 */
export const McpExecutionStatusSchema = z.enum([
  "started",
  "running",
  "done",
  "failed",
  "cancelled",
  "unknown"
]);

export type McpExecutionStatus = z.infer<typeof McpExecutionStatusSchema>;

/**
 * Sobre estructurado de respuesta paginada para herramientas MCP.
 */
export const McpPagedResponseSchema = z.object({
  executionId: z.string().min(1).describe("Identificador de la ejecución"),
  items: z.array(z.record(z.string(), z.any())).describe("Lote de elementos contenidos en la página"),
  cursor: z.number().int().nonnegative().describe("Índice inicial del cursor para esta página"),
  nextCursor: z.number().int().nonnegative().describe("Índice del cursor para solicitar la siguiente página"),
  done: z.boolean().describe("Indica si se ha completado la entrega de todos los elementos"),
  byteSize: z.number().int().nonnegative().describe("Tamaño total aproximado en bytes de los datos serializados"),
  itemCount: z.number().int().nonnegative().describe("Cantidad de elementos en la página actual")
});

export type McpPagedResponse = z.infer<typeof McpPagedResponseSchema>;

/**
 * Reporte de estado de ejecución en background para sondeo de clientes MCP.
 */
export const McpExecutionReportSchema = z.object({
  executionId: z.string().min(1),
  status: McpExecutionStatusSchema,
  totalItems: z.number().int().nonnegative().optional(),
  error: z.string().optional(),
  timedOut: z.boolean().default(false),
  cancelled: z.boolean().default(false),
  startedAt: z.string().datetime().optional(),
  completedAt: z.string().datetime().optional()
});

export type McpExecutionReport = z.infer<typeof McpExecutionReportSchema>;
