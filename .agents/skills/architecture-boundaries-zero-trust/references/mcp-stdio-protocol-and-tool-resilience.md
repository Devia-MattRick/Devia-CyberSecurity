# Hardening del Protocolo MCP Stdio y Resiliencia de Herramientas

> **ID de Vulnerabilidad:** `VULN-ARCH-020`  
> **Taxonomía:** CWE-250 (*Execution with Unnecessary Privileges*) / CWE-668 (*Exposure of Resource to Wrong Sphere*) / OWASP MCP Top 10 (MCP03/MCP05)  
> **Dimensión:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`  
> **Skill:** `architecture-boundaries-zero-trust`  

---

## 1. El Modelo de Servidor MCP Headless sobre Stdio

El Model Context Protocol (MCP) permite a los agentes de IA invocar herramientas del sistema operativo. Cuando un servidor MCP opera en modo **Headless Stdio**:
1. **Zero Network Ports:** La comunicación se realiza exclusivamente a través de los flujos estándar de entrada y salida (`stdin`/`stdout`). No expone puertos TCP ni sockets de red escuchando conexiones externas.
2. **Fragilidad del Canal IPC:** A diferencia de un servidor HTTP donde una excepción no capturada solo aborta una petición (error 500), en un servidor Stdio un error no controlado o una llamada a `process.exit()` **finaliza el subproceso entero**, rompiendo permanentemente la sesión del agente.

---

## 2. Invariante de Resiliencia: `{ isError: true }`

Para garantizar que un fallo en una herramienta no derribe el canal IPC de Stdio, **toda herramienta MCP registrada DEBE envolver su ejecución en bloques `try/catch` rigurosos**:

```typescript
// Implementación canónica de resiliencia en herramientas MCP
server.tool(
  'inspect_leads_file',
  'Inspecciona y valida un archivo de prospectos en disco',
  InspectLeadsSchema.shape,
  async (args) => {
    try {
      // 1. Validar ruta dentro del confinamiento seguro
      const safePath = SafeFilePathSchema.parse(args.filePath);
      
      // 2. Ejecución de la lógica de la herramienta
      const result = await processFile(safePath);
      
      return {
        content: [{ type: 'text', text: JSON.stringify(result) }]
      };
    } catch (err: any) {
      // Rescatar limpiamente sin propagar la excepción al runtime de Node
      return {
        isError: true,
        content: [{
          type: 'text',
          text: `Error en la herramienta inspect_leads_file: ${err.message || 'Error desconocido'}`
        }]
      };
    }
  }
);
```

---

## 3. Confinamiento Perimetral con `SafeFilePathSchema`

Para neutralizar vectores de **Path Traversal** donde un prompt o modelo intente acceder a rutas críticas del sistema (e.g. `../../../../Windows/System32` o `/etc/passwd`), toda herramienta que interactúe con el sistema de archivos debe validar las rutas mediante un esquema Zod estricto:

```typescript
export const SafeFilePathSchema = z.string()
  .min(1)
  .refine(val => !val.includes('\0'), { message: 'Bytes nulos prohibidos' })
  .refine(val => !val.includes('..'), { message: 'Secuencias de escape de directorio (..) prohibidas' })
  .refine(val => !val.includes('%2e'), { message: 'Codificación URL en rutas prohibida' })
  .transform(val => {
    const baseDir = path.resolve(process.cwd(), 'exports');
    const resolved = path.resolve(baseDir, val);
    
    // Confinamiento estricto al subdirectorio autorizado
    if (!resolved.startsWith(baseDir)) {
      throw new Error(`Acceso fuera de la jaula './exports/' denegado`);
    }
    return resolved;
  });
```

---

## 4. Checklist de Auditoría para Servidores MCP

- [ ] ¿El servidor MCP opera exclusivamente sobre `StdioServerTransport` sin abrir puertos HTTP innecesarios?
- [ ] ¿La totalidad de herramientas registradas capturan sus excepciones y devuelven `{ isError: true }`?
- [ ] ¿Las herramientas que reciben rutas de archivo aplican `SafeFilePathSchema` bloqueando secuencias `..` y confinándose a un subdirectorio aislado?
- [ ] ¿El servidor maneja adecuadamente las señales de terminación del sistema operativo (`SIGINT`, `SIGTERM`) cerrando descriptores de archivos?
