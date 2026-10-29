# Marco de Auditoría de Sistemas Agenticos y Ecosistemas de Herramientas MCP

Este documento establece la metodología autoritativa y el marco de evaluación de seguridad para sistemas de Inteligencia Artificial que invocan herramientas, servidores MCP (Model Context Protocol), recursos y subagentes autónomos dentro de **Devia-CyberSecurity**.

---

## 🏛️ Axioma Fundamental de Autoridad

> [!CRITICAL]
> **El texto del prompt o las instrucciones del sistema NO son una frontera de autorización.**  
> Trata al runtime del modelo como un *diputado confundido* (*confused deputy*) cuya autoridad efectiva está delimitada por la unión de sus credenciales, herramientas registradas, alcance de red, permisos de filesystem y políticas de aprobación.

---

## 🗺️ Mapa de Autoridad Efectiva (*Effective-Authority Map*)

Para auditar un agente o ecosistema MCP, debe trazarse la ruta completa de propagación de datos y privilegios:

```
[Usuario / Contenido Externo No Confiable]
                    │
                    ▼
       [Contexto del Modelo y Memoria]
                    │
                    ▼
     [Planificador / Enrutador / Políticas]
                    │
                    ▼
     [Herramienta / Subagente Delegado]
                    │
                    ▼
    [Credenciales y Sistemas Destino]
                    │
                    ▼
[Efecto Secundario (Mutación) / Datos Retornados]
```

### Factores a Auditar en Cada Nodo:
1. **Identidad del Componente:** Canonizar la identidad de cada herramienta como:
   $$\text{Tool ID} = \text{server\_identity/version} + \text{endpoint/transport} + \text{tool\_name} + \text{schema\_digest}$$
   *Regla:* Jamás fusionar en una misma decisión de confianza dos herramientas con el mismo nombre provenientes de servidores diferentes.
2. **Alcance y Audiencia de Credenciales:** Verificar que los tokens no tengan permisos superiores a los estrictamente requeridos para la tarea asignada.
3. **Escalada de Lectura a Escritura (*Read-to-Write Escalation*):** Un agente destinado a resumen o lectura de datos jamás debe poder ejecutar acciones de mutación, eliminación, envío de correos o despliegue porque un documento recuperado lo solicite en su texto.

---

## 🔌 Fronteras de Seguridad en el Protocolo MCP (Model Context Protocol)

### 1. Prohibición de Reenvío de Tokens (*No Token Passthrough*)
El protocolo MCP estipula que los tokens de acceso de clientes no deben propagarse aguas abajo hacia APIs de terceros sin un flujo de autorización explícito para ese servidor específico. Los servidores MCP deben rechazar tokens que no fueron emitidos explícitamente para su recurso (`resource/audience`).

### 2. Hints del Protocolo como Metadatos No Confiables e Integridad Total del Esquema
Las anotaciones del protocolo como `readOnlyHint`, `destructiveHint`, `idempotentHint` o `openWorldHint` son pistas informativas suministradas por el servidor o el cliente:
- **Regla:** Ningún motor de políticas de seguridad debe basar sus controles de autorización en estos hints. La verificación de mutabilidad debe validarse contra el esquema canónico y el handler real.
- **Hasheo Criptográfico Integral (Anti Rug-Pull):**  
  Para detectar ataques de "rug pull" (donde un servidor MCP muta la definición de una herramienta aprobada para convertirla en maliciosa), el cliente debe calcular el hash SHA-256 de la definición **completa** de la herramienta:
  $$\text{ToolDigest} = \text{SHA-256}(\text{name} : \text{description} : \text{inputSchema} : \text{outputSchema} : \text{annotations})$$
  Alterar un hint (e.g. cambiar `destructiveHint: true` a `false`) o mutar un parámetro opcional altera el hash y fuerza una re-evaluación humana obligatoria.

### 3. Conexiones Stdio vs Streamable HTTP
- **Transporte Stdio:** El comando de inicio y sus variables de entorno representan ejecución de código local directa. Debe verificarse que los binarios estén firmados o anclados a rutas inmutables.
- **Transporte Streamable HTTP (Reemplazo de HTTP+SSE):**
  - Los endpoints locales deben escuchar exclusivamente en `127.0.0.1` a menos que se requiera acceso de red explícito.
  - El servidor MCP DEBE validar la cabecera `Origin` en peticiones entrantes rechazando orígenes no autorizados con HTTP 403 (protección contra DNS Rebinding y peticiones CSRF desde navegadores).
  - La autenticación sobre HTTP debe adoptar el perfil **MCP OAuth 2.1 con Resource Indicators**, validando que el token emitido contenga como audiencia (`aud`) el recurso específico del servidor MCP.

### 4. Mitigación de Tool Shadowing y Cross-Server Escalation
- Dado que el LLM observa en su contexto las descripciones de herramientas provenientes de todos los servidores MCP conectados, un servidor malicioso puede inyectar instrucciones en sus descripciones para secuestrar o alterar la forma en que el modelo invoca herramientas de otros servidores confiables (*Tool Shadowing*).
- **Contramedida:** Tratar cada servidor MCP como un dominio de seguridad aislado, auditar descripciones con escáneres estáticos (e.g. `mcp-scan`), exigir que las invocaciones pasen por un proxy mediador de políticas y evitar prefijos genéricos de herramientas.

---

## 📋 Checklist de Auditoría para Sistemas Agenticos (`VULN-ARCH-011`)

- [ ] **Canonización e Integridad de Herramientas:** ¿Cada herramienta cuenta con hash SHA-256 de su esquema completo (incluyendo `inputSchema` y `annotations`) para detectar rug pulls?
- [ ] **Anotaciones como No Confiables:** ¿El motor de autorización trata `readOnlyHint` y `destructiveHint` como meras pistas sin relajar controles de seguridad?
- [ ] **Validación de Origen en Streamable HTTP:** ¿El servidor MCP valida estrictamente la cabecera `Origin` para evitar ataques cross-origin?
- [ ] **Protección Anti-Shadowing:** ¿Se valida que las descripciones de herramientas no referencien ni condicionen el comportamiento de herramientas de otros servidores MCP?
- [ ] **Compuerta de Aprobación Criptográfica (*Action-Binding*):** ¿Las acciones de alto impacto requieren confirmación humana vinculada a un hash inmutable de los argumentos deserializados?
- [ ] **Aislamiento Multi-Tenant:** ¿Los datos, memorias, historiales de chat y herramientas están particionados criptográficamente entre diferentes usuarios o inquilinos?
- [ ] **Fallos Cerrados (*Fail-Closed*):** ¿Ante un fallo de conexión con el sandbox o error de parsing de esquema, el agente aborta la operación en lugar de ejecutar en el host?
- [ ] **Sanitización de Retorno:** ¿Los datos retornados por las herramientas son neutralizados para evitar inyecciones secundarias antes de ser reinyectados al contexto del modelo?
