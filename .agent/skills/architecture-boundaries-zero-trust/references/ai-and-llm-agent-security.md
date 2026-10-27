# Guía Autoritativa: Fronteras de Seguridad en Sistemas de IA, Agentes Autónomos y Protocolo MCP

**Dimensión Canónica:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`  
**Taxonomía:** CWE-74 (Improper Neutralization), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), OWASP LLM Top 10 (LLM01, LLM02, LLM06, LLM07)  
**Skill Asignada:** [`architecture-boundaries-zero-trust`](file:///.agent/skills/architecture-boundaries-zero-trust/SKILL.md)  
**Origen:** Absorción forense de Cloudflare Security Audit (`skills/security-audit/AI-AND-LLM.md`)  

---

## 🏛️ 1. Disciplina Fundamental de Auditoría

Al auditar aplicaciones donde un modelo de lenguaje o agente participa en una decisión sensible a la confianza (asistentes, pipelines RAG, memoria persistente, bucles de llamadas a herramientas, servidores y clientes MCP), rigen los siguientes principios inmutables:

1. **La inyección de prompts por sí sola NO es una vulnerabilidad reportable:**  
   Un texto persuasivo o una elusión de restricciones conversacionales es únicamente un vector de entrada. Para constituir una vulnerabilidad de seguridad de software, debe demostrarse un fallo de frontera a nivel de código: el contenido alcanza el contexto de otro usuario, invoca privilegios de los que carece el solicitante, divulga datos protegidos o alimenta un sumidero destructivo (*sink*) que el usuario no puede alcanzar directamente.
2. **Las salidas del modelo, memorias y respuestas MCP son entradas NO CONFIABLES:**  
   Todo dato devuelto por un LLM, una memoria vectorial o una herramienta MCP debe tratarse como hostil. El código backend debe aplicar validación estricta de esquemas (Zod / Pydantic) y autorización antes de despachar cualquier acción.
3. **Un prompt de sistema (*system prompt*) NO es una frontera de seguridad:**  
   Las instrucciones en lenguaje natural jamás sustituyen a controles deterministas de código, autorización basada en recursos, aislamiento de sesiones y credenciales limitadas.
4. **Separación estricta entre Autorización y Vinculación de Acciones (*Action-Binding*):**  
   Aunque un usuario tenga permisos genéricos para ejecutar una acción, si un contenido controlado por un atacante induce al modelo a invocar esa acción sin la intención o aprobación explícita de los argumentos exactos por parte de la víctima, existe una vulnerabilidad de *Action-Binding*.

---

## 🔍 2. Vectores de Ataque en Contexto, Recuperación y Memoria

### 2.1. Inyección Indirecta a través de Contenido Recuperado (RAG e Ingesta)
- **Mecanismo:** Un atacante introduce instrucciones maliciosas en documentos, páginas web indexadas, correos electrónicos, tickets o metadatos consumidos por un proceso RAG. Cuando otro usuario consulta el sistema, el texto inyectado secuestra las instrucciones del modelo.
- **Control Requerido:** Aislamiento estricto de contextos entre inquilinos; filtrado de metadatos antes de la síntesis; delimitación sintáctica clara entre datos no confiables y directivas del sistema; y desactivación de herramientas privilegiadas durante flujos de sólo lectura.

### 2.2. Sangrado de Contexto entre Sesiones o Tenants (*Context Bleed*)
- **Mecanismo:** Historiales de conversación, embeddings vectoriales, resultados de búsqueda semántica o cachés de prompts compartidos se indexan sin claves compuestas que incluyan el identificador estricto del tenant (`tenant_id`).
- **Control Requerido:** Toda consulta vectorial y caché semántico debe incorporar obligatoriamente el `tenant_id` en el predicado de búsqueda y en la clave primaria de almacenamiento:
  $$\text{CacheKey} = \text{SHA-256}(\text{tenant\_id} : \text{user\_id} : \text{query})$$

### 2.3. Envenenamiento de Memoria Persistente (*Persistent Memory Poisoning*)
- **Mecanismo:** El modelo resume o almacena hechos derivados de interacciones con datos no confiables en una memoria a largo plazo (SQLite, Vector Store, Graph). En sesiones futuras, estas instrucciones envenenadas alteran el comportamiento del agente.
- **Control Requerido:** Procedencia obligatoria de cada registro de memoria; segregación entre preferencias declaradas por el usuario autenticado e inferencias autónomas; confirmación del operador antes de persistir cambios en políticas operativas.

---

## 🛠️ 3. Vectores de Ataque en Herramientas y Despacho de Acciones

### 3.1. Inyección de Argumentos de Herramienta hacia Sumideros Sensibles
- **Mecanismo:** Los argumentos generados por el modelo se pasan directamente a comandos del sistema operativo (`subprocess`), consultas a base de datos (`SQL / ORM`), invocaciones de red (`fetch / axios`) o manipulación de archivos (`fs.writeFile`) sin validación en el manejador (*handler*).
- **El Patrón Seguro (Contrato Zod en el Handler):**
  ```typescript
  // ❌ VULNERABLE: Confianza ciega en argumentos generados por el modelo
  async function executeTool(args: any) {
    await db.query(`SELECT * FROM users WHERE id = ${args.userId}`);
  }

  // ✅ SEGURO: Validación de esquema y control de acceso en el handler
  const UserLookupSchema = z.object({
    userId: z.string().uuid()
  });

  async function executeTool(rawArgs: unknown, callerSession: UserSession) {
    const validated = UserLookupSchema.parse(rawArgs);
    if (validated.userId !== callerSession.userId && !callerSession.isAdmin) {
      throw new SecurityException("Unauthorized access across user boundary");
    }
    return await db.users.findUnique({ where: { id: validated.userId } });
  }
  ```

### 3.2. Autoridad de Diputado Confundido y Exceso de Agencia
- **Mecanismo:** El agente ejecuta herramientas utilizando una credencial de servicio global con altos privilegios (e.g. `service_role` de base de datos o token IAM de administrador), mientras que el usuario final que originó la petición tiene privilegios restringidos.
- **Control Requerido:** Paso explícito de la identidad del usuario solicitante (*execution context*) al manejador de la herramienta, re-validando los permisos RBAC/ABAC sobre el recurso específico solicitado.

### 3.3. Fallo de Vinculación de Confirmación de Acción (*Action-Binding Failure*)
- **Mecanismo:** La interfaz solicita confirmación al usuario para una acción descrita en texto plano ("¿Deseas transferir \$10?"), pero la ejecución posterior utiliza argumentos alterados por un turno subsecuente del modelo, o ejecuta la acción con un destinatario diferente.
- **El Patrón Seguro (Hash Criptográfico de Vinculación):**
  ```typescript
  // Al presentar la confirmación:
  const approvalDigest = crypto.createHash('sha256')
    .update(`${normalizedToolName}:${JSON.stringify(normalizedArgs)}:${sessionToken}:${nonce}`)
    .digest('hex');

  // Al ejecutar la acción:
  if (receivedApprovalToken !== expectedApprovalDigest) {
    throw new SecurityException("Action-Binding validation failed: arguments or session mutated");
  }
  ```

---

## 🔌 4. Fronteras de Confianza en el Protocolo MCP (Model Context Protocol)

### 4.1. Herencia de Confianza en Subagentes y MCP
- **Mecanismo:** Al delegar una tarea a un subagente o servidor MCP externo, se transmiten la sesión completa, los tokens de acceso amplios y el historial sin restricciones de menor privilegio.
- **Control Requerido:** Estricto estrechamiento de capacidades (*Capability Narrowing*). Los servidores MCP reciben únicamente tokens con audiencia restringida y alcance temporal efímero.

### 4.2. Confusión de Identidad en Servidores y Herramientas MCP
- **Mecanismo:** Dos servidores MCP declaran herramientas con nombres idénticos o solapados (e.g. `execute_query`), o un servidor malicioso registra un alias para interceptar llamadas destinadas a un servidor legítimo.
- **Control Requerido:** Espacios de nombres forzados por el cliente: `<server_id>.<tool_name>`. El despachador resuelve las llamadas basándose en la conexión autenticada y el identificador único del servidor, jamás por nombres globales planos.

### 4.3. Metadatos y Esquemas MCP como Política
- **Mecanismo:** Confiar en que las descripciones de herramientas, esquemas de entrada o sugerencias proporcionadas por un servidor MCP son garantías de seguridad o políticas de autorización.
- **Control Requerido:** La autorización reside exclusivamente en el cliente y en los controladores del backend. La descripción de una herramienta guía al modelo, pero jamás confiere autoridad técnica.

---

## 📋 Checklist de Auditoría para Sistemas con IA / Agentes

- [ ] ¿Todos los argumentos generados por el LLM se validan contra esquemas estrictos de Zod antes de su uso?
- [ ] ¿Se re-verifica la identidad y permisos del usuario solicitante en el handler de cada herramienta?
- [ ] ¿Las acciones mutantes o irreversibles exigen confirmación atómicamente vinculada por hash criptográfico (*Action-Binding*)?
- [ ] ¿Las consultas vectoriales y cachés RAG aíslan deterministamente por `tenant_id`?
- [ ] ¿Los servidores MCP están confinados en espacios de nombres únicos sin solapamiento de herramientas?
- [ ] ¿Se cuenta con un presupuesto estricto de ejecuciones ($O(1)$) que impida bucles autónomos infinitos de gasto de recursos?
