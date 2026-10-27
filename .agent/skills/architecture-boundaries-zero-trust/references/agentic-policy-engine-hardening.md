# Hardening de Motores de Políticas Agenticas y Prevención de Evasión por Verbos

Este documento establece las directivas de arquitectura defensiva para diseñar y auditar **Motores de Políticas en Sistemas Autónomos y Agentes IA** en **Devia-CyberSecurity**, conforme a la taxonomía canónica (`VULN-ARCH-006` / `VULN-ARCH-007` / CWE-863 / CWE-862 / CWE-285 / OWASP A01:2021).

---

## 🏛️ 1. La Falacia del Filtrado de Verbos por Prefijos de String (VULN-ARCH-006)

Al diseñar agentes con niveles de autonomía restringidos (e.g. `observe`, `read-only`, `audit-only`), muchos frameworks intentan detectar si una acción es mutadora o destructiva verificando si su nombre en string comienza con una lista cerrada de verbos:

```python
# ANTIPATRÓN VULNERABLE: Matching por prefijo de string (ZAK / US-ADSL)
if dsl.reasoning.autonomy_level == AutonomyLevel.OBSERVE:
    mutating_verbs = ("write", "delete", "update", "create", "modify", "execute")
    if any(action.lower().startswith(v) for v in mutating_verbs):
        return PolicyDecision.deny("Action is a mutating operation...")
```

### Vectores de Evasión Demostrados
Cualquier herramienta o acción que realice escrituras en disco, cambios en bases de datos, despliegue de paquetes o peticiones destructivas utilizando verbos alternativos **elude por completo la guardia de seguridad**:

| Acción Maliciosa / Mutadora | Verbo Inicial | ¿Capturado por la Lista? | Resultado de la Política |
| :--- | :--- | :--- | :--- |
| `patch_dependency` | `patch` | ❌ No | **PERMITIDO (Bypass)** |
| `run_exploit` | `run` | ❌ No | **PERMITIDO (Bypass)** |
| `drop_tables` | `drop` | ❌ No | **PERMITIDO (Bypass)** |
| `post_telemetry` | `post` | ❌ No | **PERMITIDO (Bypass)** |
| `put_s3_bucket` | `put` | ❌ No | **PERMITIDO (Bypass)** |
| `kill_process` | `kill` | ❌ No | **PERMITIDO (Bypass)** |
| `set_admin_role` | `set` | ❌ No | **PERMITIDO (Bypass)** |
| `truncate_log` | `truncate` | ❌ No | **PERMITIDO (Bypass)** |
| `apply_migration` | `apply` | ❌ No | **PERMITIDO (Bypass)** |

---

## 🔒 2. El Patrón Contract-First: Metadatos Tipados de Mutabilidad

Para garantizar seguridad determinista, la mutabilidad y los efectos secundarios de una herramienta **deben declararse explícitamente a nivel de contrato o esquema tipado**, jamás deducirse mediante nombres de strings:

```typescript
// PATRÓN SEGURO (TypeScript + Zod): Contrato de herramienta tipada
export const ToolContractSchema = z.object({
  actionId: z.string().min(1),
  isMutating: z.boolean().describe("True si modifica estado, archivos, red o DB"),
  requiresApproval: z.boolean().default(false),
  riskLevel: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  sideEffects: z.array(z.enum(["FS_WRITE", "DB_MUTATION", "NETWORK_CALL", "PROCESS_SPAWN"])).default([])
});

export type ToolContract = z.infer<typeof ToolContractSchema>;
```

### Regla de Evaluación en el Policy Engine:
```typescript
if (agent.autonomyLevel === "observe" && tool.isMutating) {
  return PolicyDecision.deny(`Herramienta '${tool.actionId}' declarada como mutadora.`);
}
```

---

## 🚫 3. Erradicación del Bypass por Invocación Directa (VULN-ARCH-007)

### El Fallo en Decoradores de Herramientas
Cuando un decorador como `@zak_tool` define un wrapper permisivo que ejecuta la función original si se llama directamente:
```python
# ANTIPATRÓN VULNERABLE: Direct call bypasses policy engine
@functools.wraps(fn)
def wrapper(*args, **kwargs):
    return fn(*args, **kwargs)  # Bypass silencioso sin policy ni audit
```
Un desarrollador, subagente o atacante mediante inyección de código puede invocar `tool_fn()` directamente sin pasar por `ToolExecutor.call()`, suprimiendo la auditoría forense y saltándose todas las barreras de contención.

### La Solución Arquitectónica: Invocación Hermética
1. **Ocultamiento de Funciones Subyacentes:** Las funciones de herramientas reales no deben ser invocables directamente. Deben permanecer privadas o requerir un token de despacho criptográfico que solo el ejecutor central (`ToolExecutor`) puede emitir.
2. **Inyección Obligatoria de Contexto Sellado:** La herramienta debe rechazar la ejecución inmediata si el contexto suministrado no contiene una decisión de política sellada (`PolicyDecision.permit`) con el hash correspondiente a la llamada en curso.
