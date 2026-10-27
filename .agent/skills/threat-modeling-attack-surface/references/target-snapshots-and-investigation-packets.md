# Snapshots Deterministas de Objetivo y Paquetes de Investigación (Investigation Packets)

Este documento define la metodología autoritativa para calcular snapshots inmutables del espacio de trabajo y estructurar paquetes de investigación (*Investigation Packets*) durante el modelado de amenazas en **Devia-CyberSecurity**.

---

## 1. Snapshots Deterministas de Espacio de Trabajo

Para garantizar reproducibilidad absoluta y trazabilidad a prueba de manipulaciones, todo análisis debe comenzar calculando el hash del objetivo según su naturaleza física:

| Tipo de Objetivo | Identificador / Requisitos | Formato del Digest |
| :--- | :--- | :--- |
| **`git_revision`** | Commit SHA limpio (`rev-parse HEAD`). | Commit hash exacto. |
| **`git_worktree`** | Revision base + digest determinista del árbol de trabajo (incluyendo staged y untracked pertinentes). | `devia-snapshot/v1:sha256:<64-hex>` |
| **`git_diff`** | Base commit, head commit y digest del changeset. | `devia-snapshot/v1:sha256:<64-hex>` |
| **`directory_snapshot`** | Snapshot sin Git: traversal ordenado lexicográficamente de todos los archivos en scope calculando `path:sha256`. | `devia-snapshot/v1:sha256:<64-hex>` |

> [!TIP]  
> Utilizar la utilidad de Capa 3 [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py) para el cálculo automático en línea de comandos:  
> `python src/scripts/target_snapshot.py snapshot <DIRECTORIO> --json`

---

## 2. Derivación de Huellas Primarias Estables (Finding Fingerprints)

Para evitar la deriva de hallazgos ante refactorizaciones o inserciones de líneas intermedias, la identidad de un hallazgo **NUNCA** debe contener números de línea:

$$\text{Fingerprint} = \text{SHA-256}(\text{targetId} : \text{ruleId} : \text{anchor} : \text{instance})$$

- **`ruleId`**: Identificador de la familia de control (e.g. `path-traversal.archive-extraction`, `authorization-bypass.object-update`). Formato: `<categoría>.<control>`.
- **`anchor`**: Ancla semántica del control raíz vulnerable (e.g. `extract-zip-without-containment`, `upsert-environment-reserved-id`).
- **`instance`**: Diferenciador opcional para instancias hermanas independientes dentro de la misma función o módulo.
- **Formato Final:** `devia/v1:sha256:<64 hex>`.

---

## 3. Metodología de Paquetes de Investigación (*Investigation Packets*)

En lugar de lanzar agentes o tareas de inspección con prompts genéricos o fragmentados, el análisis debe descomponer la superficie de ataque en **Paquetes de Investigación Coherentes**:

Cada paquete agrupa preguntas de seguridad concretas que comparten:
1. **Actor de Amenaza Plausible:** Nivel de acceso y capacidades asumidas.
2. **Activo Protegido:** Datos sensibles, llaves maestras, bases de datos o aislamiento de procesos.
3. **Puntos de Entrada Reales:** Rutas HTTP, endpoints IPC, argumentos CLI, variables de entorno.
4. **Controles de Seguridad Esperados:** Validación de esquema, autorización RBAC/ABAC, sanitización de paths.
5. **Operaciones Sensibles:** Sinks críticos (`fs.writeFile`, `exec`, deserialización, queries SQL).
6. **Anclas en Código Fuente:** Rutas relativas del repositorio donde residen los componentes.

### Estructura de un Paquete de Investigación:
```json
{
  "packetId": "PKT-AUTH-001",
  "attacker": "Unauthenticated Remote Client",
  "asset": "Internal IPC Execution Server",
  "entrypoint": "POST /api/v1/environment",
  "expectedControl": "Rechazar identificadores de entorno reservados ('local', 'system')",
  "sensitiveOperation": "EnvironmentManager.upsert()",
  "sourceAnchors": ["src/server/environment.ts:45-80"],
  "objective": "Verificar si rutas de mutación en runtime omiten la validación aplicada en el inicio"
}
```
