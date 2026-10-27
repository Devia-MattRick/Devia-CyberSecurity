# Devia-CyberSecurity — Memoria Proactiva de Ingeniería y Heurísticas Operativas

Este documento constituye la **Memoria Proactiva de Lecciones Aprendidas** de **Devia-CyberSecurity**. Registra soluciones probadas, heurísticas deterministas, decisiones arquitectónicas y atajos de ingeniería para optimizar futuros flujos de trabajo, evitar el sobregasto de tokens en deliberaciones ya resueltas y maximizar la velocidad y precisión defensiva.

---

## 🏛️ 1. Arquitectura y Modelado Contract-First (Capa 2: TypeScript + Zod)

### 1.1. El Patrón del Paquete Sellado (*Sealed Scan Contract*)
- **La Lección:** Tratar los reportes Markdown (`report.md`) o exportaciones SARIF como el estado de verdad de una auditoría provoca pérdida de tipos, falsificación de cobertura y vulnerabilidades de manipulación de estado (`VULN-ARCH-004`).
- **La Regla Operativa:**  
  La auditoría se sella en un bundle inmutable compuesto exclusivamente por:
  1. `scan-manifest.json`: Recibo terminal criptográfico con hashes SHA-256 de los artefactos.
  2. `findings.json`: Hallazgos semánticos canónicos.
  3. `coverage.json`: Cobertura honesta y superficies evaluadas.
- **Proyecciones de Solo Lectura:** `report.md`, exports SARIF o HTML son proyecciones *downstream*. Ningún script ni agente debe parsear Markdown para obtener datos de auditoría.

### 1.2. Huellas Primarias Estables (*Fingerprints*) Desacopladas de Líneas
- **La Lección:** Si la identidad de un hallazgo depende de números de línea (`path:line`), cualquier refactorización, inserción de comentarios o commit rompe el seguimiento histórico y duplica incidencias.
- **La Solución:** Derivar la huella primaria a partir de 4 elementos semánticos estables:
  $$\text{Fingerprint} = \text{SHA-256}(\text{targetId} : \text{ruleId} : \text{anchor} : \text{instance})$$
  - `ruleId`: Familia de control estable (`<categoría>.<control>`, e.g. `path-traversal.archive-extraction`).
  - `anchor`: Ancla semántica del control raíz (e.g. `extract-entry-without-containment`).
  - `instance`: Diferenciador opcional para instancias hermanas.
  - Formato: `devia/v1:sha256:<64-hex>`.

### 1.3. Estructura de Evidencia de Código con 7 Roles Semánticos
- **La Lección:** Los veredictos en prosa genérica ("falta validación") son ambiguos y difíciles de verificar.
- **La Solución:** Todo hallazgo SAST debe estructurar su `codeEvidence` asignando a cada fragmento uno de los 7 roles canónicos:
  `user_input` $\to$ `entrypoint` $\to$ `propagation` $\to$ `root_control` $\to$ `sink` $\to$ `outcome`, complementado con `expected_control` para contrastar el invariante esperado.

### 1.4. Contratos de Mapeo Multimarco y Capas de Visualización ATT&CK
- **La Lección:** Consumir capas JSON de visualización táctica (MITRE ATT&CK Navigator v4.x) sin tipado estricto genera fallos silenciosos por discrepancias de versión (v14 vs v15) y roturas de esquema en dashboards SIEM/CISO.
- **La Solución:** Modelar la estructura formal en Zod (`src/schemas/framework-mapping.schema.ts`):
  `AttackNavigatorLayerSchema`, `MitreTechniqueIdSchema`, `NistCsfFunctionSchema` y `CrossFrameworkMappingEntrySchema`. Ninguna capa se exporta ni procesa sin pasar validación contract-first.


---

## ⚡ 2. Rendimiento y Complejidad Algorítmica (Capa 3: Python Determinista)

### 2.1. Traversal y Cálculo Determinista en Python vs Bucles ReAct
- **La Lección:** Intentar listar directorios, parsear JSONs grandes o calcular hashes mediante bucles conversacionales de LLM o comandos bash encadenados gasta decenas de miles de tokens y es propenso a errores de timeout.
- **La Regla Operativa:**  
  Toda operación de cálculo de hashes, inventario de archivos o análisis de lockfiles debe delegarse a scripts Python deterministas en `src/scripts/` con soporte `--json`.
  - [`src/scripts/forensic_inventory.py`](file:///k:/Devia-CyberSecurity/src/scripts/forensic_inventory.py): Traversal determinista en memoria sin ejecutar código del objetivo.
  - [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py): Hashing ordenado lexicográficamente $O(n \log n)$ y huellas primarias $O(1)$.

### 2.2. Manejo de Inodos de 64/128 bits en Windows para SQLite
- **La Lección:** En Windows con Python 3.12+, `os.stat()` puede reportar IDs de inodo de 128 bits o dispositivos de 64 bits sin signo. Si se almacenan directamente en columnas `INTEGER` de SQLite, se produce un error por desbordamiento del entero firmado de 64 bits ($> 2^{63}-1$).
- **La Solución:** Si el valor excede $[-(2^{63}), 2^{63}-1]$, serializar como cadena prefijada: `stat:<hex>`.

### 2.3. Ingesta y Proyección Determinista de Capas ATT&CK Navigator en Capa 3
- **La Lección:** Parsear capas JSON de ATT&CK Navigator (200+ técnicas con metadatos anidados) mediante bucles ReAct de LLM consume decenas de miles de tokens y produce alucinaciones en la proyección táctica.
- **La Solución:** Utilizar [`src/scripts/navigator_mapper.py`](file:///src/scripts/navigator_mapper.py) en Python 3.11+ stdlib con CLI `--json` (`validate`, `summary`, `project`). Proyecta técnicas $O(n)$ hacia las 8 Dimensiones Canónicas con sobreescrituras semánticas de precisión en $<0.05$ segundos.


---

## 🛡️ 3. Heurísticas Defensivas y Detección de Falsos Negativos

### 3.1. Estándar de Divulgación de Secretos en Código Fuente
- **La Lección:** Analistas o LLMs frecuentemente descartan secretos diciendo: *"está en la carpeta tests"*, *"es un mock"*, o *"la función nunca es invocada en runtime"*.
- **La Regla Operativa:**  
  Un lector con acceso al código fuente que obtiene una credencial que otorga acceso a recursos externos es una ruta de divulgación válida e inmediata (`VULN-CRYP-001`). No se requiere que el código sea ejecutable en producción. Nunca desestimar un secreto únicamente por estar en rutas de test o ejemplos. Queda estrictamente prohibido probar las claves en servicios remotos para ver si están activas.

### 3.2. Discrepancia de Guardias en Operaciones Hermanas (*Sibling Operations*)
- **La Lección:** Los fallos más severos de autorización e IDOR no ocurren en la ruta principal de creación, sino en métodos secundarios de sincronización, actualización o mutación en runtime (`upsert`, `batch-update`, `add`).
- **Heurística de Detección:** Comparar siempre todos los endpoints que aceptan el mismo identificador de entidad y auditar si las rutas secundarias omiten los controles de inmutabilidad o permisos de la ruta principal.

### 3.3. Contención Estricta en Descompresión de Archivos (Zip Slip - CWE-22)
- **La Lección:** Comprobar únicamente si el nombre del archivo contiene `../` es eludible mediante enlaces simbólicos, codificaciones URL o caracteres especiales.
- **Heurística Segura:**
  ```typescript
  const resolvedPath = path.resolve(destinationRoot, entryName);
  if (!resolvedPath.startsWith(path.resolve(destinationRoot) + path.sep)) {
    throw new SecurityException("Zip Slip path traversal attempt");
  }
  ```

### 3.4. El Principio Epistemológico de Inconclusión en Auditorías Incompletas
- **La Lección:** Si una auditoría se detiene por timeout, excepción o cancelación (`failed`, `interrupted`, `canceled`), el agente tiende erróneamente a reportar: *"no se encontraron más vulnerabilidades"*.
- **La Regla Inmutable:**  
  La ausencia de hallazgos en un escaneo no completado es **estrictamente INCONCLUSA**. Queda prohibido emitir certificados de seguridad sobre auditorías parciales.

### 3.5. Filtro Terminal de Calidad: 7-Question Gate & Never-Submit List
- **La Lección:** Reportar incidencias de hardening aisladas (cabeceras HTTP ausentes, banner disclosure, cookie sin `HttpOnly` en tokens no sensibles, GraphQL introspection) satura los reportes de ruido y desvía la atención de brechas críticas.
- **La Regla Operativa:**  
  Ningún hallazgo se confirma sin superar la compuerta de 7 preguntas. Los 15 elementos de la *Never-Submit List* solo son admisibles si forman parte demostrada de una cadena de explotación (*Exploit Chain*, e.g. Open Redirect + OAuth = ATO).

### 3.6. Optimización InitPlan en Políticas RLS de PostgreSQL (InitPlan O(1) vs O(N))
- **La Lección:** Invocar funciones de sesión como `tenant_id = get_user_tenant_id()` de manera desnuda en políticas RLS fuerza a Postgres a re-evaluar la llamada para cada fila ($O(N)$), degradando severamente el rendimiento y abriendo riesgos de timeout en tablas grandes.
- **El Patrón Seguro:**  
  Envolver siempre la función en una subconsulta escalar: `tenant_id = (SELECT get_user_tenant_id())`. Esto permite al optimizador computar el valor una sola vez al inicio del query (`InitPlan` $O(1)$) y reutilizarlo para todas las filas.

### 3.7. Procesamiento y Deduplicación Determinista de SARIF 2.1.0 en Capa 3
- **La Lección:** Intentar parsear reportes SARIF voluminosos mediante regex o LLM conversacional agota tokens y pierde metadatos de ubicación.
- **La Solución:** Utilizar [`src/scripts/sarif_toolkit.py`](file:///src/scripts/sarif_toolkit.py) en Python 3.11+ stdlib para resumen, filtrado por niveles/reglas y fusión con deduplicación por fingerprint (`ruleId:path:line`).

### 3.8. Filtrado Antiruido en Dos Fases: Hard Exclusions O(1) + LLM Confidence Gate
- **La Lección:** El 85-90% de los reportes emitidos por LLMs o herramientas SAST descalibradas corresponden a ruido de baja señal: DoS genérico, falta de rate limiting (mitigado en API Gateway), fugas de recursos/conexiones sin cerrar, open redirects sin cadena de explotación, y falsos reportes de memory safety en Rust/Go/TypeScript (`VULN-RESI-004`).
- **El Patrón de Dos Fases:**
  1. *Fase 1 (Determinista O(1)):* Ejecutar [`src/scripts/hard_exclusions.py`](file:///src/scripts/hard_exclusions.py) con expresiones regulares precompiladas. Si un hallazgo carece de exploit demostrado y coincide con DoS, rate limiting o markdown, se descarta sin gastar tokens.
  2. *Fase 2 (Validación Semántica):* Exigir puntuación de confianza $\ge 8.0 / 10.0$ (>80%) con escenario de explotación explícito (*exploit scenario*) antes de incorporar a `findings.json`.

### 3.9. Axioma de Confianza Cero y No-Vulnerabilidad en Código Cliente (Frontend)
- **La Lección:** Analistas o modelos frecuentemente reportan "falta de autorización", "ausencia de comprobación de roles" o "bypass de permisos" al auditar componentes React, Angular o TypeScript client-side.
- **La Regla Inmutable:** El código del cliente jamás es confiable y no constituye una frontera de seguridad. La autorización y autenticación se auditan y exigen exclusivamente en los controladores, middlewares y APIs del backend. La falta de validación de permisos en código cliente NO es una vulnerabilidad reportable.

### 3.10. Mapeo Canónico MECE de Subdominios Empíricos hacia las 8 Dimensiones
- **La Lección:** Al auditar repositorios o catálogos externos que utilizan taxonomías arbitrarias (*e.g.* los 24 subdominios de habilidades de Anthropic como `ot-ics-security`, `container-security` o `devsecops`), el agente tiende erróneamente a proponer o inventar nuevas dimensiones de seguridad.
- **La Regla Inmutable:** Ningún agente, skill o script puede emitir dimensiones fuera de `SecurityDimensionSchema`. Todo conocimiento debe proyectarse mediante la [Matriz Canónica de Mapeo Multimarco](file:///.agent/skills/threat-modeling-attack-surface/references/cross-framework-mapping-matrix.md): ICS y Zero Trust $\to$ `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`; DevSecOps y contenedores $\to$ `SUPPLY_CHAIN_SCA` y `CONFIGURATION_HARDENING`; pentesting y threat intel $\to$ `THREAT_MODELING_ATTACK_SURFACE`.

### 3.11. Verificación Estática Determinista de Lockfiles y Hooks de Instalación (Supply Chain SCA)
- **La Lección:** Confiar en que los desarrolladores o herramientas CI bloquean versiones sin auditar la presencia física de lockfiles produce brechas graves de integridad de la cadena de suministro (`VULN-SCA-002`, `VULN-SCA-005`). La existencia de lockfiles competitivos en la misma raíz (e.g. `package-lock.json` + `yarn.lock`) genera desincronización y ataques de confusión. Asimismo, scripts de instalación (`preinstall`, `postinstall`) son vectores predilectos para RCE en paquetes troyanizados (`VULN-SCA-003`).
- **La Solución:** Utilizar [`src/scripts/check_lockfiles.py`](file:///src/scripts/check_lockfiles.py) en Python 3.11+ stdlib con CLI `--json`. Inspecciona 8 ecosistemas (npm, pnpm, yarn, bun, pip, poetry, cargo, composer, go), audita exclusiones en `.gitignore`, detecta versiones desancladas (`*`, `latest`) y alerta sobre hooks de instalación de alto riesgo en $<0.02$s sin requerir herramientas externas.

### 3.12. Erradicación del Sesgo de Severidad en Tests para Detección de Secretos
- **La Lección:** Escáneres o herramientas externas de secretos frequentemente degradan la severidad de hallazgos críticos a 'medium' o 'low' si el archivo reside en directorios `test/`, `spec/` o `fixtures/`. Esto constituye un fallo metodológico grave: los desarrolladores comitean regularmente credenciales activas de staging o producción dentro de suites de pruebas.
- **La Regla Inmutable:** La ubicación física del archivo no altera la naturaleza intrínseca de una credencial. Todo secreto real en código fuente es `VULN-CRYP-001` (Critical/High), sin importar si está en rutas de test o mocks. Queda prohibida la degradación automática de severidad por rutas de test.

### 3.13. Detección de Slopsquatting: Verificación de Alucinaciones en Dependencias IA (VULN-SCA-006)
- **La Lección:** Asistentes de codificación basados en LLMs (Copilot, ChatGPT, etc.) alucinan nombres de paquetes no existentes en Python (PyPI) o JavaScript (npm). Atacantes monitorizan estas alucinaciones y pre-registran paquetes troyanizados en los registros públicos esperando su instalación inadvertida.
- **La Regla Operativa:**
  1. Extraer importaciones mediante parsers sintácticos AST (`ast.parse` en Python, compiler API en TypeScript) en lugar de regex lineales para evitar falsos positivos en comentarios o docstrings.
  2. Contrastar cada paquete contra la API del registro oficial. Si no existe $\to$ `phantom` (alucinación de alto riesgo).
  3. Si existe pero su fecha de creación inicial es menor a 30 días $\to$ `suspicious` (posible trampa pre-registrada).
  4. Codificar siempre los identificadores en las URLs (`urllib.parse.quote`) para manejar paquetes con scope (`@scope%2Fname`) y neutralizar traversals.

### 3.14. Antipatrón de Matching por Prefijos de Verbos en Motores de Políticas Agenticas (VULN-ARCH-006)
- **La Lección:** Intentar gobernar la mutabilidad de herramientas o agentes de sólo lectura (`observe-only`) comprobando si el nombre de la acción comienza con una lista fija de prefijos (`write`, `delete`, `update`, `create`, `modify`, `execute`) es fácilmente eludible por herramientas con verbos alternativos (`patch_*`, `run_*`, `drop_*`, `post_*`, `set_*`, `kill_*`).
- **El Patrón Seguro:** Las herramientas deben declarar explícitamente su naturaleza de mutabilidad mediante contratos tipados booleanos (`is_mutating: boolean`, `side_effects: boolean`) o etiquetas semánticas inmutables en tiempo de definición, jamás mediante inspección sintáctica de nombres de acción en runtime.

### 3.15. Sanitización Multiplataforma de Separadores de Ruta: El Caso Windows (VULN-SAST-007)
- **La Lección:** Desarrolladores frecuentemente sanitizan nombres de archivo de usuario o salidas de LLM haciendo únicamente `name.replace('/', '-')`. En sistemas Windows, la barra invertida `\` no es reemplazada, permitiendo que secuencias como `..\..\..\archivo` atraviesen el directorio de destino y sobrescriban archivos críticos del sistema.
- **El Patrón Seguro:**
  ```typescript
  const safeName = path.basename(inputName);
  const resolved = path.resolve(destinationRoot, safeName);
  if (!resolved.startsWith(path.resolve(destinationRoot) + path.sep)) {
    throw new SecurityException("Path traversal attempt detected");
  }
  ```

### 3.16. Modelo Multiplicativo de Propagación de Riesgo frente a la Saturación Plana
- **La Lección:** Fórmulas de scoring lineal plano como `min(100, critical*25 + high*10 + ...)` saturan en 100 con muy pocos hallazgos, cegando al analista respecto a la severidad relativa entre proyectos con 4 o 40 vulnerabilidades críticas.
- **La Solución:** Emplear propagación multiplicativa normalizada (modelo SIF):
  $$\text{node\_risk} = \text{base\_risk} \times \text{exposure\_factor} \times \text{exploitability} \times (1 - \text{control\_effectiveness}) \times \text{privilege\_amplifier}$$
  Ajustado a escala 0.0–10.0 con atenuación formal por efectividad de controles existentes.

### 3.17. Confinamiento Estricto de Salida de Reportes en Agentes de Auditoría (CWE-73 / CWE-200)
- **La Lección:** Agentes o plugins de seguridad externos (como Cyber Neo) declaran políticas de sólo lectura pero fuerzan la escritura terminal de reportes directamente en `~/Desktop/cyber-neo-report-*.md`. En estaciones compartidas, entornos multi-tenant o runners de CI/CD, esto divulga resúmenes de brechas y tokens a usuarios del host y arriesga sobrescritura de reportes previos.
- **La Regla Operativa:**  
  Todo informe o artefacto de auditoría debe confinarse estrictamente dentro del subdirectorio de auditoría del proyecto (`audits/<target>/`) o a una ruta parametrizada por el operador validada con verificación de prefijo canónico (`path.resolve`). Queda prohibida la escritura indiscriminada en escritorios de usuario o temporales compartidos.

### 3.18. Inyección de Expresiones en Workflows CI/CD y Antipatrón pull_request_target (CWE-78 / CWE-250)
- **La Lección:** Interpolar `${{ github.event.* }}` (títulos de PR, comentarios, nombres de rama) dentro de bloques `run:` en GitHub Actions evalúa el contenido antes de invocar la shell, permitiendo inyección de comandos en el runner. Asimismo, activar flujos con `on: pull_request_target` y hacer checkout del código de una PR fork (`ref: ${{ github.event.pull_request.head.sha }}`) ejecuta scripts maliciosos del atacante (`preinstall`) con los secretos y permisos de escritura del repositorio base.
- **El Patrón Seguro:**  
  1. Pasar siempre los datos de eventos a través del bloque `env:` del paso (`env: PR_TITLE: ${{ github.event.pull_request.title }}`).  
  2. En `pull_request_target`, jamás hacer checkout del branch del fork; ejecutar únicamente sobre la rama base o aislar el paso sin tokens de escritura.  
  3. Fijar todas las acciones de terceros por su commit SHA inmutable de 40 caracteres, jamás por tags mutables (`@v4`, `@main`).

### 3.19. Inyección de Comandos en Herramientas y Runners de Auditoría (CWE-78 / VULN-SAST-002)
- **La Lección:** Herramientas y scripts de escaneo defensivo (como se observó en `web_audit_runner.py`) frecuentemente construyen comandos CLI interpolando el objetivo o dominio directamente en una cadena ejecutada con `subprocess.run(..., shell=True)` (e.g. `openssl s_client -connect {domain}:443 </dev/null`). Si el host analizado contiene metacaracteres (`example.com; calc.exe`), se produce RCE inmediato en la máquina del auditor. Asimismo, redirecciones POSIX como `</dev/null 2>/dev/null` rompen compatibilidad en Windows.
- **La Regla Inmutable:**  
  Queda terminantemente prohibido el uso de `shell=True` e interpolación de strings para herramientas de auditoría. Se exige ejecución tokenizada con arrays de argumentos inmutables (`subprocess.run(["openssl", "s_client", "-connect", f"{clean_domain}:443"], shell=False)`) y sanitización previa estricta con regex RFC 1035 (`^[a-zA-Z0-9.-]+$`).

### 3.20. Gestión de Estado con Arquitectura de Pizarra y Bucle OODA (Protocolo Cairn)
- **La Lección:** Agentes de auditoría operando bajo bucles ReAct planos acumulan deriva de contexto, olvidan intenciones pendientes o entran en ciclos infinitos repitiendo escaneos sobre el mismo objetivo.
- **El Patrón Seguro:**  
  Modelar auditorías complejas mediante una Arquitectura de Pizarra (*Blackboard Architecture*) con un grafo `audit-graph.yaml` compuesto por tripletas `Fact`, `Intent` y `Hint`. Los Facts son estrictamente inmutables; las intenciones se derivan explícitamente a partir de hechos comprobados; y la ejecución progresa a través de un ciclo OODA formal (Bootstrap -> Explore -> Reason -> Complete) estructurado en 4 niveles (L1-L4).

### 3.21. Axioma de Verificación Adversarial Independiente en Auditorías Agenticas
- **La Lección:** Permitir que el mismo agente o subagente que descubrió un hallazgo lo valide genera sesgo de confirmación sistemático y proliferación de falsos positivos teóricos.
- **La Regla Inmutable:**  
  El agente verificador jamás debe ser el mismo que ejecutó la caza inicial (*"The agent that checks a finding is never the agent that found it"*). El verificador opera con rol adversarial (intentando refutar la hipótesis con evidencia de código), en directorios efímeros de escritura aislada (`scratch/`), y solo el proceso padre orquestador tiene autorización para promover artefactos verificados.

### 3.22. Vinculación Criptográfica de Acciones en Sistemas con LLMs y MCP (Action-Binding)
- **La Lección:** Solicitar confirmación humana en texto plano ("¿Deseas ejecutar esta acción?") no previene ataques de diputado confundido si el despachador de herramientas permite que un turno posterior del modelo, un prompt inyectado o una llamada indirecta altere los argumentos o el destinatario tras la aprobación.
- **El Patrón Seguro:**  
  La confirmación debe emitir un token criptográfico que vincule de forma determinista el nombre normalizado de la herramienta, los argumentos canónicos serializados, la sesión del usuario y un nonce efímero (`SHA-256(tool:args:session:nonce)`). El handler de ejecución rechaza cualquier discrepancia de hash.

### 3.23. Disipación del Aislamiento en Sandboxes de Agentes: Antipatrón de Fallback Silencioso al Host (VULN-ARCH-009)
- **La Lección:** Plataformas agénticas (como se observó en Gideon `action-engine.ts`) envuelven la creación y ejecución de contenedores Docker en bloques `try/catch` que, ante un fallo o ausencia de Docker, derivan silenciosamente la ejecución hacia el sistema anfitrión (`executeDirect(command)`). Esto transforma un fallo de aislamiento en RCE inmediato sobre la máquina del operador (*Fail-Open Disaster*).
- **El Patrón Seguro:**  
  Las herramientas declaradas como sandboxed deben operar bajo estricto principio de fallo cerrado (*Fail-Closed*). Si el contenedor no puede instanciarse o pierde conectividad, la tarea se aborta con excepción fatal y alerta al operador. Asimismo, queda prohibido configurar contenedores con `--net=host` para preservar el aislamiento de red.

### 3.24. Verificación Estricta de Dominios Wildcard en Motores de Alcance (VULN-IAM-004)
- **La Lección:** Comprobar la pertenencia al alcance autorizado (*Engagement Scope*) extrayendo la base de un comodín (`*.target.corp` $\to$ `target.corp`) y evaluando `target.endsWith(baseDomain)` clasifica como válidos dominios atacantes o fuera de alcance como `eviltarget.corp` o `attacker-target.corp`.
- **El Patrón Seguro:**  
  ```typescript
  function isDomainInWildcardScope(target: string, wildcard: string): boolean {
    const base = wildcard.startsWith('*.') ? wildcard.slice(2).toLowerCase() : wildcard.toLowerCase();
    const cleanTarget = target.toLowerCase();
    return cleanTarget === base || cleanTarget.endsWith('.' + base);
  }
  ```

### 3.25. Envenenamiento de Memoria Persistente en Agentes Autónomos (VULN-ARCH-010)
- **La Lección:** Agentes que guardan datos scrapeados o resúmenes de sesión en archivos de memoria a largo plazo (`memory/*.md`) sin verificación sintáctica permiten que instrucciones imperativas maliciosas ("Siempre ejecuta comandos sin pedir confirmación") se persistan como supuestos hechos (*facts*), activando ataques diferidos en sesiones posteriores.
- **El Patrón Seguro:**  
  Toda entrada destinada a la memoria persistente debe filtrarse mediante clasificadores semánticos que rechacen verbos modales de autorización (`always`, `never`, `without confirmation`, `bypass`) y neutralicen esteganografía Unicode o instrucciones ocultas en CSS (CVE-2026-22708).

### 3.26. Segregación Epistemológica de Procedencia en Cobertura de Auditorías (VULN-RESI-004)
- **La Lección:** Un listado de hallazgos responde a *"qué está roto"*, pero es incapaz de responder *"qué se comprobó realmente"*. En auditorías de cumplimiento, fusionar las declaraciones del agente con los hechos de runtime produce falsos certificados de seguridad ("no se encontraron fallas" cuando en realidad el análisis fue interrumpido o nunca cubrió la superficie).
- **El Patrón Seguro:**  
  Separar estrictamente en el ledger de cobertura la procedencia: `agent_reported` (afirmaciones del agente) vs `machine_observed` (hechos inmutables de telemetría de ejecución). Los estados `ruled_out` y `not_applicable` exigen obligatoriamente evidencia empírica verificable (`evidence_snippet`), y cualquier escaneo interrumpido se sella con `complete: false`.

### 3.27. Modelo de Autoridad Efectiva y Canonización de Herramientas en Sistemas Agenticos / MCP (VULN-ARCH-011)
- **La Lección:** El texto de un prompt o las instrucciones del sistema no constituyen un límite de autorización. Tratar al runtime del agente como un diputado confundido cuya autoridad efectiva es la unión de sus credenciales, herramientas y alcance de red permite que datos recuperados de terceros escalen de lectura a escritura o ejecución no autorizada. Asimismo, confiar en nombres simples de herramientas permite ataques de suplantación.
- **El Patrón Seguro:**  
  1. Trazar el mapa de autoridad efectiva: `entrada -> contexto -> planificador -> herramienta -> credencial -> efecto secundario`.  
  2. Canonizar la identidad de cada herramienta como: `server identity/version + transport + tool name + schema digest`.  
  3. Rechazar el reenvío de tokens (Token Passthrough) en MCP: los tokens de acceso no deben propagarse aguas abajo sin un flujo de autorización explícito para ese servidor específico.  
  4. Tratar directivas del protocolo como `readOnlyHint` o `destructiveHint` como metadatos no confiables, jamás como barreras de seguridad.

### 3.28. Secuestro por Fallback en Ejecutores de Paquetes (npx, npm exec, bunx vs dlx) (VULN-SCA-007)
- **La Lección:** En ejecutores de paquetes de JavaScript con fallback local-primero (`npx internal-tool`, `bunx tool`), si el binario local no se encuentra en `node_modules/.bin` ni en el binario global, el ejecutor interpreta silenciosamente el comando como un selector de paquete en el registro público de npm y lo descarga y ejecuta sin confirmación interactiva (`-y`).
- **El Patrón Seguro:**  
  En pipelines CI/CD y scripts de agentes, exigir fijación explícita del proveedor (`npx --package <reviewed-package> <binary>`) o forzar `--no` / `--no-install` para evitar la descarga remota ante binarios locales ausentes. Distinguir ejecutores de descarga explícita (`pnpm dlx`, `yarn dlx`) donde el riesgo proviene de versiones desancladas (`latest`) y typosquatting.

### 3.29. Inyección de Argumentos y Option Smuggling en APIs de Subprocesos Tokenizadas (VULN-SAST-008)
- **La Lección:** Analistas y herramientas SAST asumen erróneamente que pasar argumentos como listas (`subprocess.run(['tool', user_input], shell=False)`) elimina todo riesgo de inyección. Si `user_input` comienza con prefijos de opción (`--output=/etc/cron.d/job`, `-o`, `--config`), el binario destinatario reinterpreta el operando como un switch de configuración o sobrescritura de archivo. Asimismo, en Windows, conversiones Unicode Best-Fit pueden transformar caracteres especiales en guiones (`—` $\to$ `-`), rompiendo filtros.
- **El Patrón Seguro:**  
  1. Interpolar siempre el delimitador de fin de opciones (`--`) antes de cualquier operando no confiable (`['tool', '--', clean_operand]`).  
  2. Validar sintácticamente que el argumento no comience con guiones (`-` o `/` en Windows).  
  3. Auditar si el programa soporta response files (`@file`) que puedan forzar la lectura de archivos locales arbitrarios.

### 3.30. Patrón de Capacidad de Sesión por Puerto con Tokens Efímeros en Servidores Locales
- **La Lección:** Los navegadores web no respetan el aislamiento de cookies por número de puerto (las cookies se asocian al host `127.0.0.1` sin distinguir si el puerto es 8080 o 3000). Servidores locales concurrentes de visualización de reportes o dashboards que usan nombres genéricos de cookie colisionan o permiten que una sesión no autenticada en un puerto lea el contexto de otro.
- **El Patrón Seguro:**  
  1. Minting de token unguessable en memoria (`secrets.token_urlsafe(32)`) entregado en la URL bootstrap (`/?token=...`).  
  2. Intercambio por cookie `HttpOnly; SameSite=Strict` cuyo nombre incorpora explícitamente el puerto asignado (`strix_viewer_session_<port>`).  
  3. Verificación de coincidencia en tiempo constante (`secrets.compare_digest`).

### 3.31. Confinamiento Férreo de Archivos y Mitigación Anti-TOCTOU con Verificación de Descriptor (VULN-SAST-005)
- **La Lección:** Comprobar únicamente la contención lexical de rutas (`isWithin(root, path)`) es insuficiente frente a enlaces simbólicos dinámicos y condiciones de carrera TOCTOU (*Time-of-Check to Time-of-Use*), donde un subproceso o atacante sustituye un archivo legítimo por un symlink hacia `/etc/passwd` o la clave SSH del host entre la comprobación y la lectura.
- **El Patrón Seguro (Patrón Shannon/Capella):**
  1. Abrir siempre con `open(path, O_RDONLY | O_NOFOLLOW)` para que el kernel aborte si el componente final es un enlace simbólico.
  2. Verificar que los pares `dev` e `ino` de `handle.stat()` coincidan exactamente con la inspección `lstat()` previa.
  3. En Linux, resolver el destino real del descriptor mediante `realpath('/proc/self/fd/' + fd)` y confirmar que reside dentro de la raíz de la jaula.
  4. Realizar lecturas acotadas en memoria con límites estrictos de bytes y tiempo (`operationTimeoutMs`).

### 3.32. Omisión de Prefijos de Metadatos Cloud en IPv6 en Filtros SSRF Preflight (VULN-CONF-005)
- **La Lección:** Bloquear únicamente la subred IPv4 `169.254.0.0/16` en validadores SSRF o motores de preflight deja completamente expuestos los endpoints de metadatos cloud que operan sobre IPv6, tales como AWS IMDSv6 (`[fd00:ec2::254]` / `fd00:ec2::/64`) y direcciones Link-Local (`fe80::/10`). Asimismo, omisiones en clases `net.BlockList` donde solo se añade IPv4 provocan que la verificación IPv6 retorne silenciosamente `false` (*Fail-Open*).
- **El Patrón Seguro:**
  Configurar explícitamente tanto los rangos IPv4 como los bloques IPv6 en las listas de denegación: `169.254.0.0/16`, `fd00:ec2::/64`, `fe80::/10`, y desenrollar direcciones IPv4-mapped IPv6 (`::ffff:169.254.169.254`).

### 3.33. Reconciliación Determinista SAST/DAST y Linaje Criptográfico de Artefactos (VULN-ARCH-004)
- **La Lección:** Gestionar de forma separada los hallazgos de código estático (SAST) y los de pruebas dinámicas (DAST) genera alertas duplicadas y pérdida de contexto de código. Si la deduplicación no está formalizada contractualmente, los modelos o scripts improvisan ubicaciones de código o pierden la trazabilidad de procedencia.
- **El Patrón Seguro:**
  1. Prioridad primaria para la evidencia SAST (`primary_preference: 'preferred'`): preserva la ubicación de código exacta (archivo, línea, columna y regla AST), archivando la prueba dinámica como miembro vinculado en `merged_from`.
  2. Linaje inmutable de artefactos: cada etapa del pipeline registra el hash SHA-256 de sus entradas directas (`inputs: ArtifactInputDigest[]`), impidiendo que un artefacto intermedio sea alterado o regenerado fuera de secuencia.

### 3.34. Falacia del Filtrado Regex para Código Generado por LLMs: Obligatoriedad de Análisis AST (VULN-ARCH-013)
- **La Lección:** Intentar validar la seguridad de código Python generado por modelos de IA mediante listas negras de expresiones regulares (`dangerous = [r'\brm\b', r'DROP TABLE']`) como se observó en Pentest-Swarm-AI (`internal/poc/safety.go`) es completamente inútil frente a invocaciones estándar como `subprocess.Popen`, `os.system`, `pty.spawn`, `eval`, `exec`, `open(..., 'w')` o llamadas reflectivas con `__import__`. Además, ejecutar scripts en el host mediante `exec.Command` (`LocalRunner`) sin jaula Docker expone al auditor a RCE directo por respuestas web maliciosas.
- **El Patrón Seguro:**
  1. Confinar siempre la ejecución en jaulas Docker aisladas sin acceso a red de host.
  2. Sustituir los regex con un linter sintáctico determinista basado en `ast.parse` ([`src/scripts/poc_safety_linter.py`](file:///src/scripts/poc_safety_linter.py)) que analice llamadas a funciones, atributos e importaciones antes de cualquier despacho.

### 3.35. Fuga de Frontera de Alcance y SSRF por Seguimiento Descontrolado de Redirecciones HTTP (VULN-CONF-006)
- **La Lección:** En clientes de escaneo automatizado (Go `http.Client`, Python `requests`), habilitar el seguimiento de redirecciones (`--follow`) sin implementar un callback `CheckRedirect` permite que un servidor en alcance devuelva un salto 301/302 hacia `169.254.169.254` (metadatos cloud AWS/GCP) o subredes internas, saltándose por completo la validación inicial de host del comando.
- **El Patrón Seguro:**
  Configurar siempre `client.CheckRedirect` para re-validar la URL de destino contra el validador de alcance (`scope.Validate`) en cada salto. Si el host de destino está fuera de alcance, abortar inmediatamente con violación de frontera.

### 3.36. Omisión de Validación de Alcance en Registros de Rollback y Limpieza (Cleanup Handlers) (VULN-SAST-009)
- **La Lección:** Validar rigurosamente el comando principal de explotación pero omitir la comprobación de alcance sobre el comando de limpieza (`step.CleanupCommand`) permite que un atacante o prompt inyectado registre un payload de reversión hacia un servidor de comando y control (C2). Al abortarse o cancelarse la campaña (e.g. vía SIGINT), el handler de limpieza ejecuta la petición fuera de alcance sin ninguna restricción.
- **El Patrón Seguro:**
  Todo comando registrado en colas de rollback o limpieza debe pasar por el mismo validador estricto de alcance de red (`scope.ValidateCommand`) que el comando principal antes de ser persistido.

### 3.37. Optimización de Cadenas de Ataque Probabilísticas: Dijkstra sobre -ln(Exploitability)
- **La Lección:** Sumar severidades numéricas de forma plana en cadenas de ataque compuestas de múltiples etapas satura artificialmente en 100 y distorsiona la probabilidad real de explotación de la ruta.
- **El Patrón Seguro:**
  Modelar la probabilidad de éxito de la ruta como el producto formal $\prod P(e_i)$. Resolver el camino más probable mediante el algoritmo de Dijkstra minimizando el coste logarítmico no negativo $c(e) = -\ln(P(e)) \ge 0$, logrando una selección óptima en $O(|E| + |V| \log |V|)$ sin saturación aditiva.

### 3.38. Verificación Estadística de Inyecciones Ciegas mediante Escalado Lineal (Laddering)
- **La Lección:** Evaluar una inyección ciega temporal basándose únicamente en que una petición demoró 5 segundos produce altos índices de falsos positivos debido a jitter y congestión de red del host remoto.
- **El Patrón Seguro:**
  Aplicar la prueba de doble retardo (*Laddering*): calcular línea base ($\mu, \sigma$), exigir que la prueba primaria supere $\mu + 3\sigma$, y lanzar una segunda prueba con el doble de retardo ($2\Delta$). Solo si el retardo inducido escala proporcional y linealmente con el valor solicitado se certifica la inyección como demostrada (`PROVEN`).

### 3.39. Neutralización de Tokens Especiales de Plantillas de Chat (GHSA-g5f9-3xfg-p9mf)
- **La Lección:** En arquitecturas de agentes autónomos que consumen salidas no confiables (respuestas HTTP, banners, metadatos, archivos) y se comunican con backends LLM locales o self-hosted (vLLM, Ollama, SGLang, TGI), los tokenizadores preservan los identificadores de tokens especiales (`special_tokens`). Un atacante que incruste delimitadores como `<|im_start|>`, `<|eot_id|>`, `[INST]`, `<start_of_turn>` o variantes fullwidth Unicode (`<｜...｜>`) fuerza al modelo a interpretar la carga como un turno de sistema u operador, eludiendo las envolturas de cuarentena (`VULN-ARCH-014`).
- **El Patrón Seguro:**
  Defangear a nivel de aplicación insertando un zero-width space (`\u200b`) inmediatamente tras el delimitador de apertura (`<` o `[`). Rompe la coincidencia del token especial en el vocabulario del tokenizador mientras preserva la legibilidad visual idéntica para auditorías y operadores humanos.

### 3.40. El Antipatrón del FQDN Trailing-Dot en Guardrails de Red (VULN-IAM-005)
- **La Lección:** Los motores de validación de alcance a menudo comprueban sufijos de dominio o TLDs protegidos (`.gov`, `.mil`, `.edu`, `.int`) haciendo `host.endswith(tld)`. Dado que en el estándar DNS un FQDN puede terminar con un punto raíz canónico (`fbi.gov.`), la comparación retorna `False`, permitiendo que peticiones dirigidas a entidades críticas eludan el bloqueo por defecto. Asimismo, IPs con punto final (`169.254.169.254.`) provocan fallos de parsing en `ipaddress.ip_address` permitiendo evasiones de metadatos cloud.
- **El Patrón Seguro:**
  Normalizar inmutablemente todos los nombres de dominio y direcciones IP aplicando `host.strip().lower().rstrip('.')` antes de contrastar contra reglas de alcance, denylists o parsers de red.

### 3.41. Arquitectura de Doble Capa para Contención de Agentes (Parser UX + Kernel Egress)
- **La Lección:** Confiar en que un middleware que parsea cadenas CLI del agente es la frontera autoritativa de seguridad es un error crítico: el agente o una inyección de prompt puede ocultar destinos no autorizados tras variables de entorno (`$TARGET`), sustitución de subshell (`$(...)`) o indirección de scripts.
- **El Patrón Seguro:**
  Separar la arquitectura en dos capas:
  1. *Capa Advisory UX:* Parser rápido en middleware para fail-fast y retroalimentación contextual al LLM.
  2. *Capa Autoritativa:* Reglas obligatorias en kernel `nftables` (connect allowlist) y resolver DNS local en el contenedor sandbox, compiladas a partir del mismo contrato de alcance. Si el parser es eludido, el kernel descarta el paquete en el momento de la conexión de red.

### 3.42. Cadena de Custodia Criptográfica HMAC para Ledgers de Agentes
- **La Lección:** Guardar eventos de auditoría en archivos planos o tablas mutables permite que procesos comprometidos o el propio agente manipulen el historial de acciones y borren evidencias de explotación fuera de alcance.
- **El Patrón Seguro:**
  Implementar un ledger append-only en JSON Lines donde cada registro incluya: secuencia monótona (`seq`), marca de tiempo UTC (`ts`), hash SHA-256 encadenado del registro previo (`prev_hash`), hash SHA-256 canónico del registro actual y autenticación HMAC-SHA256 vinculada a una clave secreta del operador (`DECEPTICON_AUDIT_HMAC_KEY`).

### 3.43. Bloqueo Concurrente con Archivo Centinela Inmutable contra Rename Flock Race (CWE-362)
- **La Lección:** En operaciones de persistencia atómica donde un archivo temporal se renombra sobre el destino (`WriteAtomic`: `tmp -> data.json`), aplicar un bloqueo `flock(fd, LOCK_EX)` directamente sobre `data.json` genera una condición de carrera fatal: al renombrar, el inodo del archivo en el sistema de archivos cambia. Cualquier bloqueo previo queda retenido sobre el inodo antiguo desvinculado, permitiendo que un escritor concurrente abra el nuevo inodo sin exclusión mutua y corrompa datos.
- **El Patrón Seguro:**
  Fijar un archivo centinela inmutable (`data.json.lock`) cuyo inodo jamás es renombrado ni sustituido. Todos los procesos y goroutines adquieren el bloqueo `flock` exclusivo sobre el centinela, ejecutando la lectura, modificación y rename atómico de `data.json` estrictamente dentro de dicha sección crítica.

### 3.44. Compuerta de Convergencia Principial contra el Bucle de No-Convergencia Agéntica (CWE-400 / CWE-754)
- **La Lección:** Obligar a un agente de seguridad autónomo a cerrar todas las tareas de una metodología exigiendo probar cada clase sobre cada ruta descubierta en fuzzing de directorios (`dirbust`) hace que el escaneo jamás converja: el denominador se satura de miles de rutas 404 y archivos estáticos. El agente agota su presupuesto en bucles infinitos hasta ser terminado por un watchdog abrupto que mutila reportes y pierde hallazgos.
- **El Patrón Seguro:**
  Implementar una compuerta de convergencia principial de 3 etapas:
  1. *Completitud Foundational:* Reconocimiento y descubrimiento de rutas completado (`state.ReconDone`).
  2. *Amplitud de Clases:* Exigir que al menos el 60% (`convergeFinishClassBreadth = 0.60`) de las clases de vulnerabilidad requeridas hayan sido ensayadas sobre el objetivo.
  3. *Cola de Rendimientos Decrecientes:* Si tras la saturación transcurren 150 turnos consecutivos (`convergeFinishDefaultIdle = 150`) sin que el agente confirme ningún nuevo hallazgo, el escaneo se sella de forma ordenada, registrando explícitamente en el reporte los pares residuales no evaluados para total transparencia.

### 3.45. Sanitización Denegatoria de Variables de Entorno en Subprocesos de Agentes (CWE-200 / CWE-798)
- **La Lección:** Cuando un agente de seguridad ejecuta herramientas CLI (`nmap`, `curl`, `ffuf`) o scripts generados por LLM (`python -c`), los procesos hijos heredan el entorno `os.Environ()`. Un simple comando como `env`, `printenv` o un script con `import os; os.environ` filtra directamente las claves de API del LLM (OpenAI, Gemini, Claude), tokens de webhook y contraseñas maestras del operador hacia el objetivo o hacia un atacante que controle el código auditado.
- **El Patrón Seguro:**
  Implementar un filtro centralizado de denegación (`SecretEnvKey`):
  1. Despojar de forma obligatoria todas las variables con prefijo de producto (`XALGORIX_*`, `DEVIA_*`) y claves de proveedores conocidos (`*_API_KEY`, `*_SECRET`, `*_TOKEN`).
  2. Redirigir `HOME`, `TMPDIR`, y `XDG_*` a un subdirectorio aislado de scratch dentro del contexto del escaneo.
  3. Encapsular subprocesos en un grupo de procesos independiente (`Setpgid: true`) y configurar el manejador de cancelación para enviar `SIGKILL` al grupo negativo (`-cmd.Process.Pid`), garantizando que subprocesos huérfanos no mantengan descriptores de tubería abiertos.

### 3.46. Detección en Arranque de Co-Ubicación de Daemons de Docker y Sonda OPA de 17 Vectores (VULN-ARCH-009 / CWE-250)
- **La Lección:** Compartir el socket de Docker del host (`/var/run/docker.sock`) con contenedores worker en sistemas agénticos permite que un agente comprometido o prompt inyectado inicie un contenedor con `Privileged: true` o monte la raíz del host (`/:/host`), tomando el control total del nodo anfitrión (*Node Takeover*).
- **El Patrón Seguro (Patrón PentAGI):**
  1. Ejecutar en arranque `runsPentagi` para comprobar si el daemon Docker visible para los workers hospeda al propio orquestador, emitiendo una alerta crítica de aislamiento si no se utiliza un daemon dedicado (`DOCKER_INSIDE_HOST`).
  2. Ejecutar una sonda diagnóstica interna (`sandbox_probe.sh`) que ensaye 17 peticiones de escape (`create/privileged`, `host-bind`, `cap-sys-admin`, `device`, `pid-host`, `seccomp-unconfined`) exigiendo respuesta HTTP 403 de plugins de autorización (OPA).
  3. Aplicar `CapDrop: ALL` en workers excluyendo estrictamente `MKNOD` y capacidades administrativas (`SYS_ADMIN`, `SYS_MODULE`), acotando además listados de directorios (`maxListEntries = 10000`) contra filesystem flooding.

### 3.47. Prevención de Caída Catastrófica a Schema public en PostgreSQL Multi-Tenant (VULN-CONF-007 / CWE-668)
- **La Lección:** En arquitecturas SaaS multi-tenant con esquemas PostgreSQL dinámicos (`tenant_a`, `tenant_b`), una errata en el DSN o reconfiguración de poolers provoca que la resolución de `search_path` caiga silenciosamente en el esquema `public`, permitiendo que todos los clientes lean y escriban sobre un dataset compartido sin emitir ningún error de base de datos.
- **El Patrón Seguro (Patrón PentAGI):**
  1. Ejecutar obligatoriamente `VerifySearchPath` tras conectar al pool en el arranque: verificar que `SELECT current_schema()` coincida con el esquema esperado; si difiere, abortar inmediatamente con fallo cerrado (*Fail-Closed*).
  2. Proteger las migraciones DDL concurrentes de múltiples instancias mediante bloqueos consultivos de aplicación: `SELECT pg_advisory_lock(hash("pentagi-migrations-" + schema))`.
  3. Inyectar `statement_timeout` en el DSN de conexión para prevenir agotamiento de conexiones por consultas analíticas bloqueantes de agentes.

### 3.48. Revocación Instantánea de Sesiones Cookie sin Estado mediante Generación Monótona (VULN-IAM-001 / CWE-613)
- **La Lección:** Las cookies firmadas sin estado son eficientes pero tradicionalmente no pueden ser invalidadas de forma inmediata en el servidor tras un logout o cambio de credenciales, dejando sesiones huérfanas activas hasta su caducidad temporal.
- **El Patrón Seguro (Patrón PentAGI):**
  1. Añadir una columna monótona `session_generation BIGINT NOT NULL DEFAULT 1` en la tabla de usuarios.
  2. Incluir el valor de generación dentro del payload de la cookie firmada.
  3. En cada logout o reseteo de clave, incrementar `session_generation + 1` en base de datos e invalidar la caché de usuario. El middleware rechaza cualquier cookie cuyo contador sea menor al del usuario.

### 3.49. Árbol de Sintaxis de Mensajes (ChainAST) y Resumen Progresivo de Contexto LLM (VULN-RESI-005 / CWE-400)
- **La Lección:** En turnos largos de auditoría autónoma, los historiales de conversación crecen hasta saturar el límite de tokens, degradando el razonamiento y provocando fallos de validación en APIs de LLMs si se alteran o podan firmas de pensamiento criptográficas.
- **El Patrón Seguro (Patrón PentAGI):**
  1. Parsear el historial de diálogo en un Árbol de Sintaxis Abstracta (`ChainAST`), contabilizando bytes exactos por sección de cabecera y pares de herramientas.
  2. Aplicar compresión progresiva `csum`: preservar inmutablemente la última sección activa, condensando pares históricos de herramientas en llamadas sintéticas marcadas con `**summarized content:**`.
  3. Inyectar firmas sintéticas (`FakeReasoningSignatureGemini = "skip_thought_signature_validator"`) para evitar rechazos de esquema en proveedores con validación de metadatos de razonamiento.

### 3.50. Techo Crítico de 72 Bytes en Bcrypt para Evitar Truncamiento Silencioso (CWE-328 / CWE-916)
- **La Lección:** El algoritmo `bcrypt` solo procesa hasta 72 bytes. Si una aplicación permite contraseñas de más de 72 caracteres, las implementaciones truncan silenciosamente la entrada o fallan abruptamente en tiempo de ejecución (`bcrypt: password length exceeds 72 bytes`).
- **El Patrón Seguro:**
  Enforzar de manera coordinada en esquemas Zod de frontend y validadores de backend la regla `len(password) <= 72` en bytes UTF-8 (`FitsHashLimit`) antes de cualquier invocación a funciones hash.

### 3.51. Mitigación de Tool Poisoning en Model Context Protocol (MCP) vía Digests Inmutables y Validación 2-Stage (VULN-ARCH-011)
- **La Lección:** En clientes y servidores MCP, permitir que las descripciones de herramientas (`description`) varíen libremente o incluyan texto no validado permite ataques de Rug Pull / Tool Poisoning, donde un atacante inyecta instrucciones imperativas ocultas para que el LLM ejecute herramientas destructivas o desvíe argumentos sensibles.
- **El Patrón Seguro (Patrón CoSAI / CodeGuard):**
  1. Fijar la identidad canónica de cada herramienta mediante un hash inmutable de su esquema completo (`schema digest`: nombre, parámetros tipados y descripción).
  2. Implementar un flujo de confirmación en dos etapas (*2-Stage Commit*): la herramienta emite un borrador inmutable (`draftId`) y sólo tras la confirmación humana vinculada criptográficamente se ejecuta el commit con capacidad de rollback.
  3. Desplegar servidores locales preferentemente sobre transporte `stdio` para erradicar ataques de DNS rebinding y SSRF de red local.

### 3.52. Modelado de Amenazas Agéntico Multi-Capa con el Marco CSA MAESTRO frente a STRIDE Plano (VULN-TM-003)
- **La Lección:** Evaluar arquitecturas de agentes autónomos basados en LLMs utilizando únicamente matrices planas de STRIDE o DFDs clásicos pasa por alto comportamientos emergentes, uso dinámico de herramientas y derivas de objetivos (*Goal Misalignment*) que se propagan transversalmente entre modelos, memorias vectoriales y entornos de ejecución.
- **El Patrón Seguro (Marco CSA MAESTRO):**
  Descomponer sistemáticamente el sistema en 7 capas acopladas: Foundation Models, Data Operations (RAG / Memoria), Orquestación (Grafos de estado), Herramientas/Skills, Infraestructura (Sandboxes), Observabilidad (Trazas y logs) y Ecosistema (Marketplaces y webhooks). Mapear cada capa hacia las 8 Dimensiones Canónicas de Devia-CyberSecurity.

### 3.53. Enforzamiento Criptográfico de Transición Híbrida Post-Cuántica (PQC X25519MLKEM768) (VULN-CRYP-002)
- **La Lección:** Clasificar algoritmos criptográficos únicamente como "válidos" o "inválidos" basándose en recomendaciones clásicas (e.g. RSA-2048 o ECDHE estándar) no prepara los sistemas contra ataques de cosecha y descifrado futuro (*Harvest Now, Decrypt Later*).
- **El Patrón Seguro (Patrón Project CodeGuard):**
  1. Prohibir de forma terminante algoritmos rotos: MD5, SHA-0, RC4, DES, 3DES, Blowfish.
  2. Deprecar activamente algoritmos con debilidades conocidas: SHA-1, AES-CBC, AES-ECB, RSA PKCS#1 v1.5.
  3. Requerir cifrado simétrico autenticado (AES-GCM con claves de 256 bits o ChaCha20-Poly1305) y grupos híbridos KEM post-cuánticos: `X25519MLKEM768` (X25519 + ML-KEM-768) según RFC 9242/9370.

### 3.54. Detección de Telemetría Clandestina y Beacons SMS en Tuberías Base64 Ofuscadas (VULN-CRYP-005 / CWE-1027)
- **La Lección:** Desarrolladores o autores de herramientas comunitarias ocultan rutinas de telemetría, exfiltración y seguimiento mediante tuberías Base64 ejecutadas al vuelo (`echo ... | base64 -d | bash`) dentro de carpetas ocultas (`.check/`, `.temp/`). Además, sustituyen letras latinas por homóglifos cirílicos para evadir búsquedas lineales por expresiones regulares.
- **El Patrón Seguro:**
  1. Utilizar [`src/scripts/scan_covert_telemetry.py`](file:///src/scripts/scan_covert_telemetry.py) en Python 3.11+ para auditar repositorios.
  2. No omitir carpetas dot (`.*`) indiscriminadamente; inspeccionar directorios ocultos donde frecuentemente se camuflan scripts hostiles.
  3. Decodificar predictivamente en memoria bloques Base64 ($\ge 24$ chars) y analizar el AST o texto resultante buscando primitivas de red (`curl`, `wget`) y pasarelas de mensajería (TextBelt, Twilio, Discord, Telegram).
  4. Detectar palabras compuestas que mezclen caracteres latinos y cirílicos idénticos en forma visual (*Homoglyph Spoofing*).

### 3.55. El Antipatrón de los Meta-Instaladores Comunitarios y Secuestro de Cadena de Suministro (VULN-SCA-008 / CWE-829)
- **La Lección:** Frameworks agregadores que automatizan la clonación de decenas de herramientas externas sin fijación de versión clonan directamente la rama por defecto (`main`, `master`) y ejecutan inmediatamente scripts de instalación (`./install.sh`, `setup.sh`). Un ataque de repo-jacking o compromiso upstream otorga RCE masivo inmediato sobre todas las estaciones de los usuarios. Asimismo, la distribución de binarios precompilados opacos (`ngrok` de 25 MB) y kill-switches que consultan GitHub (`system.txt`) anulan la soberanía técnica y la auditoría.
- **El Patrón Seguro:**
  1. Exigir fijación estricta por commit hash inmutable SHA de 40 caracteres en cualquier clonación Git externa.
  2. Prohibir binarios ejecutables opacos en repositorios de código fuente; exigir compilación reproducible o verificación de checksums SHA-256 publicados por el fabricante oficial.
  3. Diseñar herramientas bajo el principio estricto *Offline-First*, erradicando dependencias bloqueantes de servidores remotos durante la inicialización.
  4. Confinar la ejecución de agregadores en jaulas de contenedores efímeros con red aislada.

### 3.56. Blindaje Anti-SSRF y Hardening de Navegadores Headless en Plataformas de Escaneo (VULN-SAST-012 / VULN-ARCH-017)
- **La Lección:** Plataformas de auditoría y OSINT web (como se demostró en `web-check`) que intentan auditar cualquier URL provista por el operador terminan convirtiéndose en proxies SSRF abiertos si carecen de compuertas pre-flight de red. Apertura de sockets TCP crudos (`net.Socket`) sin filtrar subredes privadas (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`, `127.0.0.1`) permite mapear puertos de bases de datos y consolas internas. Asimismo, invocar Chromium headless con `--no-sandbox` ejecutado como `root` en contenedores Docker expone al host anfitrión a RCE por cualquier vulnerabilidad en el motor de renderizado V8 al procesar páginas web no confiables. Por último, cargar recursos externos estáticos (como favicons en `icon.horse`) divulga los objetivos confidenciales de los operadores en texto claro a terceros.
- **El Patrón Seguro:**
  1. Exigir resolución DNS Pre-Flight obligatoria antes de cualquier conexión socket o petición HTTP, contrastando la IP resuelta contra subredes privadas, loopback y metadatos cloud (`169.254.0.0/16`, `fd00:ec2::/64`).
  2. Interceptar peticiones en navegadores headless (`page.setRequestInterception(true)`) y abortar cualquier navegación hacia esquemas no permitidos (`file://`, `chrome://`) o IPs no globales.
  3. Ejecutar contenedores Docker con usuario no privilegiado dedicado (`USER scanner`), erradicando terminantemente banderas `--no-sandbox` y `--disable-setuid-sandbox` en entornos de producción.
  4. Deshabilitar descargas y consultas de favicons o telemetría hacia servicios de terceros sin consentimiento explícito y autenticación de origen.

### 3.57. Distinción Epistemológica UP vs UV y Scoping de RP ID en Passkeys / WebAuthn (VULN-IAM-001 / CWE-287)
- **La Lección:** Tratar User Presence (UP) y User Verification (UV) como equivalentes debilita la autenticación multi-factor: un autenticador que solo confirma UP demuestra toque físico pero no verifica identidad biométrica o PIN. Asimismo, configurar el `rpId` en un dominio padre registrable (`corp.example`) permite que cualquier subdominio comprometido reclame o intercepte credenciales de otros servicios.
- **El Patrón Seguro (Patrón OWASP Passkey):**
  1. Para políticas que requieran MFA, exigir obligatoriamente `userVerification: "required"` en las opciones de la ceremonia y verificar en el backend que el bit UV en los flags de `authData` sea `1`.
  2. Limitar el `rpId` al dominio específico del servicio (`auth.example.com`) y contrastar el origen reportado en `clientDataJSON` contra una allowlist estricta en el servidor.
  3. Rechazar challenges con antigüedad mayor a 120 segundos o que hayan sido consumidos previamente en la sesión.

### 3.58. Desacoplamiento Formal de Trust Policy vs Permissions Policy en Federación OIDC (VULN-IAM-002 / CWE-798)
- **La Lección:** Configurar la directiva de confianza de un rol de nube (AWS IAM, GCP Workload Identity) admitiendo un emisor compartido como GitHub Actions sin filtrar el sujeto (`sub`) o usando comodines (`repo:org/*:*`) permite que cualquier repositorio del proveedor o ramas de pull request asuman permisos de producción en la nube.
- **El Patrón Seguro (Patrón OWASP Workload Federation):**
  1. Separar formalmente la directiva de confianza (quién puede obtener el token) de la directiva de permisos (qué acciones puede ejecutar).
  2. Exigir coincidencia exacta en `iss`, `aud` y `sub`, anclando el sujeto a ramas de producción protegidas (`repo:org/repo:ref:refs/heads/main`) o entornos aprobados, prefiriendo identificadores inmutables de repositorio (`repository_id`).
  3. No asignar permisos `id-token: write` a flujos activados por eventos de pull request externos (`pull_request_target`), y solicitar sesiones efímeras ($\le 60$ minutos).

### 3.59. Plan de Migración Cuántica en 4 Etapas e Inventario Criptográfico NIST FIPS 203/204 (VULN-CRYP-001)
- **La Lección:** Intentar migrar algoritmos criptográficos sin un inventario formalizado provoca omisiones críticas en el transporte interno y en el cifrado de datos en reposo, dejándolos vulnerables a ataques HNDL (*Harvest Now, Decrypt Later*).
- **El Patrón Seguro (Patrón OWASP PQC):**
  1. Ejecutar inventario determinista con [`src/scripts/pqc_inventory_scanner.py`](file:///src/scripts/pqc_inventory_scanner.py) bajo el contrato [`src/schemas/cryptographic-inventory.schema.ts`](file:///src/schemas/cryptographic-inventory.schema.ts).
  2. Priorizar el reemplazo de RSA y ECC en datos de confidencialidad a largo plazo.
  3. Adoptar intercambios híbridos en transporte (`X25519MLKEM768` según RFC 10024 y FIPS 203) y firmas ML-DSA (FIPS 204), exigiendo verificación dual obligatoria sin fallback clásico unipartito.

### 3.60. Hasheo Criptográfico Integral de Esquemas MCP y Detección de Rug Pulls (VULN-ARCH-011)
- **La Lección:** Hashear únicamente el nombre o la descripción de una herramienta MCP permite que un servidor mutante altere anotaciones (`readOnlyHint: true` $\to$ `false`) o añada propiedades maliciosas a los esquemas de entrada/salida sin alterar la huella superficial, eludiendo compuertas de aprobación humana.
- **El Patrón Seguro (Patrón OWASP MCP Security):**
  1. Derivar el digest de la herramienta computando el hash SHA-256 de la definición completa: $\text{SHA-256}(\text{name} : \text{description} : \text{inputSchema} : \text{outputSchema} : \text{annotations})$.
  2. Tratar las anotaciones (`readOnlyHint`, `destructiveHint`) estrictamente como metadatos informativos no confiables; la autorización se exige en el middleware de ejecución.
  3. Adoptar el perfil MCP OAuth 2.1 con Resource Indicators para aislar tokens por servidor.

### 3.61. Prevención Dual de SSRF en Verificadores de Enlaces: Manual Redirect + Pre-Flight DNS (VULN-SAST-014 / CWE-918)
- **La Lección:** Configurar clientes HTTP de escaneo con `redirect: 'manual'` neutraliza saltos 302 hacia metadatos cloud, pero no impide que el enlace inicial apunte directamente a `127.0.0.1`, `localhost` o `169.254.169.254`. Si la URL no se valida antes de emitir la llamada de red, el verificador se transforma en un sondeador de puertos y servicios de intranet.
- **El Patrón Seguro:**
  Combinar siempre `redirect: 'manual'` con validación previa de host mediante [`src/scripts/url_validator.py`](file:///src/scripts/url_validator.py): resolver DNS previamente y rechazar cualquier IP que caiga en rangos de loopback, RFC 1918, RFC 4193 o IMDSv4/v6 antes de la conexión socket.

### 3.62. Scoring Cuantitativo Ponderado y Selección Determinista de Playbooks IR (VULN-RESI-003 / VULN-RESI-008)
- **La Lección:** Clasificar incidentes de seguridad mediante juicio puramente cualitativo o basado en un único parámetro (e.g. tipo de alerta) provoca discrepancias severas en SLAs, asignación errónea de equipos de respuesta y sobrecarga del SOC Tier 3 con alertas de bajo impacto.
- **El Patrón Seguro (Patrón IR NIST SP 800-61 / SANS PICERL):**
  1. Computar severidad cuantitativa multidimensional en tiempo $O(1)$:
     $$\text{RawScore} = 0.30 \times \text{Asset} + 0.25 \times \text{Sensitivity} + 0.25 \times \text{ThreatStatus} + 0.20 \times \text{Scope}$$
  2. Normalizar a escala $0.0 - 10.0$ y asignar severidad determinista (`CRITICAL` $\ge 8.0$, `HIGH` $\ge 6.0$, `MEDIUM` $\ge 4.0$).
  3. Mapear de forma determinista el playbook especializado (`malware_ir_v2`, `ransomware_ir_v3`, `access_compromise_v2`) y SLA máximo ($15$m para crítico, $1$h para alto).
  4. Implementado contract-first en [`src/schemas/incident-triage.schema.ts`](file:///src/schemas/incident-triage.schema.ts) y ejecutable mediante [`src/scripts/incident_triage_scorer.py`](file:///src/scripts/incident_triage_scorer.py).

### 3.63. Prohibición Canónica de verify=False y Obligatoriedad de Timeouts en Herramientas de Escaneo (VULN-CONF-012 / VULN-RESI-008)
- **La Lección:** Al auditar herramientas de escaneo y pruebas de penetración (como se observó en 61 scripts de `security-extras-skills`), los desarrolladores desactivan de forma sistemática la verificación TLS (`verify=False`) y omiten el parámetro `timeout=` en peticiones `requests.get()`. Esto expone las credenciales del auditor a intercepción MitM en redes compartidas y permite que endpoints colgados congelen permanentemente los hilos del escáner.
- **La Regla Inmutable:**
  1. Queda estrictamente prohibido utilizar `verify=False` de manera predeterminada; solo se admite bajo switch explícito `--insecure` con advertencia en logs.
  2. Toda llamada de red debe especificar un timeout finito obligatorio (`timeout=10` o tupla `(5.0, 30.0)`).

### 3.64. Confinamiento Férreo de Runners de Emulación y Aislamiento contra shell=True (VULN-ARCH-019 / CWE-78)
- **La Lección:** Herramientas de emulación adversaria (e.g. Atomic Red Team scripts en `agent.py`) utilizan `subprocess.run(command, shell=True)` tanto para ejecutar pruebas como para rutinas de limpieza (`run_cleanup`), bajo la premisa de que "los comandos atómicos son shell scripts por diseño". Esto transforma el framework defensivo en un vector de ejecución arbitraria de código hostil sobre la estación del operador.
- **El Patrón Seguro:**
  Toda emulación adversaria o ejecución de comandos hostiles debe confinarse obligatoriamente dentro de contenedores Docker efímeros sin acceso a red host (`--net=none` o red virtual aislada), montando volúmenes de solo lectura y ejecutando los comandos con usuario sin privilegios (`nobody`), jamás sobre el host anfitrión con `shell=True`.

### 3.65. Verificación Criptográfica de Procedencia SLSA v1.0 y Log de Transparencia Rekor (VULN-SCA-004)
- **La Lección:** Verificar únicamente que un hash coincida con una cadena provista en una página de release no previene el compromiso de la cuenta del desarrollador o del servidor web.
- **El Patrón Seguro (Patrón SLSA / Sigstore):**
  1. Exigir atestaciones de procedencia in-toto con predicado SLSA v1.0 (`https://slsa.dev/provenance/v1`).
  2. Validar firmas keyless utilizando `cosign` contra certificados efímeros de Fulcio vinculados a identidades OIDC de GitHub Actions / GitLab.
  3. Verificar inclusión de la firma en el registro de transparencia inmutable Rekor para erradicar firmas retroactivas con identidades revocadas.

### 3.66. Atestación de Confianza Hardware y Medición de Arranque con TPM 2.0 (VULN-CRYP-004)
- **La Lección:** Verificar la integridad de un sistema operativo únicamente a nivel de archivos en disco es inútil si el firmware UEFI, Option ROM o el sector de arranque han sido comprometidos por un bootkit persistente.
- **El Patrón Seguro:**
  1. Realizar atestación remota mediante TPM 2.0 leyendo los registros PCR del banco SHA-256 (PCR 0 para BIOS/UEFI, PCR 4 para bootloader, PCR 7 para Secure Boot).
  2. Reproducir deterministamente el registro de eventos TCG (`binary_bios_measurements`) calculando la cadena extendida de hashes hasta contrastar con el valor final del PCR.
  3. Validar citas criptográficas firmadas por la Clave de Atestación (AK) con nonces efímeros para mitigar ataques de repetición.








---

## 💻 4. Entornos de Ejecución Windows y Prevención de Hijacking

### 4.1. Secuestro de Ruta de Búsqueda en Scripts Batch (CWE-427 / CWE-428)
- **La Lección:** Invocar `node.exe` o `python.exe` en scripts `.cmd` sin ruta calificada o desde un directorio de trabajo no seguro permite a un atacante colocar un binario malicioso en esa carpeta y lograr RCE (`VULN-CONF-004`).
- **El Patrón de Bastionado:**
  1. Desvincular el working directory inmediatamente: `cd /d "%SystemRoot%"`.
  2. Resolver rutas autorizadas en orden de menor a mayor privilegio.
  3. Comprobar existencia física antes de llamar (`if exist ...`).
  4. Encapsular la invocación con comillas dobles estrictas: `"%TARGET_NODE%" "%SCRIPT_PATH%" %*`.

### 4.2. Invocación Segura de Subprocesos y Paso de Prompts Vía Stdin (Bypass de ARG_MAX)
- **La Lección:** Pasar diffs voluminosos o datos no confiables como argumentos CLI (`cmd = ['scanner', prompt]`) provoca errores por desbordamiento del búfer del sistema operativo (`[WinError 206] The filename or extension is too long` o límites `ARG_MAX` en POSIX), además de exponer el contenido en tablas de procesos (`ps aux`).
- **El Patrón Seguro:**
  1. Transmitir siempre el payload mediante el descriptor estándar `stdin`: `subprocess.run(cmd, input=prompt, text=True, ...)`.
  2. Deshabilitar herramientas hostiles en el contexto del ejecutor (`--disallowed-tools "Bash(*)"`).
  3. Pasar argumentos en arrays de tokens inmutables (`spawnSync('gh', ['api', ...])`) para erradicar inyecciones de comandos (CWE-78).

---

## 🗂️ 5. Cadena de Custodia en Auditorías Forenses (Los 4 Ledgers)

Toda auditoría de repositorio ejecutada con la Skill `security-reverse-engineering` debe generar y mantener 4 ledgers estructurados en `audits/<objetivo>/`:
1. `inventory/inventory.jsonl` y `summary.json`: Árbol físico determinista, conteo de extensiones y categorización.
2. `coverage.jsonl`: Disposición por archivo (`read`, `traced`, `verified`, `excluded`, `blocked`).
3. `evidence.jsonl`: Citas factuales con hashes SHA-256, líneas base 1 y nivel epistemológico (`OBSERVED`, `DERIVED`, `INFERRED`).
4. `unknowns.jsonl`: Brechas explícitas, contradicciones y dependencias remotas no resueltas.

---

## 🚀 6. Atajos y Comandos de Verificación Rápida

| Acción | Comando | Beneficio Operativo |
| :--- | :--- | :--- |
| **Calcular Snapshot Determinista** | `python src/scripts/target_snapshot.py snapshot <DIR> --json` | Obtiene el hash inmutable del workspace en $<1$ segundo. |
| **Derivar Fingerprint de Hallazgo** | `python src/scripts/target_snapshot.py fingerprint --target-id <ID> --rule-id <RULE> --anchor <ANCHOR> --json` | Genera huella primaria estable e independiente de líneas. |
| **Filtrar Falsos Positivos O(1)** | `python src/scripts/hard_exclusions.py filter <FINDINGS.json> -o <OUT.json> --json` | Descarta hallazgos de baja señal (DoS, rate limit, leaks) en $<0.01$s. |
| **Compilar Contratos TypeScript** | `pnpm build` | Verifica cero errores de tipos en esquemas Zod (`tsc`). |
| **Ejecutar Tests de Esquemas** | `pnpm test` | Ejecuta runner nativo `node --test "dist/**/*.test.js"`. |
| **Ejecutar Tests Unitarios Python** | `python -m unittest discover -s src/scripts -p "test_*.py"` | Valida suites de scripts de Capa 3 sin dependencias externas. |
| **Procesar y Resumir SARIF** | `python src/scripts/sarif_toolkit.py summary <FILE.sarif> --json` | Resumen estadístico instantáneo de hallazgos SAST sin dependencias. |
| **Fusionar Reportes SARIF** | `python src/scripts/sarif_toolkit.py merge <F1.sarif> <F2.sarif> -o <OUT.sarif> --json` | Fusión determinista con deduplicación por huella $O(1)$. |
| **Validar Capa ATT&CK Navigator** | `python src/scripts/navigator_mapper.py validate <LAYER.json> --json` | Validación contract-first de capas Navigator v4.x en $<0.01$s. |
| **Proyectar Técnicas a 8 Dimensiones** | `python src/scripts/navigator_mapper.py project <LAYER.json> --json` | Proyección determinista de 200+ técnicas hacia las 8 dimensiones MECE. |
| **Verificar Lockfiles y Supply Chain** | `python src/scripts/check_lockfiles.py <DIR> --json` | Auditoría estática determinista de lockfiles, gitignore y hooks en 8 ecosistemas en $<0.02$s. |
| **Escaneo Batch de Secretos (Sin Sesgo)** | `python src/scripts/scan_secrets.py <DIR> --json` | Detección determinista de credenciales con 60+ firmas y cero degradación de tests en $<0.05$s. |
| **Linter AST de Seguridad PoC** | `python src/scripts/poc_safety_linter.py <FILE> --json` | Análisis estático AST determinista de código generado por LLMs en $<0.02$s. |
| **Escanear Prompt Injection** | `python src/scripts/prompt_injection_detector.py scan "<TEXT>" --json` | Detección heurística de inyecciones y evasiones de trailing dot en $<0.01$s. |
| **Defangear Tokens Especiales** | `python src/scripts/prompt_injection_detector.py defang "<TEXT>" --json` | Neutralización de delimitadores de plantillas de chat vía ZWSP (GHSA-g5f9-3xfg-p9mf). |
| **Verificación Diferencial de Inyecciones** | `python src/scripts/differential_exploit_verifier.py <CMD>` | Confirmación matemática y estadística de SSTI, SQLi, Traversal y Timing en $<0.01$s. |
| **Escanear Telemetría y Beacons Encubiertos** | `python src/scripts/scan_covert_telemetry.py <DIR> --json` | Detección estática de tuberías Base64, llamadas a SMS (TextBelt) y webhooks en $<0.02$s. |
| **Inventario Criptográfico y Detección PQC** | `python src/scripts/pqc_inventory_scanner.py <DIR> --json` | Escaneo determinista de primitivas clásicas vulnerables frente a algoritmos PQC FIPS 203/204. |
| **Triaje Cuantitativo de Incidentes IR** | `python src/scripts/incident_triage_scorer.py --incident-id <ID> --title <TITLE> ... --json` | Scoring determinista ponderado y asignación de playbooks y SLAs en $<0.01$s. |



