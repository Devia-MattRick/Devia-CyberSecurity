# Secuestro y Confusión en Ejecutores de Paquetes JavaScript (`npx`, `npm exec`, `bunx` vs `dlx`)

Este documento establece la metodología de auditoría para detectar y mitigar vulnerabilidades de confusión y secuestro de ejecución de paquetes en pipelines de CI/CD, scripts de automatización y configuración de agentes dentro de **Devia-CyberSecurity**.

---

## 🔍 La Mecánica del Fallo (`VULN-SCA-007`)

Los ejecutores de paquetes de JavaScript modernos se dividen en dos arquitecturas con comportamientos de resolución radicalmente diferentes:

### 1. Ejecutores con Fallback Local-Primero (`npx`, `npm exec`, `bunx`)
Cuando un flujo invoca un comando mediante `npx tool` o `bunx tool`:
1. El ejecutor busca el binario `tool` en `node_modules/.bin` del proyecto.
2. Si no existe, busca en los binarios globales del sistema.
3. Si no existe en el sistema ni en el caché local:
   - **El riesgo crítico:** El ejecutor interpreta el token `tool` como el nombre de un paquete en el registro público de npm (`https://registry.npmjs.org`).
   - Si se ejecuta en entornos no interactivos o con el flag `-y` (`--yes`), **descarga e instala silenciosamente el paquete público y ejecuta su binario por defecto**.

Si un desarrollador o pipeline invoca una herramienta interna que no está instalada en el workspace local, un atacante que haya registrado un paquete con ese mismo nombre en npm público logrará **RCE inmediato** en la máquina del desarrollador o en el runner de CI/CD.

### 2. Ejecutores de Descarga Explícita (`pnpm dlx`, `yarn dlx`, `deno run npm:`)
A diferencia de `npx`, herramientas como `pnpm dlx` no buscan primero binarios locales; su propósito explícito es descargar un paquete temporalmente y ejecutarlo.
- **Riesgo:** El riesgo aquí no es el fallback local, sino la ambigüedad en nombres con scope (`@scope/pkg`), errores tipográficos (*typosquatting*) y el uso de versiones flotantes o tags mutables (`latest`).

---

## 📊 Matriz Comparativa de Comportamiento por Ejecutor

| Ejecutor | Orden de Resolución | Comportamiento sin Binario Local | Flag de Mitigación / Confinamiento |
| :--- | :--- | :--- | :--- |
| **`npx` / `npm exec`** | Local $\to$ Global $\to$ Caché $\to$ Registro público npm | Descarga y ejecuta paquete de npm público (automático con `-y`) | `--package <pkg>` / `--no` (rechaza instalar) |
| **`bunx`** | Local $\to$ Caché de Bun $\to$ Registro público npm | Descarga e instala en caché de Bun | `--package <pkg>` / `--no-install` |
| **`pnpm dlx`** | Solo descarga remota temporal | No busca binario local; descarga siempre | Usar dependencias fijadas + `pnpm exec` |
| **`yarn dlx`** | Solo descarga remota temporal | No busca binario local; descarga siempre | `--package <pkg>` / fijar versión estricta |
| **`deno run npm:<pkg>`**| Caché de Deno / Registro npm | Requiere especificación explícita `npm:` | Fijar versión exacta + permisos granulares |

---

## 🛡️ Patrones de Código Vulnerables vs Seguros

### Caso 1: Invocación Desprotegida en GitHub Actions / Makefile
❌ **Vulnerable:**
```yaml
- name: Run internal linter
  run: npx -y devia-internal-lint --fix
```
*Impacto:* Si `devia-internal-lint` no está listado en `package.json` ni instalado previamente en el runner, `npx` descargará el paquete público `devia-internal-lint` desde npm si un tercero lo registró.

✅ **Seguro:**
```yaml
- name: Run internal linter
  run: npx --no devia-internal-lint --fix
  # O fijando explícitamente el paquete verificado:
  # run: npx --package @devia/internal-lint@1.2.3 devia-internal-lint --fix
```

### Caso 2: Especificación de Herramientas en Configuraciones de Agentes / MCP
❌ **Vulnerable:**
```json
{
  "mcpServers": {
    "git-tools": {
      "command": "npx",
      "args": ["-y", "git-mcp-server"]
    }
  }
}
```

✅ **Seguro:**
```json
{
  "mcpServers": {
    "git-tools": {
      "command": "npx",
      "args": ["--package", "@trusted-org/git-mcp-server@2.1.0", "git-mcp-server"]
    }
  }
}
```

---

## 📋 Checklist de Auditoría de Supply Chain (`VULN-SCA-007`)

- [ ] ¿Los flujos CI/CD invocan comandos `npx` sin el flag `--no` o sin `--package` explícito?
- [ ] ¿Existen scripts en `package.json` que asumen la presencia de binarios sin declararlos en `devDependencies`?
- [ ] ¿Las configuraciones de servidores MCP para agentes utilizan `npx -y <bare-command>`?
- [ ] ¿Se utilizan tags mutables como `latest`, `next` o rangos abiertos (`^`, `~`) en ejecutores de descarga remota (`dlx`)?
