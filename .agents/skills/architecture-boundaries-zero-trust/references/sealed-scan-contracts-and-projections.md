# Contrato de Auditoría Sellada Inmutable y Separación Estricta de Proyecciones

Este documento formaliza el principio arquitectónico de **Paquetes Sellados Inmutables (*Sealed Scan Bundle*)** y la separación de la Fuente Única de Verdad (SSOT) frente a las vistas de presentación (Markdown, SARIF), adoptado tras la auditoría de **Codex Security**.

---

## 🏛️ El Problema Arquitectónico: Manipulación de Reportes de Auditoría (`VULN-ARCH-004`)

En flujos de auditoría tradicionales, los reportes finales (e.g. `report.md`, `results.sarif`) suelen generarse o reescribirse directamente durante el ciclo de vida del análisis. Esto introduce graves debilidades arquitectónicas:
1. **Falta de Inmutabilidad Forense:** Modificaciones posteriores a un archivo Markdown pueden alterar severidades, ocultar hallazgos o falsificar la cobertura sin dejar huella criptográfica.
2. **Ambigüedad de Estado:** No es posible discernir si un informe refleja una auditoría terminada con éxito (`completed`), un análisis interrumpido (`interrupted`) o un escaneo cancelado (`canceled`).
3. **Pérdida de Evidencia Estructurada:** Al convertir hallazgos a prosa plana en Markdown, se pierde la trazabilidad de tipos, hashes SHA-256 de los archivos analizados y referencias precisas de invariantes.

---

## 🛡️ La Solución Arquitectónica: El Paquete Sellado Inmutable

El paquete canónico de auditoría se sella al alcanzar un estado terminal y se almacena en el directorio de la auditoría con tres archivos machine-readable estrictos:

```
<scan_dir>/
├── scan-manifest.json  <- Recibo terminal inmutable y firmado criptográficamente
├── findings.json       <- Registros semánticos canónicos de hallazgos
└── coverage.json       <- Resumen estructurado de superficies y cobertura honesta
```

### 1. Invariante de Sellado Criptográfico (`scan-manifest.json`)
El archivo `scan-manifest.json` registra:
- `scan.id` y metadatos de versión del motor productor.
- `scan.status`: `"completed" | "failed" | "canceled" | "interrupted"`.
- `scan.target`: Snapshot determinista del objetivo (`devia-snapshot/v1:sha256:...`).
- `scan.artifacts`: Arreglo de recibos con el hash SHA-256 exacto de `findings.json` y `coverage.json`.
- `scan.sealedAt`: Timestamp ISO 8601 UTC en que el bundle fue sellado.

Una vez sellado el paquete, **queda terminantemente prohibido a cualquier script, adaptador o agente modificar el manifiesto o sus artefactos canónicos**.

### 2. Principio de Proyección de Solo Lectura (*Downstream Projections*)
- **`report.md`** y **`results.sarif`** son **PROYECCIONES DERIVADAS**.
- Ningún consumidor debe intentar reconstruir el estado de la auditoría parseando el Markdown.
- Si se genera un nuevo exportador (e.g. SARIF para GitHub Code Scanning, HTML interactivo), este lee del paquete sellado en modo de solo lectura y persiste su salida de forma desacoplada.

### 3. Frontera Estricta Offline en Subprocesos y Workers
- Durante la ejecución de los inspectores estáticos y scripts de auditoría, **todo subproceso debe operar 100% offline**.
- Queda prohibida la invocación de endpoints remotos para validar credenciales encontradas o resolver políticas durante el análisis.
