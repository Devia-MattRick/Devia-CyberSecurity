---
name: resilience-logging-telemetry
description: Prevención y mitigación de denegación de servicio (DoS / ReDoS), control y prevención de fugas de información sensible en logs (PII, credenciales), manejo robusto de excepciones y trazabilidad/monitoreo de eventos de seguridad.
---

# Resilience, Logging & Telemetry

**Dimensión Canónica:** `RESILIENCE_LOGGING_TELEMETRY` (Dimensión 8)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Resiliencia, Registro (Logging) y Telemetría**. Su responsabilidad primordial es:
1. Identificar vectores de Denegación de Servicio (DoS): consumo descontrolado de CPU o memoria, bucles infinitos, algoritmos con complejidad $O(n^2)$ o superior sobre entradas controladas por el usuario, y Regular Expression Denial of Service (ReDoS).
2. Auditar la implementación de límites de tasa (*Rate Limiting*) y cuotas en endpoints públicos y autenticados.
3. Prevenir fugas de información confidencial en logs: detectar impresión inadvertida de contraseñas, tokens JWT, números de tarjetas, claves privadas o datos personales (PII) en archivos de registro (`CWE-532`).
4. Evaluar el manejo de excepciones y fallos: erradicar bloques `catch` vacíos que silencien fallos críticos de seguridad (*fail-open*) y garantizar que los mensajes de error no expongan trazas de pila completas (*stack traces*) al usuario final.
5. Auditar la trazabilidad y auditoría de eventos de seguridad (login fallido, cambio de credenciales, transacciones críticas) para garantizar no-repudio y respuesta forense efectiva.

---

## 📂 Organización Interna

- `references/`: Patrones de ReDoS y expresiones regulares catastróficas, guías de sanitización de logs y checklists de resiliencia (6 referencias técnicas).
  - [`interrupted-scan-recovery.md`](references/interrupted-scan-recovery.md): Principio epistemológico de inconclusión en auditorías incompletas, manejo transaccional de checkpoints y serialización segura en SQLite.

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/scan_covert_telemetry.py`](file:///k:/Devia-CyberSecurity/src/scripts/scan_covert_telemetry.py) | [`report.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/report.schema.ts) | Detección de telemetría clandestina, balizas SMS no autorizadas y exfiltración en flujos Base64. | [`test_scan_covert_telemetry.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_scan_covert_telemetry.py) |
| [`src/scripts/sarif_toolkit.py`](file:///k:/Devia-CyberSecurity/src/scripts/sarif_toolkit.py) | [`report.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/report.schema.ts) | Parser, normalizador y deduplicador determinista de reportes en formato estándar SARIF 2.1.0 (OASIS). | [`test_sarif_toolkit.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_sarif_toolkit.py) |
