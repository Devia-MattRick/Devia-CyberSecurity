# Guía de Ingeniería de Detección: Formato Portátil Sigma y Correlación Multi-SIEM

Este documento técnico de referencia para la Skill **`resilience-logging-telemetry`** establece las pautas de ingeniería de detección como código (*Detection-as-Code*), el modelado de reglas portátiles en formato **Sigma** y su traducción hacia lenguajes propietarios de SIEM (**Splunk SPL**, **Microsoft Sentinel KQL**, **Elasticsearch ES|QL**), complementando la prevención de **VULN-RESI-009**.

---

## 🏛️ Propósito y Filosofía Vendor-Agnostic

El formato **Sigma** es el estándar abierto para describir reglas de detección de amenazas de forma genérica y portable. Permite a los analistas de seguridad expresar la lógica analítica de un vector de ataque (TTP de MITRE ATT&CK) una sola vez y compilarla deterministamente hacia cualquier backend de producción mediante `pySigma`.

---

## 📋 Estructura Canónica de una Regla Sigma

```yaml
title: Detección de Volcado de Memoria LSASS vía Acceso a Procesos
id: 0d894093-71bc-43c3-8d63-bf520e73a7c5
status: stable
description: Detecta procesos no confiables accediendo a lsass.exe con permisos de lectura de memoria (T1003.001)
references:
    - https://attack.mitre.org/techniques/T1003/001/
author: Devia-CyberSecurity
date: 2026/10/29
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: '0x1010' # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    filter_legitimate:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
            - '\MsMpEng.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Agentes antivirus o EDR legítimos
level: high
```

---

## 🔄 Matriz de Proyección Multi-SIEM

| Backend SIEM | Motor de Conversión pySigma | Sintaxis Proyectada de Ejemplo |
| :--- | :--- | :--- |
| **Splunk Enterprise** | `pySigma-backend-splunk` | `index=wineventlog EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess="0x1010" NOT (SourceImage IN ("*\\svchost.exe", "*\\MsMpEng.exe"))` |
| **Microsoft Sentinel** | `pySigma-backend-kql` | `SecurityEvent \| where EventID == 4663 and ObjectName endswith @"\lsass.exe" and AccessList has "0x1010"` |
| **Elastic Security** | `pySigma-backend-elasticsearch` | `process.name: "lsass.exe" and winlog.event_data.GrantedAccess: "0x1010" and not process.parent.name: ("svchost.exe", "MsMpEng.exe")` |

---

## 🎯 Buenas Prácticas de Ingeniería de Detección en Devia

1. **Evitar Wildcards Iniciales en SPL:** Búsquedas del tipo `*mimikatz*` degradan severamente el rendimiento en petabytes de logs ($O(N)$ full table scan). Utilizar campos estructurados (`TargetImage`, `CommandLine`).
2. **Filtrado Negativo Restrictivo:** Todo bloque `filter` debe validar tanto el ejecutable de origen como su firma digital o hash SHA-256 para prevenir evasión mediante renombramiento de binarios.
3. **Mapeo MITRE ATT&CK Obligatorio:** Toda regla debe incluir su técnica canónica (e.g. `attack.t1059.001`, `attack.t1078`).
