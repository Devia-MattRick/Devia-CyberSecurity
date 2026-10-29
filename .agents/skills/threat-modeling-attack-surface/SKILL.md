---
name: threat-modeling-attack-surface
description: Auditoría y modelado de amenazas sistemático (STRIDE, PASTA), identificación de activos críticos, actores de amenaza, flujos de datos, límites de confianza y catalogación exhaustiva de la superficie de ataque expuesta.
---

# Threat Modeling & Attack Surface

**Dimensión Canónica:** `THREAT_MODELING_ATTACK_SURFACE` (Dimensión 1)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Modelado de Amenazas y Superficie de Ataque**. Su responsabilidad primordial es:
1. Identificar sistemáticamente todos los activos de información críticos del sistema auditado y clasificar su nivel de sensibilidad.
2. Identificar y clasificar actores de amenaza relevantes (*Anonymous Remote, Authenticated User, Privileged Insider, Supply Chain Dependency, Local Process*).
3. Mapear los límites de confianza (*Trust Boundaries*) y flujos de datos inter-componente.
4. Catalogar exhaustivamente los puntos de entrada (*Entry Points*) de la aplicación (APIs HTTP, CLI, WebSockets, IPC, variables de entorno, sockets).
5. Evaluar escenarios de amenaza estructurados bajo la metodología STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) y mapear contra `ThreatModelSchema` de Devia-CyberSecurity.

---

## 📂 Organización Interna

- `references/`: Guías de metodologías de modelado (STRIDE, PASTA), catálogos de superficies y checklists (10 referencias técnicas).
  - [`target-snapshots-and-investigation-packets.md`](references/target-snapshots-and-investigation-packets.md): Snapshots deterministas de workspaces, huellas primarias de hallazgos y formulación de paquetes de investigación.

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/target_snapshot.py) | [`threat-model.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/threat-model.schema.ts) | Snapshots deterministas de repositorios $O(n \log n)$ y huellas $O(1)$. | [`test_target_snapshot.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_target_snapshot.py) |
| [`src/scripts/risk_assessment_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/risk_assessment_engine.py) | [`cyber-risk-assessment.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/cyber-risk-assessment.schema.ts) | Evaluación cuantitativa de riesgos basada en NIST SP 800-30 y matrices de criticidad. | [`test_risk_assessment_engine.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_risk_assessment_engine.py) |
| [`src/scripts/navigator_mapper.py`](file:///k:/Devia-CyberSecurity/src/scripts/navigator_mapper.py) | [`framework-mapping.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/framework-mapping.schema.ts) | Generación y exportación de capas tácticas de MITRE ATT&CK Navigator v4.x. | [`test_navigator_mapper.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_navigator_mapper.py) |
| [`src/scripts/incident_triage_scorer.py`](file:///k:/Devia-CyberSecurity/src/scripts/incident_triage_scorer.py) | [`incident-triage.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/incident-triage.schema.ts) | Puntuación ponderada y selección de playbooks de respuesta a incidentes. | [`test_incident_triage_scorer.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_incident_triage_scorer.py) |
| [`src/scripts/vulnerability_sla_analyzer.py`](file:///k:/Devia-CyberSecurity/src/scripts/vulnerability_sla_analyzer.py) | [`vulnerability-sla.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/vulnerability-sla.schema.ts) | Análisis de cumplimiento de SLAs de remediación y cálculo de aging buckets. | [`test_vulnerability_sla_analyzer.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_vulnerability_sla_analyzer.py) |
| [`src/scripts/prompt_injection_detector.py`](file:///k:/Devia-CyberSecurity/src/scripts/prompt_injection_detector.py) | [`threat-model.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/threat-model.schema.ts) | Detección de inyecciones de prompt indirectas y vectores LLM. | [`test_prompt_injection_detector.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_prompt_injection_detector.py) |
