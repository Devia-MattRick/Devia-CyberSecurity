# Marco Metodológico de Modelado de Amenazas: STRIDE + 7-Stage PASTA y Attack Trees

> **ID de Vulnerabilidad:** `VULN-TM-001`  
> **Taxonomía:** CWE-1059 (*Incomplete Documentation*) / OWASP Top 10 A04:2021/2025 (Insecure Design) / NIST SP 800-30  
> **Dimensión:** `THREAT_MODELING_ATTACK_SURFACE`  
> **Skill:** `threat-modeling-attack-surface`  
> **Herramienta Capa 3:** `src/scripts/risk_assessment_engine.py`  
> **Contrato Zod:** `src/schemas/cyber-risk-assessment.schema.ts`  

---

## 1. Integración de STRIDE y PASTA

Mientras que **STRIDE** es un enfoque centrado en componentes y software (identificando categorías de amenazas por elemento del diagrama de flujo de datos), **PASTA (Process for Attack Simulation and Threat Analysis)** es un marco de 7 etapas centrado en el riesgo y en el impacto de negocio. Su combinación proporciona una cobertura completa:

```
[Etapa 1: Objetivos de Negocio] ──> [Etapa 2: Definición del Alcance Técnico (DFD)]
                                                       │
                                                       ▼
[Etapa 4: Análisis de Amenazas] <── [Etapa 3: Descomposición con STRIDE]
              │
              ▼
[Etapa 5: Análisis de Vulnerabilidades] ──> [Etapa 6: Simulación y Attack Trees] ──> [Etapa 7: Análisis de Riesgo & Contramedidas]
```

---

## 2. Las 7 Etapas del Marco PASTA

1. **Etapa 1: Definición de Objetivos de Negocio (Business Objectives):**  
   Identificar activos críticos, requerimientos de cumplimiento (GDPR, PCI-DSS, SOC 2) y el impacto financiero o reputacional de una pérdida de confidencialidad o disponibilidad.
2. **Etapa 2: Definición del Alcance Técnico (Technical Scope):**  
   Mapear la arquitectura, frameworks, componentes de red, boundaries de confianza y dependencias de terceros.
3. **Etapa 3: Descomposición de la Aplicación y DFDs (Application Decomposition):**  
   Construir Diagramas de Flujo de Datos (DFDs) identificando:
   - Procesos (`P`)
   - Almacenes de datos (`DS`)
   - Flujos de datos (`DF`)
   - Entidades externas (`EE`)
   - Límites de confianza (*Trust Boundaries*)
4. **Etapa 4: Análisis de Amenazas con STRIDE (Threat Analysis):**  
   Evaluar cada elemento del DFD bajo la matriz STRIDE:
   - **S**poofing (Suplantación de identidad)
   - **T**ampering (Manipulación de datos en tránsito o reposo)
   - **R**epudiation (Repudio o falta de auditoría)
   - **I**nformation Disclosure (Fuga de información confidencial)
   - **D**enial of Service (Denegación de servicio o agotamiento de recursos)
   - **E**levation of Privilege (Escalada de privilegios)
5. **Etapa 5: Análisis de Vulnerabilidades y Debilidades (Vulnerability Analysis):**  
   Mapear las amenazas contra catálogos CWE y reportes de escaneo SAST/SCA.
6. **Etapa 6: Simulación de Ataques y Árboles de Ataque (Attack Modeling & Trees):**  
   Construir árboles de ataque lógicos con nodos `AND` / `OR` para representar los caminos mínimos que un atacante debe recorrer para alcanzar el objetivo.
7. **Etapa 7: Análisis Cuantitativo de Riesgo y Contramedidas (Risk & Impact Analysis):**  
   Calcular el Risk Score cuantitativo y definir mitigaciones prioritarias.

---

## 3. Construcción de Árboles de Ataque (Attack Trees)

```
[Compromiso de Datos Confidenciales] (OR)
├── [1. Exfiltración vía Inyección SQL] (AND)
│   ├── Identificar parámetro no parametrizado en API
│   └── Extraer tablas de usuarios vía UNION-based payload
│
└── [2. Secuestro de Cuenta de Administrador (ATO)] (OR)
    ├── Password reset poisoning vía manipulación de cabecera Host
    └── Fuerza bruta en código OTP de MFA por falta de rate limiting
```

---

## 4. Fórmula Cuantitativa DREAD para Priorización

$$\text{DREAD Score} = \frac{D + R + E + A + D}{5}$$

- **Damage Potential:** Gravedad del daño causado si el ataque tiene éxito (0-10).
- **Reproducibility:** Facilidad para repetir el ataque con éxito (0-10).
- **Exploitability:** Esfuerzo y conocimientos técnicos necesarios (0-10).
- **Affected Users:** Proporción de usuarios impactados (0-10).
- **Discoverability:** Facilidad para que un atacante descubra la vulnerabilidad (0-10).

| DREAD Total (Suma de 0-50) | Clasificación de Severidad | Acción Requerida |
|:---:|:---:|:---|
| **≥ 40** | **CRÍTICO** | Remediación inmediata / Bloqueador de Release |
| **25 - 39** | **ALTO** | Resolver en el sprint actual |
| **15 - 24** | **MEDIO** | Programar en backlog de seguridad |
| **< 15** | **BAJO** | Monitoreo continuo |
