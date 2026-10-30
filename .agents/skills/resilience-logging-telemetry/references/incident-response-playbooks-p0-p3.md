# Playbooks Formales de Respuesta a Incidentes (P0 a P3)

> **ID de Vulnerabilidad:** `VULN-RESI-003`  
> **Taxonomía:** CWE-1059 (*Incomplete Documentation of Security Mechanisms*) / OWASP Top 10 A09:2021/2025 / NIST SP 800-61 Rev. 2  
> **Dimensión:** `RESILIENCE_LOGGING_TELEMETRY`  
> **Skill:** `resilience-logging-telemetry`  
> **Herramienta Capa 3:** `src/scripts/incident_triage_scorer.py`  
> **Contrato Zod:** `src/schemas/incident-triage.schema.ts`  

---

## 1. Niveles de Severidad y Acuerdos de Nivel de Servicio (SLAs)

| Nivel | Definición del Incidente | Ejemplos Operativos | SLA de Contención | SLA de Erradicación |
|:---:|:---|:---|:---:|:---:|
| **P0** | **Crítico / Catastrófico**<br>Compromiso activo de producción con impacto masivo o pérdida de control. | Filtración masiva de datos PII, Ejecución Remota de Código (RCE) en producción, movimiento lateral con credenciales de dominio comprometidas. | **< 15 minutos** | **< 4 horas** |
| **P1** | **Alto**<br>Afectación grave a la confidencialidad, integridad o disponibilidad de sistemas clave. | Fuga de clave maestra de API o certificado, secuestro de cuentas privilegiadas (ATO), ransomware en hosts aislados, ataque DDoS activo. | **< 1 hora** | **< 24 horas** |
| **P2** | **Medio**<br>Incidente contenido o vulnerabilidad explotable sin compromiso activo demostrado. | Campaña dirigida de phishing a empleados, desconfiguración de bucket S3 público sin descarga confirmada, vulnerabilidad crítica en dependencia sin vector expuesto. | **< 4 horas** | **< 72 horas** |
| **P3** | **Bajo / Higiene**<br>Anomalías operativas de bajo riesgo o violaciones menores de política. | Intentos fallidos de fuerza bruta bloqueados por WAF, certificados próximos a expirar, hallazgos de escaneo estático de baja severidad. | **< 24 horas** | **Próximo Sprint** |

---

## 2. El Ciclo de Vida de 4 Fases (NIST SP 800-61)

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  1. DETECTAR     │ ──> │  2. CONTENER     │ ──> │  3. ERRADICAR    │ ──> │  4. RECUPERAR    │
│  (Triage & Score)│     │  (Aislar & Cortar│     │  (Remover & Purg)│     │  (Restaurar & Post)
└──────────────────┘     └──────────────────┘     └──────────────────┘     └──────────────────┘
```

---

## 3. Playbook de Contención Rápida por Tipo de Incidente

### 3.1 Playbook: Fuga de Claves de API / Secretos (P1)
1. **Contención Inmediata:**
   - Revocar la clave comprometida en el panel del proveedor (Google AI Studio, OpenAI, AWS IAM).
   - Generar nueva clave y actualizar los secretos en runtime (variables de entorno seguras / Vault).
2. **Erradicación:**
   - Inspeccionar logs de acceso de la clave durante las últimas 72 horas para determinar si hubo consultas anómalas o exfiltración.
   - Purgar el secreto del historial de Git si fue commiteado usando `git filter-repo` o `BFG Repo-Cleaner`.
3. **Recuperación:**
   - Restablecer servicios dependientes y verificar que las métricas de error 401/403 se normalicen.

### 3.2 Playbook: Brecha de Datos PII / Base de Datos Comprometida (P0)
1. **Contención Inmediata:**
   - Revocar tokens de sesión activos para todos los usuarios involucrados.
   - Modificar contraseñas maestras de conexión a base de datos y forzar rotación de claves TLS.
   - Aislar el subproceso o host comprometido desconectando interfaces de red no administrativas.
2. **Erradicación:**
   - Identificar el punto de entrada (e.g. inyección SQL, bypass de autenticación o SSRF) y aplicar parche en HEAD.
   - Verificar si se instalaron canarios o puertas traseras.
3. **Recuperación & Notificación:**
   - Restaurar desde backup limpio verificado.
   - Activar el protocolo legal de notificación GDPR (dentro de las 72 horas si afecta a ciudadanos de la UE).

---

## 4. Checklist de Auditoría

- [ ] ¿Los incidentes se clasifican cuantitativamente utilizando la herramienta `incident_triage_scorer.py`?
- [ ] ¿Existen procedimientos documentados y probados de revocación y rotación de claves en menos de 15 minutos?
- [ ] ¿Los canales de comunicación de crisis operan fuera de banda (OutOfBand) si la infraestructura principal está comprometida?
