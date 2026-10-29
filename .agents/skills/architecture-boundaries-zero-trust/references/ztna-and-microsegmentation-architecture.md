# Arquitectura de Acceso Zero Trust (ZTNA), Políticas Cedar y Microsegmentación de Red

Esta guía técnica establece los principios de diseño, auditoría y modelado de fronteras para arquitecturas de **Zero Trust Network Access (ZTNA)** y microsegmentación de cargas de trabajo en **Devia-CyberSecurity**.

---

## 🏛️ 1. Paradigma ZTNA vs VPN Perimetral Tradicional

El modelo tradicional de seguridad perimetral asume confianza implícita una vez que un usuario o dispositivo se conecta mediante una VPN (`Layer 3 access`). ZTNA elimina la confianza implícita operando bajo los axiomas de **NIST SP 800-207**:

| Dimensión | VPN Perimetral Tradicional | Acceso Zero Trust (ZTNA) |
| :--- | :--- | :--- |
| **Frontera de Acceso** | Red completa (subred IP, asignación de DHCP virtual) | Aplicación específica exclusivamente (Reverse proxy Layer 7) |
| **Visibilidad de Red** | El usuario puede escanear puertos y descubrir otros hosts | La red interna es completamente invisible para el cliente |
| **Evaluación de Confianza** | Una sola vez en el inicio de sesión | Continua por cada petición (`per-request continuous verification`) |
| **Conexiones Perimetrales** | Puertos entrantes abiertos en firewall (`Inbound VPN ports`) | Conectores salientes exclusivos (`Outbound-only App Connectors`) |
| **Postura de Dispositivo** | Generalmente no validada o solo pre-login | Integración continua con EDR/MDM (CrowdStrike, Jamf, Intune) |

---

## 📜 2. Políticas de Autorización Declarativas en Lenguaje Cedar

En servicios como AWS Verified Access, las directivas de acceso ZTNA se formalizan mediante el lenguaje de políticas **Cedar**. Cedar garantiza evaluación determinista y separación formal entre principal, acción, recurso y contexto:

```cedar
// Política ZTNA: Acceso permitido únicamente a miembros del grupo Finanzas
// con dispositivo gestionado y puntuación de salud de CrowdStrike > 80
permit(
    principal,
    action in [Action::"view", Action::"download"],
    resource == Resource::"FinancialLedgerApp"
)
when {
    context.okta.groups.contains("Finance-Admins") &&
    context.crowdstrike.assessment.overall > 80 &&
    context.crowdstrike.assessment.sensor_config.status == "active" &&
    context.http_request.client_ip in ["198.51.100.0/24"]
};

// Prohibición explícita de dispositivos desactualizados o no gestionados
forbid(
    principal,
    action,
    resource
)
when {
    !context.crowdstrike.assessment.sensor_config.status == "active"
};
```

---

## 🔀 3. Microsegmentación de Cargas de Trabajo (Workload-to-Workload)

La microsegmentación divide el centro de datos o la nube en zonas de seguridad granulares a nivel de proceso o contenedor, erradicando el movimiento lateral (T1021) en caso de que una máquina sea comprometida.

### Principios de Auditoría de Microsegmentación:
1. **Mapeo de Dependencias de Aplicación (ADM):** Analizar flujos de red reales (NetFlow / IPFIX) antes de activar políticas de bloqueo para evitar disrupciones operativas.
2. **Identidad Criptográfica de Cargas de Trabajo:** Utilizar mTLS con identidades SPIFFE/SPIRE o etiquetas criptográficas en el kernel (eBPF / Cilium) en lugar de depender de direcciones IP efímeras.
3. **Regla de Denegación por Defecto (Default-Deny):** Todo tráfico este-oeste entre servidores dentro de la misma subred debe ser explícitamente bloqueado salvo que exista una regla que lo autorice.
