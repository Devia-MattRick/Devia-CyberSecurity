# Seguridad y Detección de Ataques en Protocolos Industriales OT/ICS (Modbus y DNP3)

Este documento define la metodología de inspección, control de fronteras y detección de inyecciones de comandos para entornos de Tecnología Operativa (OT), Sistemas de Control Industrial (ICS) y SCADA que operan sobre **Modbus TCP** y **DNP3**.

---

## 🏭 1. Arquitectura y Modelo de Zonas de Purdue en Redes OT

La seguridad en redes ciberfísicas se estructura conforme al modelo ISA-99 / IEC 62443 en niveles jerárquicos:
- **Nivel 0 / 1 (Proceso y Control Básico):** Sensores, actuadores, RTUs y Controladores Lógicos Programables (PLCs). Tráfico Modbus TCP, DNP3, S7comm, EtherNet/IP.
- **Nivel 2 (Control de Área):** Interfaces Hombre-Máquina (HMI), estaciones de ingeniería y servidores SCADA.
- **Nivel 3 (Operaciones de Planta):** Historiadores de procesos, servidores de gestión de parches OT y consolas operativas.
- **Zona Desmilitarizada Industrial (IDMZ - Nivel 3.5):** Barrera de aislamiento Zero Trust entre la red IT corporativa (Nivel 4/5) y la red de control OT (Niveles 0-3).

---

## ⚡ 2. Anatomía del Protocolo Modbus TCP y Códigos de Función Críticos

Modbus TCP carece por defecto de autenticación nativa, cifrado e integridad criptográfica. Cualquier nodo que alcance el puerto TCP 502 puede enviar tramas a los PLCs:

| Código de Función | Nombre Modbus | Clasificación de Riesgo | Impacto Operativo |
| :--- | :--- | :--- | :--- |
| **1 (0x01)** | Read Coils | Lectura (Informativo) | Inspección de estados booleanos de relés/salidas. |
| **2 (0x02)** | Read Discrete Inputs | Lectura (Informativo) | Lectura de sensores binarios de campo. |
| **3 (0x03)** | Read Holding Registers | Lectura (Informativo) | Lectura de valores analógicos (temperatura, presión). |
| **4 (0x04)** | Read Input Registers | Lectura (Informativo) | Telemetría analógica de entrada. |
| **5 (0x05)** | **Write Single Coil** | **CRITICAL (Escritura)** | Fuerza el encendido/apagado de una válvula, motor o disyuntor. |
| **6 (0x06)** | **Write Single Register** | **CRITICAL (Escritura)** | Altera setpoints críticos de operación (e.g. presión máxima). |
| **15 (0x0F)** | **Write Multiple Coils** | **CRITICAL (Escritura)** | Modificación masiva de estados de actuadores. |
| **16 (0x10)** | **Write Multiple Registers** | **CRITICAL (Escritura)** | Reescritura masiva de parámetros de memoria de PLC. |
| **22 (0x16)** | **Mask Write Register** | **CRITICAL (Escritura)** | Manipulación a nivel de bits de registros de control. |
| **23 (0x17)** | **Read/Write Multiple** | **CRITICAL (Escritura)** | Lectura y mutación atómica simultánea. |

---

## 🛡️ 3. Reglas de Detección de Inyección de Comandos Modbus

Para proteger la integridad de los PLCs en redes Nivel 1/2:
1. **Segregación Estricta de Origen de Escritura:**
   - Únicamente las HMIs y servidores SCADA autorizados en Nivel 2 poseen autorización para emitir códigos de función de escritura (5, 6, 15, 16, 22, 23).
   - Cualquier paquete Modbus con función $\in \{5, 6, 15, 16, 22, 23\}$ originado desde estaciones de ingeniería no declaradas, zonas IT o subredes Wi-Fi dispara alerta inmediata **CRITICAL** (**T1565.001 / VULN-ARCH-029**).
2. **Validación de Límites de Registros (*Register Bounds Checking*):**
   - Correlacionar escrituras que soliciten valores fuera de los límites de tolerancia física de los actuadores (e.g. RPMs superiores al límite de diseño, como en ataques tipo Stuxnet).
3. **Erradicación de HTTP Plano en Monitoreo Industrial (VULN-CONF-019):**
   - Toda interfaz web de administración de historiadores y consolas SCADA debe forzar HTTPS con TLS 1.3 y certificados emitidos por la CA industrial de planta, prohibiendo taxativamente HTTP en texto claro.

---

## 🏛️ 4. Gobernanza Dimensional MECE

- Todo análisis de protocolos ciberfísicos, aislamiento de redes industriales y controles perimetrales de PLCs se clasifica estrictamente en:
  **`ARCHITECTURE_BOUNDARIES_ZERO_TRUST`**
- Monitoreado deterministamente mediante `ThreatDetectionEngine` (`src/scripts/threat_detection_engine.py`) bajo el motor `OT_ICS_PROTOCOL`.
