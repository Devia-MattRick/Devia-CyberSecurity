# Detección de Anomalías de Red y Balizamiento C2 mediante Telemetría Zeek

Este documento define la metodología determinista para el análisis de flujos de red y registros de metadatos de **Zeek Network Security Monitor** (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `modbus.log`), orientada a la identificación matemática de canales de comando y control (C2), túneles de exfiltración y movimientos laterales.

---

## 📡 1. Los 5 Registros Esenciales de Zeek y Campos Clave

| Registro | Propósito Principal | Campos Clave de Telemetría |
| :--- | :--- | :--- |
| **`conn.log`** | Resumen de conexiones TCP/UDP/ICMP. | `id.orig_h`, `id.resp_h`, `id.resp_p`, `proto`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`. |
| **`dns.log`** | Transacciones DNS completas. | `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `rejected`. |
| **`http.log`** | Peticiones y respuestas HTTP. | `method`, `host`, `uri`, `user_agent`, `status_code`, `request_body_len`, `response_body_len`. |
| **`ssl.log`** | Negociación TLS/SSL y certificados. | `version`, `cipher`, `server_name`, `subject`, `issuer`, `validation_status`, `ja3`, `ja3s`. |
| **`modbus.log`** | Protocolo industrial Modbus TCP. | `func`, `exception`, `unit_id`, `pdu_type`. |

---

## 📊 2. Algoritmo Estadístico de Balizamiento C2 (*Beaconing Detection*)

Los agentes de comando y control automatizados (Cobalt Strike, Mythic, Sliver, Metasploit) generan llamadas periódicas a sus servidores para recibir órdenes:

### 2.1. Agrupamiento Determinista por Flujo
Las conexiones se agrupan por la tupla:
$$\text{FlowKey} = (\text{id.orig\_h}, \text{id.resp\_h}, \text{id.resp\_p})$$

### 2.2. Cálculo del Coeficiente de Variación ($CV$)
Para todo grupo con $N \ge 5$ conexiones ordenadas por marca temporal $t_1, t_2, \dots, t_N$, se calcula el vector de intervalos temporales $\Delta t_i = t_{i+1} - t_i$.
Se derivan la media ($\mu$) y la desviación típica ($\sigma$):
$$\mu = \frac{1}{N-1} \sum_{i=1}^{N-1} \Delta t_i, \quad \sigma = \sqrt{\frac{1}{N-1} \sum_{i=1}^{N-1} (\Delta t_i - \mu)^2}$$
El **Coeficiente de Variación ($CV$)** normaliza la dispersión frente a la escala de tiempo:
$$CV = \frac{\sigma}{\mu}$$

### 2.3. Puntuación de Balizamiento (*Beacon Score*)
$$S_{\text{beacon}} = \max(0, 1.0 - CV) \times 100$$
- Si $CV < 0.10$ $\to$ Balizamiento casi determinista ($S_{\text{beacon}} > 90$).
- Si $0.10 \le CV < 0.30$ $\to$ Balizamiento con jitter moderado ($70 \le S_{\text{beacon}} \le 90$).
- Si $CV \ge 0.30$ $\to$ Tráfico no regular o navegación humana interactiva ($S_{\text{beacon}} < 70$).

---

## 🔍 3. Detección de Túneles y Exfiltración sobre DNS (`dns.log`)

Los atacantes utilizan túneles DNS (Iodine, Dnscat2, Cobalt Strike DNS listener) codificando datos en las etiquetas de los subdominios:

### 3.1. Entropía de Shannon en Subdominios
Para la cadena del subdominio $S$ de longitud $L$:
$$H(S) = - \sum_{i=1}^{k} p(c_i) \log_2 p(c_i)$$
- Nombres de dominio legítimos en inglés o español promedian $H(S) \approx 2.2 - 2.9$.
- Subdominios con datos codificados en Base64 o Base32 alcanzan $H(S) \ge 3.5$.

### 3.2. Criterios Heurísticos de Exfiltración DNS
Una consulta se clasifica como sospechosa si cumple al menos dos de las siguientes condiciones:
1. $H(S) \ge 3.5$ bits por símbolo.
2. Longitud total de la consulta $\ge 40$ caracteres.
3. Tipo de consulta `TXT` o `NULL` con tasa de aparición superior al 30% del volumen del host.
4. Alta tasa de consultas hacia un único dominio registrable padre con etiquetas únicas (*Domain Fluxing*).

---

## ⚡ 4. Detección de Movimiento Lateral Este-Oeste en `conn.log`

El movimiento lateral entre subredes corporativas internas (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) se identifica mediante:
- **Puertos de Administración Críticos:** Ráfagas de conexiones hacia puertos 445 (SMB), 135 (RPC), 5985/5986 (WinRM) y 3389 (RDP) desde estaciones de usuario hacia otras estaciones o servidores no autorizados.
- **Conexiones Vacías de Larga Duración:** Sesiones TCP con estado `OTH` o `SHR` de larga duración (>3600 segundos) y volumen transferido $<100$ bytes, características de túneles proxy inversos (SOCKS / Chisel).

---

## 🛡️ 5. Gobernanza y Clasificación MECE

- Todo análisis de registros Zeek opera estáticamente sin requerir la ejecución de binarios del entorno auditado.
- Los hallazgos se clasifican canónicamente en `RESILIENCE_LOGGING_TELEMETRY` mediante contratos `ThreatDetectionReportSchema`.
