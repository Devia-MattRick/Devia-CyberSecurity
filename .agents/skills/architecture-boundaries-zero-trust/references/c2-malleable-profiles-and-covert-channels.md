# Deconstrucción de Canales C2, Malleable Profiles y Canales Encubiertos

Esta referencia técnica dota a la Skill **`architecture-boundaries-zero-trust`** de metodologías y heurísticas deterministas para la inspección de tráfico de Comando y Control (C2), deconstrucción de perfiles maleables (Cobalt Strike Malleable C2) y detección de canales encubiertos y rootkits de kernel.

---

## 🏛️ 1. Anatomía de los Perfiles Maleables de C2 (Malleable C2)

Los frameworks modernos de adversarios (Cobalt Strike, Mythic, Sliver, Havoc) emplean especificaciones declarativas para moldear sus firmas de red y camuflar balizas (*beacons*) bajo el aspecto de tráfico legítimo (CDN, analíticas, streaming o APIs populares).

### Componentes de un Perfil Maleable de Cobalt Strike
```yaml
http-get:
  uri: "/api/v1/telemetry /stats/collect /analytics"
  client:
    header: "Host: cdn.legitimate-cloud.com"
    header: "Accept: application/json"
    metadata:
      base64url: true
      prepend: "session_id="
      header: "Cookie"
  server:
    header: "Content-Type: application/json"
    output:
      mask: true
      base64: true
      prepend: "{\"status\":\"ok\",\"payload\":\""
      append: "\"}"
```

### Indicadores de Evasión de Frontera y Detección
1. **Transformaciones en Cadena (`metadata` / `output`):**
   - El stager aplica transformaciones reversibles: `mask` (XOR con clave de 4 bytes) $\to$ `base64url` $\to$ `prepend`/`append`.
   - Para extraer la clave RSA pública o configuración del Beacon, se debe aplicar el inverso exacto de la cadena de transformación declarada.
2. **Jitter y Análisis Estadístico de Frecuencias (IAT & CV):**
   - La baliza C2 consulta al servidor en intervalos definidos por:
     $$T_{\text{interval}} = T_{\text{sleeptime}} \times (1 \pm \text{jitter})$$
   - El cálculo del **Coeficiente de Variación ($CV$)** sobre los intervalos entre llegadas (Inter-Arrival Time - IAT) permite detectar el balizamiento con independencia de la duración absoluta del intervalo:
     $$CV = \frac{\sigma}{\mu} = \frac{\sqrt{\frac{1}{N}\sum_{i=1}^N (t_i - \mu)^2}}{\mu}$$
   - **Umbrales de Calibración:**
     - $CV \le 0.05$: Balizamiento periódico estricto (automatizado sin jitter, riesgo crítico).
     - $0.05 < CV \le 0.15$: Balizamiento con jitter bajo (Cobalt Strike con jitter $\le 20\%$, riesgo alto).
     - $0.15 < CV \le 0.25$: Balizamiento moderado (filtrable por correlación de bytes y puertos).
     - $CV > 0.35$: Tráfico humano o estocástico benigno.
   - **Consistencia de Carga Útil:** Los agentes de balizamiento desocupados envían peticiones HTTP de tamaño idéntico ($CV_{\text{data}} \le 0.10$), lo que complementa la regularidad temporal.


---

## 🕵️ 2. Canales Encubiertos de Red y Exfiltración

| Canal Encubierto | Protocolo Base | Mecanismo de Inyección de Carga | Método de Detección Heurística |
| :--- | :--- | :--- | :--- |
| **DNS Tunneling** | DNS (Puerto 53 UDP) | Etiquetas de subdominio Base32/Base64 (`<payload>.data.attacker.com`). | Ratios elevados de entropía en subdominios, alto volumen de peticiones `TXT` / `NULL`, nombres no resolvibles (`NXDOMAIN`). |
| **ICMP Payload Tunneling** | ICMP Echo (Ping) | Reemplazo del padding estándar (`abcdefghijklmnopqrstuvw...`) por datos cifrados. | Discrepancias de longitud de carga ICMP, firma de padding no conforme al estándar del SO. |
| **TCP Initial Sequence Number (ISN)** | TCP SYN | Codificación de 32 bits de información en el campo `Sequence Number` del handshake. | Análisis de aleatoriedad y entropía en ISNs generados frente a PRNG del kernel. |
| **HTTP Header Smuggling** | HTTP/1.1 y HTTP/2 | Inserción de metadatos en cabeceras no estándar (`X-Forwarded-Client`, `Cookie`, `ETag`). | Inspección de cabeceras de tamaño anómalo y caracteres no imprimibles. |

---

## 🛡️ 3. Detección de Rootkits de Kernel en Linux

### 3.1. Hooking de Syscalls y Falsificación de Procesos
- Los rootkits modernos de Linux (Loadable Kernel Modules - LKM o eBPF malicioso) interceptan las syscalls `sys_getdents64` para ocultar archivos/directorios de procesos maliciosos en `/proc/`.
- **Heurística de Detección Cruzada:**
  - Comparar la lista de procesos obtenida mediante `sys_getdents64` (`/proc/`) con la lista derivada de `sched_yield` o enlaces de tareas del kernel (`task_struct`).
  - Si un proceso responde a señales `kill -0 <PID>` pero no aparece listado en `/proc/`, existe un rootkit activo ocultando el proceso.

### 3.2. Módulos Ocultos en Memoria (`/proc/modules` Desvinculados)
- Un rootkit LKM puede desvincularse de la lista doblemente enlazada `modules` ejecutando `list_del(&THIS_MODULE->list)`.
- En este estado, `lsmod` o `/proc/modules` no muestran el módulo, pero sus instrucciones residen en el espacio de memoria del kernel.
- **Detección:** Inspeccionar `/sys/module/` o escanear regiones de memoria del kernel (`kallsyms` vs `vmalloc`) mediante herramientas forenses offline (Volatility / LiME).
