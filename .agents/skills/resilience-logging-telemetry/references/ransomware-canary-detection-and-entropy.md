# Despliegue de Archivos Canario contra Ransomware y Análisis de Entropía

Este documento establece las directivas de colocación estratégica de archivos señuelo (*Canary Files*) y el análisis matemático de **Entropía de Shannon** para la detección temprana de ransomware en el ecosistema **Devia-CyberSecurity**.

---

## 🎯 1. Mecanismo de Trampa Temprana: Límites Alfabéticos

Los motores de ransomware tradicionales recorren los directorios locales y recursos compartidos de red (SMB/NFS) enumerando archivos mediante llamadas de sistema como `FindFirstFile` / `FindNextFile` en Windows o `readdir()` en Linux.

Para maximizar la probabilidad de que el ransomware intercepte y cifre un archivo canario antes de dañar información crítica del negocio, los señuelos deben situarse en los extremos lexicográficos de cada directorio:

```
Directorio Compartido: /shares/finance/
├── _AAAA_Budget_2026.docx         <-- Canario inicial (Cifrado primero en orden A-Z)
├── _AAAA_Payroll_Executive.xlsx   <-- Canario secundario
├── Accounts_Payable.xlsx          [Datos reales protegidos]
├── Balance_Sheet_2026.pdf         [Datos reales protegidos]
├── Tax_Filings_Q3.docx            [Datos reales protegidos]
├── ~zzzz_Annual_Review.docx       <-- Canario final (Cifrado primero en orden Z-A)
└── ~zzzz_System_Backup_Config.csv <-- Canario final secundario
```

- **Prefijo `_AAAA_`:** Intercepta algoritmos que iteran en orden alfabético ascendente.
- **Prefijo `~zzzz_`:** Intercepta variantes modernas de ransomware que recorren directorios en orden descendente para eludir defensas primarias.
- **Bytes Mágicos Válidos:** Los archivos deben contener cabeceras legítimas (`PK\x03\x04` para Office/ZIP, `%PDF-1.7`, volcados SQL) para evitar que los escáneres del atacante los omitan por inconsistencia de formato.

---

## 📊 2. Detección de Cifrado mediante Entropía de Shannon

La entropía de Shannon mide la cantidad de aleatoriedad o incertidumbre en una secuencia de datos. Dado que los algoritmos de cifrado simétrico modernos (AES-CBC, AES-GCM, ChaCha20) producen salidas pseudoaleatorias indistinguibles del ruido blanco, los archivos cifrados exhiben una densidad de entropía cercana al máximo teórico:

$$\text{Entropía} = -\sum_{i=0}^{255} P(b_i) \log_2 P(b_i)$$

Donde $P(b_i)$ es la frecuencia relativa de cada byte ($0 \le b_i \le 255$) en la muestra analizada:

| Tipo de Contenido | Rango Típico de Entropía | Veredicto |
| :--- | :--- | :--- |
| **Texto plano (ASCII, CSV, JSON, Logs)** | $3.0 - 5.0$ bits / byte | Normal |
| **Archivos ejecutables o scripts (PE, ELF, Python)** | $5.0 - 6.5$ bits / byte | Normal |
| **Documentos comprimidos (DOCX, XLSX, PDF, ZIP)** | $6.5 - 7.3$ bits / byte | Normal |
| **Archivos cifrados por Ransomware (AES, ChaCha20)** | **$\ge 7.6$ bits / byte** | **CRÍTICO: Cifrado en progreso** |

---

## 🚨 3. Análisis de Vulnerabilidad: Lectura no Acotada en Memoria (`VULN-RESI-011`)

### El Antipatrón Inseguro:
Muchos scripts y agentes de monitoreo leen el archivo completo en memoria mediante `f.read()`:

```python
# ❌ INSEGURO: Lectura no acotada de memoria (VULN-RESI-011)
def compute_entropy_unsafe(filepath):
    with open(filepath, "rb") as f:
        data = f.read() # ¡Peligro! Si el archivo pesa 10 GB, agota la RAM
    counts = Counter(data)
    # ...
```

Si el ransomware o un atacante local reemplaza el archivo canario por un archivo disperso o un volcado de base de datos masivo, el agente es terminado por el *Out-Of-Memory (OOM) Killer*, permitiendo que el ransomware continúe cifrando sin supervisión.

### El Patrón Seguro de Devia-CyberSecurity:
El cálculo de entropía debe operar sobre un **búfer acotado en streaming de tamaño fijo ($O(1)$ en memoria)**, analizando como máximo 64 KB:

```python
# ✅ SEGURO: Cálculo de entropía en memoria acotada O(1)
def compute_bounded_entropy(filepath: str, max_bytes: int = 65536) -> float:
    byte_counts = Counter()
    total_read = 0
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            to_count = chunk[:max(0, max_bytes - total_read)]
            if to_count:
                byte_counts.update(to_count)
                total_read += len(to_count)
            if total_read >= max_bytes:
                break
    if total_read == 0:
        return 0.0
    return -sum((c / total_read) * math.log2(c / total_read) for c in byte_counts.values())
```

---

## 🔍 4. Heurísticas Complementarias de Detección en File Integrity Monitoring (FIM)

Además de la variación de entropía, el agente de monitoreo supervisa:

1. **Renombrado con Extensiones Conocidas:** Detección de cambios de nombre hacia extensiones de grupos activos (`.lockbit`, `.blackcat`, `.akira`, `.dharma`, `.rhysida`).
2. **Caída de Notas de Rescate:** Detección de creación de archivos como `readme.txt`, `how_to_recover.txt` o `decrypt.html` en el mismo directorio.
3. **Correlación de Procesos Sospechosos:** Interrogación de procesos activos mediante `psutil` que hayan abierto descriptores de archivo sobre el señuelo en los últimos 30 segundos.
