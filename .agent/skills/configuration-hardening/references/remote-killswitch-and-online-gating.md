# Auditoría de Resiliencia: Kill-Switches Remotos, Compuertas Online y Decepción de Errores

Esta referencia técnica establece los principios de modelado de amenazas, auditoría y aseguramiento de configuración para identificar dependencias remotas no autorizadas, mecanismos de compuerta online (*Online Gating*) y kill-switches unilaterales en herramientas de software (`VULN-CONF-008`, `CWE-284`, `CWE-400`, `CWE-390`).

---

## 🏛️ 1. Definición y Riesgo de las Compuertas de Arranque Online

Se denomina **Compuerta Online** o **Kill-Switch Remoto** al mecanismo arquitectónico por el cual una aplicación local, CLI o herramienta desktop condiciona su inicio o continuidad operativa a la consulta síncrona de un recurso en la red (e.g. un servidor de licencias, un archivo de texto en GitHub o una respuesta API propietaria).

### Vectores de Falla y Riesgo para el Operador
1. **Denegación de Servicio Unilateral (DoS):** Si el mantenedor del repositorio remoto elimina el archivo, cambia su contenido o revoca el acceso, todas las instalaciones existentes quedan inoperables de forma inmediata sin que medie actualización de software.
2. **Dependencia Forzada de Conectividad:** Viola el principio *Offline-First* necesario para entornos aislados (*air-gapped*), estaciones de auditoría forense o redes militares/gubernamentales.
3. **Decepción de Diagnóstico (Error Code Spoofing):** Para disimular que el bloqueo es deliberado, el software suele emitir mensajes de error falsificados acusando fallas de infraestructura ajenas (e.g. errores DNS, caídas de gateways).

---

## 🔍 2. Caso de Estudio: AllHackingTools (.check/Configuration.py)

En `AllHackingTools`, los scripts `.check/Configuration.py` y `.check/FileConfiguration.py` ejecutan el siguiente patrón antes de permitir que el usuario acceda al menú:

```python
def sys_check():
    sys_url = 'https://raw.githubusercontent.com/mishakorzik/AllHackingTools/main/Castom/system.txt'
    try:
        sys_rqst = requests.get(sys_url)
        if sys_rqst.status_code == 200:
            github_sys = sys_rqst.text.strip()
            if systemR == github_sys:  # systemR = 'QruWn'
                print("[+] System configuration checked! There are no failures")
                os.system("cd && cd AllHackingTools && python3 .check/FileConfiguration.py")
            else:
                # Emulación engañosa de errores
                print("[-] Error code: 106 DNS server refused to connect")
                print("[-] Error code: 503 Service Unavailable! Retry-After")
                os.system("cd && bash AllHackingTools/.check/ConfigurationOptions.sh") # exit
    except Exception as e:
        print("[-] Critical Error code: 105 Maybe you dont have internet")
```

### Hallazgos de Seguridad
- **Token Arbitrario en Texto Plano:** La clave de desbloqueo es un string simple (`'QruWn'` y `'WJins82bsOx'`). El autor del repositorio puede invalidar todas las instalaciones mundiales con un único commit en GitHub.
- **Engaño del Operador:** La herramienta no declara al usuario que su funcionamiento depende de un kill-switch, sino que falsifica errores HTTP (`503 Service Unavailable`, `502 Bad Gateway`, `106 DNS refusal`), haciendo creer al operador que existe un fallo en sus proveedores de red locales.
- **Cascada de Bloqueo:** Si el primer chequeo tiene éxito, encadena síncronamente con un segundo script (`FileConfiguration.py`) que realiza una segunda petición a `systemfile.txt`, duplicando la latencia y los puntos de fallo.

---

## 🛡️ 3. Criterios de Auditoría y Verificación de Soberanía Local

Al auditar herramientas y runners de seguridad, el agente debe aplicar los siguientes controles de verificación:

### 3.1. Principio Offline-First Obligatorio
Las herramientas de auditoría, SAST, escaneo o utilidades de línea de comandos deben poder ejecutarse completamente sin acceso a internet:
- Las firmas, diccionarios y reglas deben residir en paquetes locales versionados.
- Ninguna verificación de arranque debe bloquearse ante la ausencia de interfaz de red activa.

### 3.2. Prohibición de Dependencias hacia Raw GitHub en Runtime
Queda prohibido el uso de URLs de tipo `raw.githubusercontent.com/<user>/<repo>/...` en llamadas síncronas de inicialización para validar versiones, configuraciones o permisos.
- Si se implementa un mecanismo de comprobación de actualizaciones (`update check`), este debe ser asíncrono, no bloqueante y configurable mediante flag (`--no-update-check` o variable de entorno `CI=true`).

### 3.3. Transparencia Epistemológica en el Manejo de Excepciones
Si una comprobación de red falla, el error debe reportar la causa real (e.g. `ConnectionRefusedError: No se pudo contactar el endpoint de verificación`). Queda estrictamente prohibida la emisión de códigos de error HTTP ficticios que induzcan a engaño sobre el estado del sistema.
