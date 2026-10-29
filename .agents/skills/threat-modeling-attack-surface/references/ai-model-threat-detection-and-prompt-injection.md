# Detección Multicapa de Inyección de Prompts y Evasión Unicode en Modelos de IA

Este documento establece la metodología canónica para identificar y neutralizar ataques contra aplicaciones de Inteligencia Artificial basadas en Grandes Modelos de Lenguaje (LLMs) y pipelines RAG (*Retrieval-Augmented Generation*), cubriendo inyecciones de prompt directas/indirectas, esteganografía de texto y manipulación de artefactos de modelos (OWASP LLM Top 10 y MITRE ATLAS).

---

## 🏛️ 1. Taxonomía de Vectores de Ataque en Sistemas LLM

| Vector de Ataque | Clasificación OWASP / ATLAS | Mecanismo de Evasión / Explotación |
| :--- | :--- | :--- |
| **Inyección Directa (Jailbreaks)** | LLM01:2025 / AML.T0054 | Manipulación de turnos de usuario para forzar al modelo a ignorar directivas del sistema (`system_prompt_override`, `role_play_escape`). |
| **Inyección Indirecta (Cross-Prompt)** | LLM01:2025 / AML.T0051 | Cargas útiles maliciosas camufladas dentro de datos recuperados por el agente (páginas web scrapeadas, PDFs, transcripciones de audio, registros de base de datos). |
| **Contrabando de Etiquetas Unicode (ASCII Smuggling)** | LLM01:2025 / AML.T0015 | Inserción de caracteres en el bloque de etiquetas Unicode (`0xE0000 - 0xE007F`). Pasan invisibles para operadores y clasificadores convencionales pero son decodificados por tokenizadores LLM como instrucciones de control. |
| **Ofuscación por Ancho Cero (Zero-Width)** | LLM01:2025 / CWE-116 | Uso de caracteres invisibles (`\u200B` ZWSP, `\u200C` ZWNJ, `\u200D` ZWJ, `\uFEFF` BOM) para romper firmas regex o codificar instrucciones ocultas en binario. |
| **Envenenamiento de Artefactos (Pickle Deserialization)** | LLM04:2025 / AML.T0010 | Distribución de modelos de deep learning en formatos serializados (`.pt`, `.pkl`, `.bin`, `.ckpt`) con métodos mágicos `__reduce__` que ejecutan código arbitrario al cargarse. |

---

## 🔬 2. Detección y Neutralización de Contrabando Unicode y Caracteres Ocultos

### 2.1. Depuración del Rango de Etiquetas Unicode (ASCII Smuggling)
El bloque de etiquetas Unicode (`U+E0000` a `U+E007F`) fue diseñado originalmente para etiquetar idiomas pero ha sido reutilizado por adversarios para incrustar prompts invisibles:
```python
TAG_RANGE = set(range(0xE0000, 0xE0080))

def sanitize_unicode_tags(text: str) -> tuple[str, int]:
    stripped = []
    tag_count = 0
    for ch in text:
        if ord(ch) in TAG_RANGE:
            tag_count += 1
        else:
            stripped.append(ch)
    return "".join(stripped), tag_count
```
> [!CRITICAL]
> La presencia de $\ge 1$ caracteres en el rango `TAG_RANGE` en entradas de usuario o fuentes RAG debe considerarse un intento malicioso deliberado (**CRITICAL**).

### 2.2. Normalización de Caracteres de Ancho Cero
Los caracteres invisibles deben despojarse antes de procesar el texto con cualquier clasificador:
```python
ZERO_WIDTH_CHARS = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\ufeff"), None)

def sanitize_invisible_characters(text: str) -> str:
    # 1. Elimina caracteres de ancho cero
    clean = text.translate(ZERO_WIDTH_CHARS)
    # 2. Normaliza mediante compatibilidad canónica NFKC
    import unicodedata
    return unicodedata.normalize("NFKC", clean)
```

---

## 🛡️ 3. Firmas Heurísticas de Detección de Prompt Injection

Todo pipeline de ingesta de texto antes de transferir datos a un planificador LLM debe evaluar las 4 familias de firmas canónicas:

1. **System Prompt Override:**
   `(?i)\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|system|initial)\b.{0,20}\b(instructions?|prompts?|rules?|directives?)\b`
2. **Role Play Escape / Jailbreak:**
   `(?i)\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|simulate\s+being|switch\s+to|enter\s+.{0,10}mode)\b`
3. **Instruction Hijack:**
   `(?i)\b(do\s+not\s+follow|new\s+instructions?|instead\s+(do|say|output|respond))\b`
4. **Data Exfiltration / Leak:**
   `(?i)\b(reveal|print|leak|exfiltrate)\b.{0,25}\b(system\s+prompt|secret|api_key|password|token)\b`

---

## 📦 4. Integridad Criptográfica de Modelos y Prohibición de Pickle (AML.T0010)

Para mitigar la ejecución de código arbitrario al importar pesos de redes neuronales:
1. **Formatos Estrictamente Prohibidos en Entornos de Producción:**
   Queda terminantemente prohibido cargar archivos `.pkl`, `.pickle`, `.bin`, `.pt`, `.ckpt` o `.joblib` procedentes de repositorios públicos (Hugging Face, GitHub) sin un entorno de sandbox estricto y desacoplado de la red.
2. **Obligatoriedad de Safetensors:**
   Exigir el uso exclusivo de `safetensors`. Este formato almacena tensores de forma determinista y plana sin serialización de código ejecutable, neutralizando totalmente ataques de deserialización en Capa de ML.
3. **Verificación Criptográfica:** Contrastar el hash SHA-256 de los pesos del modelo contra el manifiesto inmutable del fabricante.

---

## 🏛️ 5. Gobernanza Dimensional MECE

Todos los análisis de ataques a modelos de lenguaje, vectores adversarios de prompting y envenenamiento de modelos se clasifican rigurosamente en la dimensión:
**`THREAT_MODELING_ATTACK_SURFACE`**
utilizando el contrato autoritativo `ThreatDetectionReportSchema`.
