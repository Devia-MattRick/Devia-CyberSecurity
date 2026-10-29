# Defensas de Centinela para Agentes Autónomos e Integridad de Memoria (OpenClaw Sentinel)

Este documento condensa los patrones defensivos, heurísticas de inspección y contramedidas absorbidas del ecosistema **Gideon / OpenClaw Sentinel**, diseñadas para mitigar la inyección indirecta de prompts, el envenenamiento de memoria persistente (*Long-Term Memory Poisoning*) y la degradación de límites de confianza en agentes de IA.

---

## 🛡️ 1. Detección de Instrucciones Ocultas por CSS (CVE-2026-22708)

### Mecánica del Ataque
Los atacantes insertan directivas maliciosas en páginas web o documentación externa formateada con CSS para hacerlas invisibles a los humanos pero legibles por herramientas de web scraping de agentes (`browser`, `fetch`, `curl`).

### Expresiones Regulares de Detección Heurística:
```typescript
export const CSS_HIDDEN_PATTERNS = [
  // Elementos con display:none y verbos de control de agente
  /style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // Elementos con visibility:hidden
  /style\s*=\s*["'][^"']*visibility\s*:\s*hidden[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // Texto con tamaño de fuente cero (font-size: 0)
  /style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // Opacidad cero (opacity: 0)
  /style\s*=\s*["'][^"']*opacity\s*:\s*0[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke|system|prompt)/i,
  // Clases CSS de accesibilidad o utilitarias abusadas
  /class\s*=\s*["'][^"']*(?:hidden|invisible|sr-only|visually-hidden|d-none|hide)[^"']*["'][^>]*>[^<]*(?:ignore|disregard|forget|override|instead|execute|run|call|invoke)/i,
  // Posicionamiento fuera de pantalla (off-screen)
  /style\s*=\s*["'][^"']*position\s*:\s*absolute[^"']*(?:left|top)\s*:\s*-\d{4,}[^"']*["'][^>]*>[^<]+/i
];
```

---

## 🔤 2. Esteganografía y Ofuscación Unicode

Los adversarios inyectan caracteres de control no imprimibles o mezclan alfabetos (homóglifos) para ocultar instrucciones a los analizadores sintácticos estándar.

```typescript
export const UNICODE_OBFUSCATION_PATTERNS = [
  /\u202E/,               // Right-to-left override (U+202E)
  /\u202D/,               // Left-to-right override (U+202D)
  /\u200B{3,}/,           // Zero-width space repetido (U+200B)
  /\u200C{3,}/,           // Zero-width non-joiner (U+200C)
  /\u200D{3,}/,           // Zero-width joiner (U+200D)
  /\u2060{3,}/,           // Word joiner (U+2060)
  /\u2063{3,}/,           // Invisible separator (U+2063)
  /[\uE0001-\uE007F]{3,}/,// Unicode Tag Characters (steganography)
  // Homoglyph mixing (Cyrillic + Latin alternado)
  /(?:[\u0400-\u04FF][\u0041-\u005A\u0061-\u007A]){2,}/,
  /(?:[\u0041-\u005A\u0061-\u007A][\u0400-\u04FF]){2,}/
];
```

---

## 🧠 3. Monitor de Integridad de Memoria Persistente (Long-Term Memory Poisoning - `VULN-ARCH-010`)

### El Riesgo
Muchos agentes almacenan hechos aprendidos en archivos Markdown o bases de vectores (`memory/YYYY-MM-DD.md`, `MEMORY.md`). Un atacante puede alimentar al modelo con "hechos" que en realidad son instrucciones de ejecución diferida.

### Indicadores de Envenenamiento de Memoria:
```typescript
export const MEMORY_POISONING_INDICATORS = [
  {
    pattern: /(?:always|never)\s+(?:run|execute|call|use)\s+(?:commands?\s+)?(?:without|with)\s+(?:confirmation|approval|asking)/i,
    reason: "Instrucción de omisión de aprobaciones humanas disfrazada de hecho",
    severity: "CRITICAL"
  },
  {
    pattern: /(?:your|the)\s+(?:new|updated|correct|real)\s+(?:api[_\s-]?key|token|password|secret|credential)\s+(?:is|=|:)\s+/i,
    reason: "Inyección de credenciales falsas o manipuladas en la memoria",
    severity: "CRITICAL"
  },
  {
    pattern: /(?:disable|turn\s+off|remove)\s+(?:security|safety|sandboxing|docker|approval|verification)/i,
    reason: "Instrucción para desactivar controles o aislamiento de seguridad",
    severity: "CRITICAL"
  },
  {
    pattern: /(?:send|forward|copy|upload)\s+(?:all\s+)?(?:data|files?|conversations?|messages?)\s+to\s+https?:\/\//i,
    reason: "Directiva de exfiltración persistida como memoria de trabajo",
    severity: "CRITICAL"
  },
  {
    pattern: /you\s+are\s+(?:now|actually|really)\s+(?:a|an|in)\s+(?:unrestricted|admin|root|superuser|god)\s+mode/i,
    reason: "Manipulación de rol o modo de operación alojado en memoria",
    severity: "HIGH"
  }
];
```

---

## 🔒 4. Aislamiento de Sandbox y Fallback Seguro (Fail-Closed)

### Antipatrón Observado en Gideon (`VULN-ARCH-009`)
```typescript
// VULNERABLE: Fail-Open
try {
  return await this.sandbox.execute(sessionId, command);
} catch {
  // Si Docker falla, ejecuta directamente en el host anfitrión!
  return await this.sandbox.executeDirect(command);
}
```

### Patrón Seguro en Devia-CyberSecurity:
1. **Fallo Cerrado Estricto (Fail-Closed):** Si el sandbox de aislamiento no está disponible o falla, la operación de riesgo **debe ser rechazada inmediatamente**.
2. **Sin Red Host:** Prohibir terminantemente `--net=host` en la ejecución de contenedores de herramientas.
3. **Validación Tokenizada:** Pasar argumentos en listas inmutables (`spawn(["tool", arg1, arg2])`), erradicando `sh -c` y `shell=True`.
