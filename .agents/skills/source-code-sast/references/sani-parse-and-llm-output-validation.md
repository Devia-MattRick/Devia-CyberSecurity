# Sani-Parse Invariable: Validación Estricta de Salidas No Deterministas de LLMs

> **ID de Vulnerabilidad:** `VULN-ARCH-005`  
> **Taxonomía:** CWE-20 (*Improper Input Validation*) / CWE-74 (*Improper Neutralization of Special Elements*) / OWASP LLM02:2025 / OWASP LLM05:2026  
> **Dimensión:** `SOURCE_CODE_SAST`  
> **Skill:** `source-code-sast`  

---

## 1. El Riesgo de Deserialización Ciega de Salidas de IA

Los modelos de lenguaje grandes (LLMs) generan salidas estocásticas y no deterministas. Tratar el texto devuelto por una API de IA mediante `JSON.parse` directo sin una capa de normalización y validación estricta introduce graves riesgos:
1. **Inyección de Código y Prototype Pollution:** Respuestas con propiedades reservadas (`__proto__`, `constructor`) o payloads malformados.
2. **Corrupción del Estado Reactivo:** Objetos con campos omitidos, tipos erróneos (strings en lugar de números) o arrays incompletos que provocan caídas silenciosas en el frontend o backend.
3. **Alucinaciones Estructurales:** Respuestas del modelo que envuelven el JSON en bloques Markdown (````json ... ````), comentarios en prosa o delimitadores corruptos.

---

## 2. El Patrón Canónico Sani-Parse Invariable

El protocolo **Sani-Parse Invariable** impone dos pasos secuenciales obligatorios antes de admitir cualquier dato de LLM en el estado de la aplicación:

```
[Salida Cruda del LLM (String)]
              │
              ▼
    1. Desempaquetado Polimórfico (normalizeJsonArray / extractJson)
       - Extraer bloque JSON ignorando prosa o backticks Markdown
       - Convertir respuestas tipo objeto individual en arrays uniformes
              │
              ▼
    2. Validación de Esquema en Runtime (Zod safeParse)
       - Comprobación estricta de tipos, rangos numéricos y cadenas
       - Descarte inmediato de entradas no conformes con registro de error
              │
              ▼
[Estado Validado y Seguro (Typed Domain Objects)]
```

---

## 3. Implementación Canónica con Zod

```typescript
// 1. Utilidad de desempaquetado polimórfico
export function normalizeJsonArray<T = unknown>(rawOutput: string): T[] {
  let cleaned = rawOutput.trim();
  
  // Purgar delimitadores de bloque de código Markdown
  const markdownMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (markdownMatch) {
    cleaned = markdownMatch[1].trim();
  }

  try {
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) {
      return parsed;
    }
    if (parsed && typeof parsed === 'object') {
      // Manejar respuestas envueltas en { data: [...] } o { leads: [...] }
      const arrayKey = Object.keys(parsed).find(k => Array.isArray(parsed[k]));
      if (arrayKey) return parsed[arrayKey];
      return [parsed as T];
    }
    return [];
  } catch {
    return [];
  }
}

// 2. Validación estricta con schema de Zod
export function parseAndValidateLlmOutput<T>(
  rawText: string,
  schema: z.ZodSchema<T>
): { valid: T[]; rejectedCount: number } {
  const candidates = normalizeJsonArray(rawText);
  const valid: T[] = [];
  let rejectedCount = 0;

  for (const item of candidates) {
    const result = schema.safeParse(item);
    if (result.success) {
      valid.push(result.data);
    } else {
      rejectedCount++;
      console.warn('Registro LLM descartado por violación de esquema:', result.error.format());
    }
  }

  return { valid, rejectedCount };
}
```

---

## 4. Checklist de Auditoría

- [ ] ¿Existe ausencia total de llamadas directas a `JSON.parse` sobre respuestas de LLM sin envoltorio `try/catch`?
- [ ] ¿Toda salida parseada se somete a `schema.safeParse()` de Zod antes de propagarse a la base de datos o UI?
- [ ] ¿Se eliminan o ignoran campos no declarados en el esquema (`.strip()` por defecto en Zod)?
