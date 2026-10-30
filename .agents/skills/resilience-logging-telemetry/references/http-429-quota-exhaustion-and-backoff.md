# Mitigación de Agotamiento de Cuotas HTTP 429 y AutoThrottle con Backoff Jitter

> **ID de Vulnerabilidad:** `VULN-RESI-013`  
> **Taxonomía:** CWE-400 (*Uncontrolled Resource Consumption*) / CWE-770 (*Allocation of Resources Without Limits or Throttling*) / OWASP LLM10:2026 / OWASP Top 10 A04:2021  
> **Dimensión:** `RESILIENCE_LOGGING_TELEMETRY`  
> **Skill:** `resilience-logging-telemetry`  

---

## 1. El Riesgo de Bucles Destructivos de Reintentos

Cuando un sistema interactúa con APIs de terceros o modelos de lenguaje (LLMs), un error de límite de tasa (**HTTP 429 Too Many Requests**) o cuota agotada (*Resource Exhausted*) puede desencadenar un bucle destructivo si la aplicación reintenta de inmediato:
1. **Consumo y Bloqueo de Cuenta:** Ráfagas continuas de peticiones fallidas provocan la suspensión temporal o permanente de la cuenta o API key por parte del proveedor.
2. **Saturación del Hilo de Ejecución:** El proceso se bloquea intentando resolver peticiones destinadas a fallar, provocando denegación de servicio a otros componentes locales.
3. **Pérdida de Dinero / Saldo:** En APIs con cobro por intento, reintentos agresivos sin retroceso pueden drenar el crédito del usuario en pocos minutos.

---

## 2. El Protocolo Kill-Switch `FatalQuotaError`

El protocolo impone una bifurcación estricta ante errores de cuota:
- Si el error 429 indica un límite transitorio de frecuencia por segundo (*rate limit*): aplicar **AutoThrottle con Backoff Jitter**.
- Si el error 429 indica agotamiento total de cuota o saldo (*daily/monthly quota exceeded*): lanzar un **`FatalQuotaError`** que interrumpe de inmediato toda la ráfaga de procesamiento en el orquestador principal (*Kill-Switch*).

```typescript
export class FatalQuotaError extends Error {
  constructor(public readonly provider: string, message: string) {
    super(`[FATAL QUOTA] Cuota de API agotada para el proveedor ${provider}: ${message}`);
    this.name = 'FatalQuotaError';
  }
}
```

---

## 3. Algoritmo de AutoThrottle con Exponential Backoff y Jitter

Para gestionar límites transitorios de peticiones por minuto (RPM) sin sincronizar ráfagas concurrentes:

$$\text{Delay} = \min\Big(\text{maxDelay}, \, \text{baseDelay} \times 2^{\text{attempt}}\Big) + \text{random}(0, \, \text{jitter})$$

```typescript
export async function executeWithBackoff<T>(
  operation: () => Promise<T>,
  maxRetries: number = 4,
  baseDelayMs: number = 1000,
  maxDelayMs: number = 16000
): Promise<T> {
  let attempt = 0;

  while (true) {
    try {
      return await operation();
    } catch (err: any) {
      attempt++;
      const statusCode = err?.status || err?.response?.status;
      const isQuotaFatal = err?.message?.includes('RESOURCE_EXHAUSTED') || err?.message?.includes('quota exceeded');

      if (isQuotaFatal) {
        throw new FatalQuotaError(err?.provider || 'LLM', err.message);
      }

      if (attempt > maxRetries || statusCode !== 429) {
        throw err;
      }

      // Calcular retardo exponencial con jitter aleatorio
      const exponentialDelay = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, attempt - 1));
      const jitter = Math.random() * (exponentialDelay * 0.2); // 20% jitter
      const totalDelay = exponentialDelay + jitter;

      console.warn(`[AutoThrottle] HTTP 429 detectado. Pausa defensiva de ${Math.round(totalDelay)}ms (Intento ${attempt}/${maxRetries})...`);
      await new Promise(resolve => setTimeout(resolve, totalDelay));
    }
  }
}
```

---

## 4. Checklist de Auditoría

- [ ] ¿Los clientes HTTP hacia proveedores de IA capturan explícitamente el código de estado 429?
- [ ] ¿Existe un Kill-Switch que aborta ráfagas de scraping o consultas masivas ante errores fatales de saldo?
- [ ] ¿Los reintentos transitorios aplican retroceso exponencial con variación aleatoria (*jitter*) para evitar tormentas de reconexión?
- [ ] ¿Los registros de log en memoria limitan su tamaño (ej. búfer circular de 500 entradas) para prevenir fugas de memoria durante ráfagas?
