# Detección de Condiciones de Carrera con HTTP/2 Single-Packet Attack y Bloqueos Atómicos

> **ID de Vulnerabilidad:** `VULN-SAST-005`  
> **Taxonomía:** CWE-362 (*Concurrent Execution using Shared Resource with Improper Synchronization / 'Race Condition'*) / OWASP Top 10 A04:2021/2025  
> **Dimensión:** `SOURCE_CODE_SAST`  
> **Skill:** `source-code-sast`  

---

## 1. Patrones de Código Vulnerables (Check-Then-Act)

Las condiciones de carrera suelen originarse por la separación temporal entre la verificación de una precondición y la ejecución de la acción sobre un recurso compartido (*Time-of-Check to Time-of-Use - TOCTOU*):

```typescript
// VULNERABLE — Check-then-act sin bloqueo transaccional
app.post('/api/redeem-coupon', async (req, res) => {
  const coupon = await db.coupons.findUnique({ where: { code: req.body.code } });
  
  if (coupon.usesRemaining > 0) {
    // VENTANA DE CARRERA: Múltiples peticiones concurrentes leen usesRemaining > 0 antes de decrementar
    await applyDiscount(req.user.id, coupon.value);
    await db.coupons.update({
      where: { code: req.body.code },
      data: { usesRemaining: coupon.usesRemaining - 1 }
    });
    return res.json({ success: true });
  }
  return res.status(400).json({ error: 'Cupón agotado' });
});
```

---

## 2. Metodología de Explotación Adversarial (HTTP/2 Single-Packet Attack)

Con HTTP/1.1, la fluctuación de red (network jitter) dificulta que múltiples peticiones lleguen en el mismo milisegundo al servidor. Sin embargo, con **HTTP/2 multiplexing**, es posible enviar múltiples peticiones en un solo paquete TCP (Single-Packet Attack):
- Se envían los encabezados de 20 a 50 peticiones concurrentes a través de streams HTTP/2 paralelos.
- Se retiene el último byte del cuerpo de cada petición.
- Se libera simultáneamente el último frame (`DATA` frame con flag `END_STREAM`) en un único paquete TCP, provocando que el servidor procese todas las solicitudes exactamente en el mismo ciclo de CPU.

---

## 3. Patrones de Mitigación y Remediación Canónica

### 3.1 Bloqueo Pesimista en Base de Datos (`SELECT ... FOR UPDATE`)
```sql
BEGIN;
SELECT uses_remaining FROM coupons WHERE code = 'PROMO2026' FOR UPDATE;
-- El registro queda bloqueado a nivel de fila hasta el COMMIT
UPDATE coupons SET uses_remaining = uses_remaining - 1 WHERE code = 'PROMO2026';
COMMIT;
```

### 3.2 Actualizaciones Atómicas con Condición en el `UPDATE`
```sql
UPDATE coupons 
SET uses_remaining = uses_remaining - 1 
WHERE code = 'PROMO2026' AND uses_remaining > 0;
-- Verificar si affected_rows == 1. Si es 0, el cupón ya no tenía saldo.
```

### 3.3 RPCs Atómicas en Bases de Datos Gestionadas (PostgreSQL / Supabase)
```sql
CREATE OR REPLACE FUNCTION redeem_coupon_atomic(p_code TEXT, p_user_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
  v_remaining INT;
BEGIN
  UPDATE coupons 
  SET uses_remaining = uses_remaining - 1 
  WHERE code = p_code AND uses_remaining > 0
  RETURNING uses_remaining INTO v_remaining;

  IF v_remaining IS NOT NULL THEN
    INSERT INTO coupon_redemptions(user_id, coupon_code) VALUES (p_user_id, p_code);
    RETURN TRUE;
  END IF;

  RETURN FALSE;
END;
$$;
```

---

## 4. Checklist de Auditoría SAST

- [ ] ¿Las operaciones que verifican saldo, cuotas o cupones aplican bloqueos de fila (`FOR UPDATE`) o condiciones de guardas atómicas en el `UPDATE`?
- [ ] ¿Existe ausencia de lecturas previas (`findUnique`) seguidas de escrituras separadas sin transacción envolvente?
- [ ] ¿Se realizan pruebas de carga concurrente con herramientas como Turbo Intruder utilizando ráfagas HTTP/2?
