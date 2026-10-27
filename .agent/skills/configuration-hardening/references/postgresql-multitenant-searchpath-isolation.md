# Aislamiento Multi-Tenant en PostgreSQL y Prevención de Fallback a Public Schema

Este documento detalla las directivas arquitectónicas, riesgos de aislamiento y patrones de verificación para entornos multi-tenant basados en esquemas separados en PostgreSQL, fundamentado en las lecciones defensivas extraídas de **PentAGI**.

---

## 1. La Catástrofe Silenciosa del Fallback a `public` (`VULN-CONF-007`)

### 1.1. Mecanismo del Fallo
En arquitecturas SaaS multi-tenant donde cada cliente o tenant posee su propio esquema en PostgreSQL (`tenant_a`, `tenant_b`), la separación de datos depende de la directiva `search_path`:
```sql
SET search_path = tenant_a, public;
```

Si el DSN de conexión contiene un error tipográfico, una variable de entorno `TENANT_ID` mal formada, o el pooler de conexiones (como PgBouncer en modo transaction pooling) limpia las opciones de sesión:
1. PostgreSQL ignora la directiva errónea sin lanzar un error fatal.
2. La resolución de nombres de tabla se redirige silenciosamente al esquema `public`.
3. Todos los tenants terminan leyendo y escribiendo sobre las tablas del esquema `public`, compartiendo un único conjunto de datos sin que la aplicación emita alertas de error de base de datos (*Quiet, Catastrophic Data Leakage*).

---

## 2. El Patrón Defensivo `VerifySearchPath` (Fail-Closed)

Para erradicar este riesgo, el proceso backend debe validar obligatoriamente la concordancia entre el esquema esperado y el esquema efectivo inmediatamente después de establecer el pool de conexiones en el arranque:

```go
func VerifySearchPath(ctx context.Context, db *sql.DB, cfg *config.Config) error {
    if !cfg.HasTenant() {
        return nil
    }

    var current sql.NullString
    if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&current); err != nil {
        return fmt.Errorf("failed to verify search_path on database pool: %w", err)
    }

    if current.String != cfg.SchemaName() {
        return fmt.Errorf(
            "search_path resolved to schema %q, expected %q - refusing to start so tenants do not silently share one dataset",
            current.String, cfg.SchemaName(),
        )
    }

    return nil
}
```

### Invariantes de la Regla:
1. **Fallo Cerrado (*Fail-Closed*):** Si `current_schema()` no coincide exactamente con el `SchemaName()` del tenant, el proceso aborta inmediatamente su inicio con código de salida no cero.
2. **Validación Temprana:** Se ejecuta antes de procesar cualquier petición HTTP, WebSocket o tarea agéntica.
3. **Soporte de Poolers:** Si se utiliza un connection pooler externo, la directiva debe pasarse como parámetro de inicio de conexión a nivel de protocolo libpq (`-c search_path=tenant_schema,public`), o validarse por conexión individual si el pooler reasigna conexiones físicas.

---

## 3. Bloqueos Consultivos para Migraciones Multi-Tenant (`WithAdvisoryLock`)

Cuando múltiples instancias de la aplicación o trabajadores de un tenant se inician concurrentemente, intentar aplicar migraciones DDL (`ALTER TABLE`, `CREATE TABLE`) provoca bloqueos competitivos, deadlocks o inconsistencias en la tabla de control de migraciones.

### 3.1. Patrón de Bloqueo por Hash de Esquema
PostgreSQL ofrece bloqueos consultivos a nivel de aplicación (*Application-Level Advisory Locks*) que no alteran metadatos de tablas:

```go
func WithAdvisoryLock(ctx context.Context, db *sql.DB, lockName string, fn func(*sql.Conn) error) error {
    conn, err := db.Conn(ctx)
    if err != nil {
        return fmt.Errorf("failed to obtain database connection for advisory lock: %w", err)
    }
    defer conn.Close()

    // Derivar un entero de 64 bits estable a partir del nombre del bloqueo
    lockID := int64(crc32.ChecksumIEEE([]byte(lockName)))

    if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
        return fmt.Errorf("failed to acquire advisory lock for %s: %w", lockName, err)
    }
    defer conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockID)

    return fn(conn)
}
```

Al utilizar `lockName = "pentagi-migrations-" + cfg.SchemaName()`, las migraciones de diferentes tenants pueden ejecutarse en paralelo sin interferencia, mientras que instancias que compiten por el mismo tenant se serializan de forma segura.

---

## 4. Inyección Obligatoria de `statement_timeout` en DSN

Consultas analíticas pesadas o subconsultas no optimizadas generadas por agentes de IA pueden saturar los pools de conexiones y congelar la base de datos.

### Patrón de Inyección en DSN:
Toda cadena de conexión debe forzar un límite máximo de ejecución a nivel de sesión:
```go
func withStatementTimeout(dsn string, timeout time.Duration) (string, error) {
    parsed, err := url.Parse(dsn)
    if err != nil {
        return "", err
    }

    query := parsed.Query()
    if strings.Contains(query.Get("options"), "statement_timeout") {
        return dsn, nil // Respetar si el operador ya configuró un límite
    }

    setting := fmt.Sprintf("-c statement_timeout=%d", timeout.Milliseconds())
    if existing := query.Get("options"); existing != "" {
        setting = existing + " " + setting
    }

    query.Set("options", setting)
    parsed.RawQuery = query.Encode()
    return parsed.String(), nil
}
```
Esto garantiza que ninguna consulta huérfana o bucle de agente pueda retener una conexión activa más allá del límite configurado (por defecto 25–30 segundos).
