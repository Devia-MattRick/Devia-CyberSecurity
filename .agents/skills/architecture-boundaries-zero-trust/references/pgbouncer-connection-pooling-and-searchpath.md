# Aislamiento de Sesión en PgBouncer Transaccional y Mitigación de Search-Path (CVE-2018-1058)

Esta referencia técnica define los controles de arquitectura y fronteras de aislamiento para conexiones multiplexadas en PostgreSQL mediante gestores de balanceo de conexiones (**PgBouncer**, **Odyssey**, **AWS RDS Proxy**) y endurecimiento de rutinas contra secuestro de resolución de esquemas, mitigando de forma integral `VULN-ARCH-022` y `VULN-CONF-007`.

---

## 🏛️ 1. El Antipatrón de Contaminación de Sesión en Transaction Pooling

En arquitecturas de alta concurrencia, PgBouncer se configura habitualmente en modo transacción (`pool_mode = transaction`). En este modo, una conexión física del servidor PostgreSQL se asigna dinámicamente al socket cliente únicamente durante la duración de una transacción (`BEGIN ... COMMIT/ROLLBACK`), devolviéndose de inmediato al grupo compartido al terminar.

### Mecanismo de Falla
Si el software inyecta el identificador de inquilino mediante sentencias de alcance de sesión:
```sql
-- VULNERABLE: Persiste en la conexión física tras el fin de la transacción
SET app.current_tenant = 'tenant-a-uuid';
-- O alternativamente:
SELECT set_config('app.current_tenant', 'tenant-a-uuid', false);
```
El valor queda grabado en la memoria de la sesión física de PostgreSQL. Al completarse la transacción, PgBouncer devuelve la conexión al grupo compartido sin purgar el estado. Si la siguiente solicitud de un **Inquilino B** reutiliza esa conexión y sufre un error antes de asignar su propio contexto, o invoca un endpoint secundario, **todas las consultas se ejecutarán con los privilegios y datos del Inquilino A**, provocando una filtración masiva silenciosa de datos entre clientes.

### Patrón Seguro: Ámbito Local Obligatorio
El contexto debe fijarse exclusivamente con ámbito transaccional:
```sql
-- SEGURO: La variable se purga automáticamente e incondicionalmente al emitir COMMIT o ROLLBACK
SET LOCAL app.current_tenant = 'tenant-a-uuid';
-- O mediante función parametrizada:
SELECT set_config('app.current_tenant', 'tenant-a-uuid', true);
```
El tercer parámetro (`is_local = true`) garantiza que el motor PostgreSQL descarte el valor en memoria de forma determinista al cerrar la transacción.

---

## ⚙️ 2. Hardening de Configuración en `pgbouncer.ini`

Para proteger el entorno contra desconexiones anómalas o clientes maliciosos que omitan transacciones limpias:

```ini
[databases]
app_production = host=127.0.0.1 port=5432 dbname=app_production

[pgbouncer]
listen_port = 6432
listen_addr = 0.0.0.0
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 10000
default_pool_size = 100

; DIRECTIVA CRÍTICA: Forzar el descarte total de variables de sesión, tablas temporales
; y estados residuales si una conexión física retorna al grupo
server_reset_query = DISCARD ALL
server_check_query = SELECT 1
```

---

## 🛡️ 3. Mitigación de Secuestro de `search_path` en Funciones `SECURITY DEFINER` (CVE-2018-1058)

En esquemas donde coexisten usuarios con permisos de creación de objetos (o esquemas históricos donde `public` retiene permisos de escritura para `PUBLIC`), un atacante puede crear tablas, operadores o funciones con el mismo nombre que objetos del sistema (`logs`, `users`, `now`).

Cuando una función declarada con `SECURITY DEFINER` (que adopta la identidad de su creador, usualmente un superusuario o rol de migración) se ejecuta sin un `search_path` calificado, el motor resuelve prioritariamente el objeto malicioso del atacante, resultando en **escalada vertical de privilegios hacia el dueño de la función**.

### Patrón de Código Endurecido
Toda función con privilegios elevados debe declarar taxativamente un `search_path` seguro e inmutable en su propia cabecera:

```sql
-- Función endurecida con fijación inmutable de espacio de nombres
CREATE OR REPLACE FUNCTION maintenance.purge_expired_audit_logs(retention_days integer)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, core, pg_temp
AS $$
BEGIN
  -- Se referencian objetos plenamente cualificados
  DELETE FROM core.audit_logs 
  WHERE created_at < pg_catalog.now() - (retention_days || ' days')::interval;
END;
$$;
```
> [!IMPORTANT]
> La inclusión obligatoria de `pg_temp` **al final de la lista** impide que tablas temporales inyectadas durante la sesión del usuario intercepten la resolución de nombres del definidor.

---

## 🕵️ 4. Consulta Forense para Catálogos de Base de Datos

Para identificar funciones con privilegios elevados (`SECURITY DEFINER`) que omitan la declaración de un `search_path` protegido:

```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS function_owner,
    p.prosecdef AS is_security_definer,
    p.proconfig AS execution_settings
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND (
    p.proconfig IS NULL 
    OR NOT EXISTS (
        SELECT 1 FROM unnest(p.proconfig) cfg 
        WHERE cfg LIKE 'search_path=%'
    )
  )
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY schema_name, function_name;
```

---

## 🛠️ 5. Regla Semgrep para Pipelines CI/CD

```yaml
rules:
  - id: postgres-session-leak-pooler-set-config
    languages: [javascript, typescript, python, go, java]
    severity: ERROR
    message: >-
      Se detectó asignación de contexto con alcance de sesión (is_local=false o SET global).
      En esquemas con transaction pooling (PgBouncer), esto causa contaminación cruzada
      de sesiones entre distintos inquilinos (VULN-ARCH-022, CWE-668).
    pattern-either:
      - pattern: $DB.query("SET app.tenant_id = ...")
      - pattern: $DB.query("SET search_path TO ...")
      - pattern: $CLIENT.query("SELECT set_config($PARAM, $VAL, false)", ...)
      - pattern: $CONN.execute(text("SET app.tenant_id = :id"), ...)
```
