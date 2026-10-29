# Guía Defensiva de Aislamiento PostgreSQL RLS y Esquemas Multi-Tenant

Esta referencia establece las directivas canónicas de ingeniería de base de datos para garantizar la estricta segregación de datos en plataformas multi-tenant basadas en PostgreSQL con **Row-Level Security (RLS)** y esquemas compartidos, mitigando de forma integral `VULN-IAM-001`.

---

## 🏛️ 1. Las 7 Leyes Inmutables de PostgreSQL RLS

1. **Forzado Obligatorio sobre el Propietario (`FORCE ROW LEVEL SECURITY`):**  
   Por diseño en PostgreSQL, el propietario de la tabla (`table owner`) ignora las políticas RLS a menos que se aplique expresamente `ALTER TABLE ... FORCE ROW LEVEL SECURITY`. El uso exclusivo de `ENABLE ROW LEVEL SECURITY` expone el 100% de los datos a cualquier conexión con credenciales del dueño o roles de migración.
2. **Políticas Restrictivas Simétricas (`USING` y `WITH CHECK`):**  
   Las políticas permisivas (`AS PERMISSIVE`) se combinan mediante disyunción booleana (`OR`), abriendo brechas cuando coexisten múltiples reglas. Las directivas de aislamiento entre inquilinos deben declararse como restrictivas (`AS RESTRICTIVE`), combinadas mediante conjunción (`AND`), y cubrir de manera idéntica la visibilidad de lectura (`USING`) y las mutaciones de escritura (`WITH CHECK`). Omitir `WITH CHECK` permite a un inquilino insertar tuplas asignadas a identidades ajenas.
3. **Manejo Fail-Closed de Cadenas Vacías con `NULLIF`:**  
   Si una transacción resetea o deja vacía la variable de contexto (`''`), una conversión directa `::uuid` aborta la transacción con error de sintaxis. La invocación debe envolverse en `NULLIF(current_setting('app.current_tenant', true), '')::uuid`, transformando cadenas vacías en `NULL`, lo que evalúa a falso y bloquea el acceso por defecto.
4. **Delegación de Invocador en Vistas (`security_invoker = true`):**  
   En PostgreSQL 15+, toda vista que exponga datos multi-tenant debe crearse con `WITH (security_invoker = true)`. De lo contrario, opera bajo la semántica de `SECURITY DEFINER` del creador de la vista, evadiendo las directivas RLS del usuario que consulta. Las vistas materializadas no soportan RLS y jamás deben exponerse directamente a la aplicación.
5. **Revocación Mandatoria de `TRUNCATE`:**  
   El comando DDL `TRUNCATE` no evalúa políticas RLS. El rol operativo de la aplicación (`app_runtime_user`) debe ser despojado del permiso `TRUNCATE` sobre todas las tablas de negocio.
6. **Integridad Referencial Compuesta `(tenant_id, id)`:**  
   Las claves foráneas simples sobre `id` permiten a un inquilino vincular registros secundarios propios a registros padre de competidores (IDOR relacional). Las tablas deben definir claves primarias compuestas `PRIMARY KEY (tenant_id, id)` y propagarlas a todas las claves foráneas.
7. **Aislamiento Transaccional Local en Connection Poolers:**  
   En servidores de pooling como PgBouncer operando en modo transacción (`pool_mode = transaction`), el contexto debe asignarse exclusivamente con `SET LOCAL` o `SELECT set_config('app.current_tenant', $1, true)`. El uso de `false` contamina la conexión física para solicitudes subsecuentes de otros clientes.

---

## 🛠️ 2. Patrón DDL Canónico de Implementación RLS

```sql
-- 1. Creación de tabla con clave primaria compuesta
CREATE TABLE core.invoices (
    id uuid DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    customer_id uuid NOT NULL,
    amount numeric(12, 2) NOT NULL CHECK (amount >= 0),
    created_at timestamptz DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT pk_invoices PRIMARY KEY (tenant_id, id)
);

-- 2. Habilitación y forzado obligatorio sobre el table owner
ALTER TABLE core.invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.invoices FORCE ROW LEVEL SECURITY;

-- 3. Definición de política restrictiva y simétrica
CREATE POLICY tenant_isolation_invoices ON core.invoices
    AS RESTRICTIVE
    FOR ALL
    TO app_runtime_user
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid
    );

-- 4. Creación de vista segura para reportería (PostgreSQL 15+)
CREATE VIEW reporting.invoices_summary WITH (security_invoker = true) AS
    SELECT id, tenant_id, customer_id, amount, created_at 
    FROM core.invoices;
```

---

## 🔐 3. Separación de Roles en Base de Datos

```sql
-- Rol de administración (DDL en CI/CD y migraciones)
CREATE ROLE db_migration_admin WITH LOGIN PASSWORD '***' NOSUPERUSER NOBYPASSRLS;
GRANT CREATE, USAGE ON SCHEMA core TO db_migration_admin;

-- Rol operativo de runtime (DML con mínimo privilegio)
CREATE ROLE app_runtime_user WITH LOGIN PASSWORD '***' NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA core TO app_runtime_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO app_runtime_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA core GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_runtime_user;

-- Clausura del vector de purga masiva
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA core FROM app_runtime_user;
```

---

## 🕵️ 4. Consultas Forenses sobre Catálogos para Auditoría

### 4.1. Detección de Tablas con RLS Incompleto o sin FORCE
```sql
SELECT
    n.nspname AS schema_name,
    c.relname AS table_name,
    c.relrowsecurity AS rls_enabled,
    c.relforcerowsecurity AS rls_forced,
    count(p.polname) AS total_policies
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
LEFT JOIN pg_policy p ON p.polrelid = c.oid
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
GROUP BY n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
HAVING NOT c.relrowsecurity 
    OR NOT c.relforcerowsecurity 
    OR count(p.polname) = 0
ORDER BY schema_name, table_name;
```

### 4.2. Detección de Vistas que Omiten `security_invoker`
```sql
SELECT 
    c.oid::regclass AS view_name, 
    c.relkind AS view_type, 
    pg_get_userbyid(c.relowner) AS view_owner, 
    t.oid::regclass AS referenced_rls_table, 
    t.relforcerowsecurity AS table_forced_rls 
FROM pg_class c 
JOIN pg_roles r ON r.oid = c.relowner 
JOIN pg_rewrite rw ON rw.ev_class = c.oid 
JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = rw.oid 
JOIN pg_class t ON t.oid = d.refobjid AND t.relrowsecurity AND t.oid <> c.oid 
WHERE c.relkind IN ('v', 'm') 
  AND NOT EXISTS (
    SELECT 1 FROM pg_options_to_table(c.reloptions) 
    WHERE option_name = 'security_invoker' 
      AND lower(option_value) IN ('true', 'on', '1', 'yes')
  ) 
GROUP BY 1, 2, 3, 4, 5 
ORDER BY view_name;
```

---

## 🧪 5. Suite de Verificación de Regresión con pgTAP

```sql
BEGIN;
SELECT plan(4);

SET ROLE db_migration_admin;
INSERT INTO core.invoices (id, tenant_id, customer_id, amount) 
VALUES 
    ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'cccccccc-cccc-cccc-cccc-cccccccccccc', 250.00),
    ('22222222-2222-2222-2222-222222222222', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 500.00);

SET ROLE app_runtime_user;

-- Test 1: Denegación por defecto sin contexto activo
SELECT is(
    (SELECT count(*) FROM core.invoices),
    0::bigint,
    'Sin contexto establecido, el acceso debe denegarse por defecto'
);

-- Test 2: Filtrado exclusivo para Tenant A
SELECT set_config('app.current_tenant', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', true);
SELECT is(
    (SELECT count(*) FROM core.invoices),
    1::bigint,
    'El Tenant A debe visualizar estrictamente sus propios registros'
);

-- Test 3: Bloqueo de registros del Tenant B
SELECT is(
    (SELECT count(*) FROM core.invoices WHERE tenant_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    0::bigint,
    'El Tenant A no debe acceder a registros del Tenant B'
);

-- Test 4: Rechazo de inserción cruzada hacia Tenant B (Código 42501)
SELECT throws_ok(
    $$ INSERT INTO core.invoices (id, tenant_id, customer_id, amount) 
       VALUES ('33333333-3333-3333-3333-333333333333', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 75.00) $$,
    '42501',
    NULL,
    'WITH CHECK debe rechazar inserciones dirigidas a identidades ajenas'
);

SELECT * FROM finish();
ROLLBACK;
```
