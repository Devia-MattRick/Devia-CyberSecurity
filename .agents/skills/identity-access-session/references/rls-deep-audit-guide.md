# Guía de Auditoría Forense de Políticas RLS y Aislamiento Multi-Tenant

> **Dimensión:** `IDENTITY_ACCESS_SESSION`  
> **Taxonomía:** CWE-639 / CWE-862 / CWE-250 / OWASP A01:2021  
> **Origen de Absorción:** `security-audit/Cybersecurity-Audit/references/rls-deep-audit.sql` (Acción `ABS-003`)  
> **Vulnerabilidad Asociada:** `VULN-IAM-001` (Broken Object Level Authorization - IDOR / BOLA)  

---

## 🏛️ Contexto y Riesgo de Seguridad

En arquitecturas multi-tenant basadas en PostgreSQL y Supabase, **Row Level Security (RLS)** constituye la última línea de defensa para garantizar que ningún usuario o tenant pueda acceder, alterar o eliminar registros ajenos.

Sin embargo, auditorías forenses demuestran que las brechas más críticas en RLS no se deben a la ausencia total de políticas, sino a:
1. Tablas en el esquema `public` con RLS desactivado por descuido durante migraciones.
2. Invocación de funciones de sesión como `get_user_tenant_id()` de forma **desnuda (*bare function*)**, obligando al optimizador de Postgres a re-ejecutar la función para cada fila evaluada ($O(N)$), degradando el rendimiento o provocando fallos por timeout que abren vías de bypass.
3. Tablas con columna `tenant_id` donde ninguna policy valida la pertenencia de dicho tenant.
4. Funciones `SECURITY DEFINER` que se ejecutan con privilegios de superusuario/propietario pero no fijan explícitamente `SET search_path = public`, permitiendo el **secuestro de ruta de búsqueda (*search_path hijacking*)** y la escalada de privilegios.

---

## 🔍 Consultas Forenses al Catálogo del Sistema (PostgreSQL)

Las siguientes 6 consultas SQL son de **solo lectura** y deben ejecutarse contra los catálogos del sistema (`pg_tables`, `pg_policies`, `pg_proc`).

### Q1. Tablas en esquema `public` sin RLS Habilitado
Cualquier tabla devuelta representa una **violación crítica de la frontera de aislamiento**.
```sql
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public'
  AND rowsecurity = false
ORDER BY tablename;
```
*Remediación:*
```sql
ALTER TABLE public.<nombre_tabla> ENABLE ROW LEVEL SECURITY;
```

### Q2. Inventario de Cobertura de Políticas por Comando
Verifica que las tablas no solo tengan RLS habilitado, sino que definan políticas para todos los comandos DML (`SELECT`, `INSERT`, `UPDATE`, `DELETE`):
```sql
SELECT t.tablename,
       count(p.policyname) AS policy_count,
       string_agg(DISTINCT p.cmd, ', ') AS commands
FROM pg_tables t
LEFT JOIN pg_policies p ON p.schemaname = t.schemaname AND p.tablename = t.tablename
WHERE t.schemaname = 'public'
GROUP BY t.tablename
ORDER BY policy_count ASC, t.tablename;
```
*Regla de Oro:* Una tabla con datos de negocio, columna `tenant_id` y `policy_count = 0` bloquea el acceso o queda expuesta si se desactiva RLS.

### Q3. Detección del Patrón Deprecado `auth.jwt() ->> 'tenant_id'`
Extraer el `tenant_id` directamente del JWT en cada fila es vulnerable a manipulaciones de claims y desincronización de base de datos:
```sql
SELECT schemaname, tablename, policyname, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
  AND (qual LIKE '%auth.jwt()%tenant_id%' OR with_check LIKE '%auth.jwt()%tenant_id%');
```

### Q4. Detección de Invocación Bare de `get_user_tenant_id()` (Sin Subconsulta Escalar)
PostgreSQL no puede convertir una función en `InitPlan` si no está envuelta en `(SELECT ...)`. Una llamada directa provoca re-evaluación fila por fila ($O(N)$):
```sql
SELECT schemaname, tablename, policyname, cmd
FROM pg_policies
WHERE schemaname = 'public'
  AND (
    (qual ~ 'get_user_tenant_id\(\)' AND qual !~ '\(\s*SELECT\s+get_user_tenant_id\(\)\s*\)')
    OR
    (with_check ~ 'get_user_tenant_id\(\)' AND with_check !~ '\(\s*SELECT\s+get_user_tenant_id\(\)\s*\)')
  );
```
*Patrón Vulnerable / Lento:*
```sql
-- Re-ejecuta para cada fila de la tabla
CREATE POLICY "tenant_isolation" ON contacts
FOR ALL USING (tenant_id = get_user_tenant_id());
```
*Patrón Seguro y Optimizado (InitPlan O(1)):*
```sql
-- Se evalúa una sola vez al inicio de la consulta
CREATE POLICY "tenant_isolation" ON contacts
FOR ALL USING (tenant_id = (SELECT get_user_tenant_id()));
```

### Q5. Tablas Multi-Tenant sin Policy que Valide `tenant_id`
Tablas que poseen la columna `tenant_id` pero cuyas políticas ignoran el aislamiento:
```sql
SELECT c.relname AS tabla_con_tenant_id
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN information_schema.columns col
  ON col.table_schema = n.nspname AND col.table_name = c.relname AND col.column_name = 'tenant_id'
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND NOT EXISTS (
    SELECT 1 FROM pg_policies p
    WHERE p.schemaname = 'public' AND p.tablename = c.relname
      AND (p.qual LIKE '%tenant_id%' OR p.with_check LIKE '%tenant_id%')
  )
ORDER BY c.relname;
```

### Q6. Funciones `SECURITY DEFINER` sin Fijación de `search_path`
Una función `SECURITY DEFINER` que no fija `search_path` permite a un usuario no privilegiado crear tablas u operadores homónimos en un esquema temporal y lograr RCE como superusuario:
```sql
SELECT n.nspname, p.proname, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.prosecdef = true
  AND (p.proconfig IS NULL OR NOT EXISTS (
    SELECT 1 FROM unnest(p.proconfig) cfg WHERE cfg LIKE 'search_path=%'
  ));
```
*Remediación Inmediata:*
```sql
ALTER FUNCTION public.<nombre_funcion>(...) SET search_path = public;
```
