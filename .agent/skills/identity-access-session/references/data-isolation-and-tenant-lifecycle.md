# Guía Autoritativa: Auditoría de Aislamiento de Datos Multi-Inquilino y Ciclo de Vida

**Dimensión Canónica:** `IDENTITY_ACCESS_SESSION`  
**Taxonomías:** CWE-639 (Insecure Direct Object Reference), CWE-284 (Improper Access Control), CWE-200 (Information Disclosure), OWASP A01:2021 (Broken Access Control)  
**Skill Asignada:** [`identity-access-session`](file:///.agent/skills/identity-access-session/SKILL.md)  
**Origen:** Absorción forense de Cloudflare Security Audit (`skills/security-audit/DATA-ISOLATION-AND-LIFECYCLE.md`)  

---

## 🏛️ 1. Disciplina Fundamental de Aislamiento de Datos

Al auditar aplicaciones SaaS o sistemas distribuidos que almacenan datos pertenecientes a múltiples inquilinos (*tenants*) o usuarios segregados:

1. **Un campo de inquilino o propietario en un registro NO es aislamiento:**  
   La presencia de una columna `tenant_id` o `user_id` en una fila o documento no garantiza protección por sí misma. El auditor debe rastrear y verificar la consulta específica, la política RLS, el predicado SQL o el middleware de acceso que aplica esa restricción en **todas** las rutas de lectura, actualización, listado y eliminación.
2. **Rastreo Obligatorio de Copias Derivadas:**  
   Los datos que están aislados en el almacén primario (PostgreSQL, MongoDB) frecuentemente se filtran cuando se replican hacia almacenes secundarios: índices de búsqueda (Elasticsearch, OpenSearch), cachés compartidas (Redis, Memcached), almacenes de objetos (S3, GCS), pipelines de analítica, logs estructurados o backups. Cada copia secundaria debe auditarse con su respectiva matriz de control de acceso.
3. **El Borrado y la Revocación son Contratos de Ciclo de Vida:**  
   Una promesa de eliminación de datos exige verificar copias activas, cachés, índices, copias en tránsito y backups. El bypass de registros con borrado lógico (*soft-delete*) constituye una brecha directa de confidencialidad.

---

## 🔍 2. Vectores de Ataque en Fronteras de Inquilinos y Objetos

### 2.1. Desacople entre Política Principal y Consultas Secundarias
- **Mecanismo:** El ORM o framework aplica un filtro de tenant por defecto (`defaultScope` en Sequelize, filtros globales en Prisma/TypeORM), pero ciertas operaciones utilizan clientes en crudo (`raw query`), vistas complejas, subconsultas de agregación o métodos `unscoped()` que omiten el filtro de inquilino.
- **Heurística de Detección:** Comparar todos los puntos donde se ejecuta SQL o consultas de agregación. Si una consulta omite el predicado `WHERE tenant_id = :tenant_id`, se produce filtración cruzada de datos.

### 2.2. Colisión de Claves Compuestas y Espacios de Nombres en Caché
- **Mecanismo:** Las claves de caché en Redis o los identificadores de documentos en el motor de búsqueda utilizan únicamente el identificador numérico de la entidad (`cache:user:1234`) en lugar de incluir el identificador del inquilino. Dos inquilinos con IDs colisionantes sobreescriben o acceden a datos mutuos.
- **El Patrón Seguro:**
  ```typescript
  // ❌ VULNERABLE: Clave global sin espacio de nombres de inquilino
  const cacheKey = `contact:${contactId}`;

  // ✅ SEGURO: Clave con espacio de nombres compuesto inmutable
  const cacheKey = `tenant:${session.tenantId}:contact:${contactId}`;
  ```

### 2.3. Exceso de Alcance en Enlaces y Referencias Firmadas (Signed URLs)
- **Mecanismo:** Un endpoint genera una URL prefirmada de S3/Cloud Storage para descargar un reporte o archivo. La URL permite descargar objetos fuera del prefijo del inquilino (`/tenants/otro-tenant/archivo.pdf`) o no expira tras la revocación de la sesión del usuario.
- **Control Requerido:** Toda URL prefirmada debe restringirse al prefijo estricto del tenant (`/tenants/${tenantId}/*`), con tiempo de vida acotado (máximo 15 minutos) y vinculación a la acción exacta (`read` o `write`).

---

## 🔄 3. Vectores de Ataque en Copias Derivadas y Observabilidad

### 3.1. Deriva de ACLs en Motores de Búsqueda y Cachés
- **Mecanismo:** Cuando un usuario pierde acceso a un recurso en la base de datos relacional (e.g. revocado de un equipo), el registro en Elasticsearch o el objeto en Redis mantiene el documento indexado sin invalidarse, permitiendo al usuario revocado continuar consultando datos confidenciales a través del buscador global.
- **Control Requerido:** Invocación atómica de invalidación de índices y cachés ante cualquier mutación de ACL; o aplicación de filtros de autorización en tiempo de consulta en el motor de búsqueda (`filter: { term: { tenant_id: current_tenant } }`).

### 3.2. Oráculos de Enumeración y Agregación
- **Mecanismo:** Endpoints de métricas, conteo de registros o validación de duplicados (e.g. "comprobar si el email ya existe") revelan la existencia de registros protegidos de otros inquilinos a través de variaciones en tiempos de respuesta o mensajes de error diferenciados.

---

## 📦 4. Vectores en Operaciones de Exportación, Backup, Restauración y Migración

### 4.1. Expansión de Privilegios en Exportación y Backup
- **Mecanismo:** Una función de exportación (e.g. "Descargar todos mis datos en ZIP") genera un paquete que recopila registros mediante consultas sin filtrar, incorporando datos de otros inquilinos o registros con borrado lógico que el usuario normal no podía visualizar en la interfaz web.
- **Control Requerido:** La función de exportación debe someterse a la misma matriz de autorización por ítem que las vistas interactivas del sistema.

### 4.2. Expansión de Autoridad en Importación y Restauración
- **Mecanismo:** El proceso de importación de datos (e.g. importar contactos desde CSV/JSON) confía ciegamente en los identificadores de tenant o usuario contenidos dentro del archivo importado, permitiendo a un atacante inyectar registros en cuentas ajenas.
- **El Patrón Seguro:**
  ```typescript
  // ❌ VULNERABLE: Confianza en el tenant_id del payload subido
  for (const item of importedRows) {
    await db.contacts.create({ data: item }); // item contiene tenant_id manipulado
  }

  // ✅ SEGURO: Forzado inmutable del tenant_id desde la sesión autenticada
  for (const item of importedRows) {
    const { tenant_id, id, ...safePayload } = item;
    await db.contacts.create({
      data: {
        ...safePayload,
        tenant_id: session.tenantId // Forzado autoritativo
      }
    });
  }
  ```

---

## 🗑️ 5. Vectores en Ciclo de Vida: Borrado Lógico (*Soft-Delete*) y Purga

### 5.1. Bypass de Borrado Lógico (Tombstone Bypass)
- **Mecanismo:** La aplicación oculta registros eliminados agregando `deleted_at IS NULL` en las pantallas principales. Sin embargo, endpoints secundarios de analítica, exportación, búsqueda o APIs legacy omiten la comprobación, permitiendo acceder a información que el usuario ordenó eliminar.
- **Control Requerido:** Empleo de políticas de Row Level Security (RLS) en base de datos que filtren `deleted_at IS NULL` de forma universal y transparente para todos los roles no administrativos.

---

## 📋 Checklist de Auditoría para Sistemas Multi-Inquilino

- [ ] ¿Todas las consultas SQL / ORM incluyen explícitamente el filtro de inquilino o están protegidas por RLS?
- [ ] ¿Las funciones de sesión en PostgreSQL RLS utilizan subconsultas escalares `(SELECT get_user_tenant_id())` para optimización `InitPlan` $O(1)$?
- [ ] ¿Todas las claves de Redis, Memcached y buckets de S3 incluyen el prefijo de `tenant_id`?
- [ ] ¿Los índices de búsqueda (Elasticsearch) aplican filtros de inquilino en tiempo de consulta además de en la ingesta?
- [ ] ¿Los procesos de importación y restauración ignoran cualquier identificador de inquilino suministrado en los archivos y fuerzan el de la sesión?
- [ ] ¿Las operaciones de exportación masiva validan autorización a nivel de fila individual?
- [ ] ¿Los registros marcados con borrado lógico están excluidos en APIs secundarias, reportes y búsquedas globales?
