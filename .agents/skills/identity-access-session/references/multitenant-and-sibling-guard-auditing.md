# Auditoría de Discrepancias en Guardias Hermanas y Aislamiento Multinquilino

Este documento detalla las metodologías avanzadas de auditoría para detectar brechas de control de acceso lógico mediante el análisis diferencial de guardias de seguridad entre operaciones hermanas (*Sibling Operations*) y la verificación de límites multinquilino (*Multitenancy Isolation*).

---

## 🏛️ El Concepto de Operaciones Hermanas (*Sibling Operations*)

En arquitecturas de microservicios, APIs REST o endpoints RPC, con frecuencia existen múltiples operaciones que manipulan la misma entidad o recurso subyacente a lo largo de su ciclo de vida:
- Creación vs Mutación en Runtime (`environment/create` vs `environment/add` o `upsert`).
- Consulta individual vs Listado por lote (`GET /item/:id` vs `GET /items`).
- Actualización parcial vs Reemplazo total (`PATCH /profile` vs `PUT /profile`).
- Eliminación suave vs Purgado (`DELETE /account` vs `POST /account/archive`).

### El Mecanismo de Falla: Discrepancia de Guardias de Seguridad
Los desarrolladores suelen implementar verificaciones estrictas en la operación principal (e.g. en el inicio o en la creación), pero omiten las mismas restricciones en rutas secundarias de mutación o sincronización:

```
[Cliente / Atacante]
       │
       ├──> POST /api/environment (Creación)  --> [Guard: ID != 'local' / 'system'] --> OK (Protegido)
       │
       └──> POST /api/environment/add (Upsert) --> [Sin Guard de ID reservado]      --> VULNERABLE
```

---

## 🔍 Metodología de Auditoría Diferencial de Guardias

1. **Agrupación por Recurso:**  
   Identificar todos los endpoints, métodos RPC o controladores que aceptan como parámetro la misma clave de recurso (`resourceId`, `tenantId`, `environmentId`).
2. **Matriz de Validación Comparativa:**  
   Construir una tabla comparando los validadores ejecutados en cada ruta:
   - ¿Todas las rutas validan el esquema Zod/Pydantic completo?
   - ¿Todas las rutas comprueban identificadores reservados o inmutables?
   - ¿Todas las rutas verifican la pertenencia del recurso al `tenantId` de la sesión autenticada?
3. **Inspección de Persistencia Subyacente:**  
   Verificar si un método como `upsert()` en el motor de base de datos sobrescribe registros del sistema o de otros inquilinos cuando se invoca con un ID ya existente sin verificar propiedad previa.

---

## 🛡️ Aislamiento Multinquilino Estricto

En aplicaciones multi-tenant:
- **Directiva de Filtrado Forzado:** Toda consulta a la base de datos debe incluir el `tenantId` en la cláusula `WHERE` derivado estrictamente del token de sesión verificado, **NUNCA** de parámetros suministrados por el cliente en el cuerpo o la URL.
- **Validación de Identificadores Cruzados:** Rechazar operaciones donde un usuario autenticado en el Tenant A intente vincular un recurso (`teamId`, `organizationId`) perteneciente al Tenant B.
