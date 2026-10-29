# Guía SAST de Prevención de Mass Assignment y Auto-Binding en APIs REST / GraphQL

Esta referencia técnica describe los principios de análisis estático (SAST), validación contract-first y prevención de vulnerabilidades de **Auto-Binding y Asignación Masiva de Propiedades (Mass Assignment)**, catalogada como **`VULN-SAST-019`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Mecanismo del Fallo

Los frameworks web modernos (Express/Prisma, NestJS, FastAPI, Ruby on Rails, Spring Boot, ASP.NET Core) ofrecen utilidades para deserializar automáticamente cargas útiles JSON provenientes del cliente y vincularlas directamente a modelos de dominio o entidades ORM.

Cuando los desarrolladores pasan el objeto completo de la petición (`req.body`, `params`, `@RequestBody`) directamente a métodos de creación o mutación de la base de datos sin una lista blanca explícita de campos mutables:
- Un atacante puede incluir propiedades sensibles en el JSON que no están expuestas en la interfaz de usuario pero sí existen en el modelo de base de datos (`role: "admin"`, `is_verified: true`, `credit_balance: 999999`, `tenant_id: "victim_org"`).
- El ORM o framework vincula ciegamente el campo inyectado, provocando escalada vertical de privilegios, omisión de pasos de verificación o corrupción de aislamiento multi-inquilino.

---

## 🔍 Taxonomía y Mapeo Multimarco

| Estándar / Marco | Identificador | Denominación Oficial |
| :--- | :--- | :--- |
| **CWE** | **CWE-915** | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **OWASP API Security** | **API6:2023** | Server-Side Request Forgery & Unrestricted Resource Consumption / Mass Assignment |
| **OWASP Top 10** | **A01:2021/2025** | Broken Access Control |
| **MITRE ATT&CK** | **T1078** | Valid Accounts |
| **Devia Catalog** | **`VULN-SAST-019`** | API Mass Assignment & Unbounded Object Property Auto-Binding |

---

## 💻 Patrones Vulnerables vs Implementación Contract-First

### Antipatrón Vulnerable: Inyección Directa de `req.body` en Prisma / Express
```typescript
// VULNERABLE: El cliente puede inyectar cualquier campo del modelo User
app.post("/api/users", async (req, res) => {
  // Peligro: Si req.body contiene { "role": "ADMIN", "isSuperuser": true }, se guardan en BD!
  const user = await prisma.user.create({
    data: req.body
  });
  res.json(user);
});

app.patch("/api/users/:id", async (req, res) => {
  // Peligro: El usuario puede modificar su propio tenantId o status
  const updated = await prisma.user.update({
    where: { id: req.params.id },
    data: req.body
  });
  res.json(updated);
});
```

### Patrón Seguro: Contrato DTO con Validación Estricta Zod
```typescript
// SEGURO: Validación contract-first mediante DTO explícito con Zod
import { z } from "zod";

// 1. Esquema DTO con lista blanca de campos mutables permitidos para usuarios estándar
const CreateUserDtoSchema = z.object({
  email: z.string().email(),
  fullName: z.string().min(2).max(100),
  bio: z.string().max(500).optional()
}).strict(); // .strict() rechaza cualquier propiedad adicional no declarada!

type CreateUserDto = z.infer<typeof CreateUserDtoSchema>;

app.post("/api/users", async (req, res) => {
  // Validación estricta en runtime: si viene 'role' o 'isAdmin', Zod lanza error
  const validatedData = CreateUserDtoSchema.parse(req.body);

  const user = await prisma.user.create({
    data: {
      email: validatedData.email,
      fullName: validatedData.fullName,
      bio: validatedData.bio,
      role: "STANDARD_USER", // Campo sensible fijado autoritativamente por el backend
      isVerified: false
    }
  });
  res.status(201).json(user);
});
```

### Patrón Seguro en Python / FastAPI (Pydantic DTO)
```python
# SEGURO: Modelo Pydantic con extra="forbid"
from pydantic import BaseModel, EmailStr, ConfigDict

class UserCreateDTO(BaseModel):
    model_config = ConfigDict(extra="forbid") # Rechaza campos extra como 'is_admin'
    
    email: EmailStr
    full_name: str

@app.post("/users")
async def create_user(dto: UserCreateDTO, db: Session = Depends(get_db)):
    user = User(
        email=dto.email,
        full_name=dto.full_name,
        role="STANDARD_USER", # Fijado por el servidor
        is_active=True
    )
    db.add(user)
    db.commit()
    return user
```

---

## 🔬 Detección SAST Determinista

Un linter o analizador SAST para Mass Assignment debe evaluar:
1. **Detección de Sumidero:** Métodos de persistencia de ORM (`Model.create`, `Model.update`, `repository.save`, `db.session.add`).
2. **Origen del Argumento:** Si el argumento proviene directamente del parámetro de petición sin pasar por desestructuración de campos o validación de DTO.
3. **Ausencia de Lista Blanca:** Ausencia de flags de restricción estricta (e.g. `zod.strict()`, `model_config = ConfigDict(extra="forbid")`).

---

## ✅ Checklist de Auditoría para Evaluadores de Devia-CyberSecurity

- [ ] Ningún endpoint de API pasa `req.body`, `params` o el objeto de entrada completo de manera directa al ORM o base de datos.
- [ ] Todos los endpoints de creación y mutación utilizan **DTOs dedicados** con tipado estricto.
- [ ] Los validadores de esquema están configurados para rechazar o descartar propiedades adicionales no declaradas (`.strict()` en Zod, `extra="forbid"` en Pydantic).
- [ ] Los campos de autorización, roles, saldo, tenencia (`tenant_id`) y estado de verificación se asignan exclusivamente desde el contexto de sesión autenticado del backend.
- [ ] Las respuestas de API no serializan entidades completas del modelo que expongan claves foráneas o atributos internos (evitando `Excessive Data Exposure`).
