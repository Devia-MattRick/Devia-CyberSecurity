# Guía Canónica de Patrones SAST Multimarco (Node.js & Python)

Este documento constituye la **Referencia Operativa de Auditoría Estática de Código (SAST)** para aplicaciones web y APIs desarrolladas sobre los ecosistemas JavaScript/TypeScript y Python en **Devia-CyberSecurity**.

---

## 🏛️ 1. Inyección SQL en ORMs Modernos (CWE-89 / OWASP A03:2021 / A05:2025)

**Vulnerabilidad:** [`VULN-SAST-001`](file:///docs/VULNERABILITIES.md)  
**Severidad Canónica:** `CRITICAL`  
**Mecanismo de Fallo:** Los desarrolladores asumen que el uso de un ORM erradica automáticamente las inyecciones SQL. Sin embargo, los métodos de consulta cruda (*raw queries*), literales no vinculados o fragmentos dinámicos en cláusulas `WHERE`, `ORDER BY` o `SELECT` admiten concatenación no sanitizada de entradas de usuario.

### 1.1. Sequelize (Node.js / TypeScript)

#### Patrones de Detección (Grep / AST)
```regex
sequelize\.query\s*\(.*`.*\$\{
Sequelize\.literal\s*\(.*`.*\$\{
where\s*:\s*Sequelize\.literal\(
```

#### Código Vulnerable vs Seguro
```typescript
// ❌ VULNERABLE: Interpolación directa en Sequelize.literal
const users = await User.findAll({
  where: Sequelize.literal(`status = '${req.query.status}' AND tenant_id = ${req.user.tenantId}`)
});

// ✅ SEGURO: Parámetros vinculados (replacements / bind)
const users = await User.findAll({
  where: {
    status: req.query.status,
    tenantId: req.user.tenantId
  }
});
// O con consulta cruda segura:
const [results] = await sequelize.query(
  "SELECT * FROM users WHERE status = :status AND tenant_id = :tenantId",
  {
    replacements: { status: req.query.status, tenantId: req.user.tenantId },
    type: QueryTypes.SELECT
  }
);
```

---

### 1.2. TypeORM & Prisma (Node.js / TypeScript)

#### Patrones de Detección (Grep / AST)
```regex
createQueryBuilder.*\.where\s*\(.*`.*\$\{
getRepository.*\.query\s*\(.*`.*\$\{
\$queryRaw\s*`.*\$\{
\$executeRawUnsafe\s*\(
```

#### Código Vulnerable vs Seguro
```typescript
// ❌ VULNERABLE: Inyección en TypeORM QueryBuilder y Prisma Raw
const users = await userRepository.createQueryBuilder("user")
  .where(`user.email = '${req.body.email}'`)
  .getMany();

const items = await prisma.$queryRawUnsafe(`SELECT * FROM items WHERE category = '${req.query.cat}'`);

// ✅ SEGURO: Parámetros tipados en QueryBuilder y Prisma.sql
const users = await userRepository.createQueryBuilder("user")
  .where("user.email = :email", { email: req.body.email })
  .getMany();

const items = await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM items WHERE category = ${req.query.cat}`
);
```

---

### 1.3. SQLAlchemy & Django ORM (Python)

#### Patrones de Detección (Grep / AST)
```regex
text\s*\(f["'].*\{
\.raw\s*\(f["'].*\{
\.extra\s*\(where\s*=\s*\[f["']
cursor\.execute\s*\(f["']
```

#### Código Vulnerable vs Seguro
```python
# ❌ VULNERABLE: Inyección en SQLAlchemy text() y Django raw()
db.session.execute(text(f"SELECT * FROM accounts WHERE owner_id = '{user_input}'"))
Account.objects.raw(f"SELECT * FROM accounts WHERE org_id = '{org_id}'")

# ✅ SEGURO: Declaración parametrizada estricta
db.session.execute(
    text("SELECT * FROM accounts WHERE owner_id = :owner_id"),
    {"owner_id": user_input}
)
Account.objects.raw("SELECT * FROM accounts WHERE org_id = %s", [org_id])
```

---

## 🍃 2. Inyección NoSQL en MongoDB / Mongoose (CWE-943)

**Vulnerabilidad:** [`VULN-SAST-001`](file:///docs/VULNERABILITIES.md)  
**Severidad Canónica:** `CRITICAL`  
**Mecanismo de Fallo:** MongoDB interpreta objetos de consulta enriquecidos con operadores (`$gt`, `$ne`, `$regex`, `$where`). Cuando `express.json()` o `body-parser` parsean un objeto JSON enviado por el atacante directamente a `User.findOne(req.body)`, un atacante puede eludir autenticación mediante payloads como `{"username": "admin", "password": {"$ne": ""}}`.

### Patrones de Detección
```regex
\.find(One)?\s*\(\s*req\.(body|query)
\.find(One)?\s*\(\s*\{.*password\s*:\s*req\.body\.password
```

### Código Vulnerable vs Seguro
```typescript
// ❌ VULNERABLE: Acepta objetos de consulta no tipados
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password // Si req.body.password es {"$ne": ""}, el check pasa
  });
  if (user) generateSession(user);
});

// ✅ SEGURO: Coerción de tipos explícita y validación de esquema con Zod
const LoginSchema = z.object({
  username: z.string().min(1).max(100),
  password: z.string().min(1)
});

app.post('/api/login', async (req, res) => {
  const { username, password } = LoginSchema.parse(req.body);
  const user = await User.findOne({ username: String(username) });
  if (user && await verifyPassword(password, user.passwordHash)) {
    generateSession(user);
  }
});
```

---

## 📁 3. Carga Insegura de Archivos (CWE-434 / OWASP A06:2025)

**Vulnerabilidad:** [`VULN-SAST-003`](file:///docs/VULNERABILITIES.md)  
**Severidad Canónica:** `HIGH` / `CRITICAL`  
**Mecanismo de Fallo:** Aceptar archivos de usuario sin sanitizar el nombre original, sin verificar la firma mágica (*magic bytes*) y almacenándolos dentro del árbol servible por el servidor web, permitiendo ejecución remota de código (RCE) o sobreescritura de archivos arbitrarios (Zip Slip / Path Traversal).

### Código Vulnerable vs Seguro (Multer / Express)
```typescript
// ❌ VULNERABLE: Sin filtro de extensión, guarda nombre original en webroot
const upload = multer({ dest: 'public/uploads/' });
app.post('/upload', upload.single('avatar'), (req, res) => {
  res.json({ url: `/uploads/${req.file.originalname}` });
});

// ✅ SEGURO: Nombre aleatorio UUID, validación de extensión + magic bytes y ruta externa
const ALLOWED_MIME = new Set(['image/jpeg', 'image/png', 'application/pdf']);
const ALLOWED_EXT = new Set(['.jpg', '.jpeg', '.png', '.pdf']);

const safeStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '/var/app/isolated_uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage: safeStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB max
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_MIME.has(file.mimetype) && ALLOWED_EXT.has(ext)) {
      cb(null, true);
    } else {
      cb(new SecurityException("Tipo de archivo no autorizado"));
    }
  }
});
```

---

## 🌐 4. Redirecciones Abiertas (CWE-601 / OWASP A01:2025)

**Vulnerabilidad:** [`VULN-SAST-006`](file:///docs/VULNERABILITIES.md)  
**Severidad Canónica:** `MEDIUM` (Escala a `CRITICAL` en cadenas OAuth/ATO)  
**Mecanismo de Fallo:** Utilizar parámetros de consulta (`returnUrl`, `next`, `redirect`) directamente en cabeceras `Location` o métodos `res.redirect()` sin verificar pertenencia al dominio ni caracteres de evasión de esquema (`//evil.com`, `/\evil.com`, `javascript:`).

### Código Vulnerable vs Seguro
```typescript
// ❌ VULNERABLE: Redirección no validada
app.get('/login', (req, res) => {
  res.redirect(req.query.returnUrl as string);
});

// ✅ SEGURO: Validación estricta de ruta relativa y dominio autorizado
app.get('/login', (req, res) => {
  const rawUrl = req.query.returnUrl;
  let target = '/dashboard';

  if (typeof rawUrl === 'string' && rawUrl.startsWith('/') && !rawUrl.startsWith('//') && !rawUrl.includes('\\')) {
    target = rawUrl;
  }
  res.redirect(target);
});
```
