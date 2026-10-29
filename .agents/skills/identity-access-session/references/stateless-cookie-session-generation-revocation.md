# Revocación de Sesiones Cookie sin Estado mediante Generación Monótona y Hardening de Bcrypt

Este documento describe la arquitectura defensiva para gestión de sesiones web mediante cookies firmadas sin estado con capacidad de revocación instantánea en servidor, y el control estricto de límites de longitud en funciones hash de contraseñas (`bcrypt`), basado en la ingeniería inversa de **PentAGI**.

---

## 1. El Dilema de las Sesiones sin Estado y la Revocación

### 1.1. Limitación Tradicional
Las cookies de sesión firmadas criptográficamente evitan mantener un registro voluminoso de sesiones activas en Redis o PostgreSQL. Sin embargo, su principal desventaja de seguridad es la imposibilidad de revocación inmediata en servidor: al cerrar sesión, borrar la cookie en el cliente no impide que un atacante que interceptó el token previo continúe autenticándose hasta la expiración natural del token.

### 1.2. El Patrón `session_generation` Monótono
Para resolver esto sin sacrificar la ligereza del modelo sin estado, la sesión se vincula a un contador entero monótono en la tabla de usuarios:

```sql
ALTER TABLE users ADD COLUMN session_generation BIGINT NOT NULL DEFAULT 1;
```

#### Flujo de Funcionamiento:
1. **Emisión de la Sesión:** Al autenticar con éxito, la cookie firmada incluye:
   $$\text{SessionPayload} = \{\text{user\_id}: 101, \text{session\_generation}: 1, \dots\}$$
2. **Validación en Middleware:** El middleware de autenticación extrae el `user_id` y compara la `session_generation` de la cookie con el valor almacenado en caché/base de datos para ese usuario:
   ```go
   if cookie.SessionGeneration < user.SessionGeneration {
       // La cookie pertenece a una sesión revocada
       return authResultFail, ErrSessionExpired
   }
   ```
3. **Revocación Global Inmediata (Logout / Cambio de Contraseña):**
   ```go
   func RevokeSessions(db *gorm.DB, cache *UserCache, userID uint64) (uint64, error) {
       // Incrementar monótonamente en la base de datos
       err := db.Model(&models.User{}).
           Where("id = ?", userID).
           UpdateColumn("session_generation", gorm.Expr("session_generation + 1")).Error
       if err != nil {
           return 0, err
       }

       // Invalidar inmediatamente en caché de memoria (UserCache)
       if cache != nil {
           cache.Invalidate(userID)
       }

       var user models.User
       db.Select("session_generation").Where("id = ?", userID).First(&user)
       return user.SessionGeneration, nil
   }
   ```
4. **Re-Sellado Opcional:** Si el usuario que provocó el cambio de contraseña desea mantener activa su propia sesión actual, el servidor simplemente re-emite la cookie firmada estampando el nuevo valor de `session_generation`. Todas las demás sesiones previas quedan automáticamente invalidadas.

---

## 2. Derivación Criptográfica Dual con PBKDF2 (OWASP 2023)

Las cookies y los tokens JWT no deben firmarse directamente con la contraseña o una cadena de texto plano. Se debe aplicar una función de derivación de claves (KDF) con alta resistencia a cómputo por fuerza bruta:

```go
const (
    pbkdf2Iterations = 210000 // Recomendación OWASP para PBKDF2-HMAC-SHA512
    jwtKeyLength     = 32     // 256 bits para HMAC-SHA256
    authKeyLength    = 64     // 512 bits para autenticación de cookie
    encKeyLength     = 32     // 256 bits para cifrado AES de cookie
)

func MakeCookieStoreKey(globalSalt string) [][]byte {
    password := []byte("salt-base-entropy|" + globalSalt)
    
    // Clave de autenticación con sal variante 1
    authSalt := []byte("pentagi.cookie.auth|" + globalSalt)
    authKey := pbkdf2.Key(password, authSalt, pbkdf2Iterations, authKeyLength, sha512.New)

    // Clave de cifrado con sal variante 2
    encSalt := []byte("pentagi.cookie.enc|" + globalSalt)
    encKey := pbkdf2.Key(password, encSalt, pbkdf2Iterations, encKeyLength, sha512.New)

    return [][]byte{authKey, encKey}
}
```

---

## 3. Límite Crítico de Longitud en Bcrypt (72 Bytes)

### 3.1. Vulnerabilidad de Truncamiento Silencioso
El algoritmo `bcrypt` opera internamente sobre bloques de hasta **72 bytes**. En implementaciones de backend, una contraseña de 100 caracteres puede:
- Truncarse silenciosamente en los primeros 72 bytes, provocando que cualquier contraseña que comparta los primeros 72 bytes sea aceptada.
- O bien, en librerías estrictas como Go (`golang.org/x/crypto/bcrypt`), la función `bcrypt.GenerateFromPassword` retorna un error fatal en tiempo de ejecución: `bcrypt: password length exceeds 72 bytes`. Si la aplicación valida en frontend 8–128 caracteres pero el backend falla al almacenar el hash, se producen errores 500 no capturados.

### 3.2. Regla de Paridad Frontend / Backend (`FitsHashLimit`)
Tanto el validador del backend como el esquema Zod del frontend deben reflejar la misma política de longitud en bytes (no en caracteres Unicode):

```go
// Package password
const MaxBytes = 72

func FitsHashLimit(password string) bool {
    // Medir longitud en BYTES UTF-8, no runas
    return len(password) <= MaxBytes
}
```

```typescript
// Frontend Zod Schema
export const PasswordPolicySchema = z.string()
  .min(8, "La contraseña debe tener al menos 8 caracteres")
  .refine((val) => new TextEncoder().encode(val).length <= 72, {
    message: "La contraseña no debe exceder 72 bytes UTF-8 (límite del algoritmo bcrypt)"
  });
```
