# Estándar de Divulgación de Secretos en Código Fuente (Sin Requisito de Ejecución)

Este documento formaliza el estándar heurístico de auditoría para la detección de secretos, credenciales y claves criptográficas expuestas en repositorios de código, adoptado tras la auditoría forense de **Codex Security**.

---

## 🏛️ Axioma de Divulgación por Acceso al Código Fuente

> [!IMPORTANT]
> **Principio de Divulgación Autocontenida:**  
> En una auditoría de secretos, la ruta de compromiso (*disclosure path*) se concreta cuando **un lector con acceso al código fuente obtiene una credencial que otorga acceso a recursos más allá del propio código fuente**.  
> El código contenedor **NO necesita ejecutarse en producción, aceptar entradas del atacante ni poseer una ruta de explotación en tiempo de ejecución**.

### Antipatrones de Falso Negativo Erradicados:
1. **"Está en una carpeta de pruebas (tests/ fixtures):"**  
   Frecuentemente desarrolladores introducen claves reales de staging o producción en mocks o fixtures. La ubicación en `tests/` o `examples/` **NO** es contraevidencia válida por sí misma.
2. **"Es una función nunca invocada / código muerto:"**  
   Cualquier lector de código (humano, CI/CD, auditor o atacante que lea el repositorio) tiene acceso a la credencial independientemente de su invocación.
3. **"No se sabe si la clave sigue activa en el proveedor:"**  
   El desconocimiento de la vigencia o estado de rotación de una credencial limita el nivel de confianza o impacto específico, pero **jamás desestima la existencia del hallazgo**. Queda estrictamente prohibido probar las claves en servicios remotos para verificar si están activas.

---

## 🔍 Criterios para Diferenciar Secretos de Falsos Positivos

| Tipo de Cadena | Naturaleza Técnica | ¿Es un Secreto Reportable? | Heurística de Confirmación |
| :--- | :--- | :--- | :--- |
| **Credencial / Token / Private Key** | API key, JWT con firma, PEM privado, contraseña de BD. | **SÍ** | Entropía de Shannon $> 4.5$, formato reconocido (e.g. `sk_live_`, `ghp_`, `AKIA`), asignación a parámetros de autenticación. |
| **Referencia a Secret Store / Env** | Variable de entorno (e.g. `process.env.DB_PASS`, `os.getenv`). | **NO** | Acceso a almacenamiento externo; el secreto reside fuera del código. |
| **Clave Pública o Certificado** | Clave pública RSA/ECC, certificado X.509 (`BEGIN CERTIFICATE`). | **NO** | Diseñado matemáticamente para ser público. |
| **Identificador o UUID** | IDs de usuario, UUIDs de bases de datos, IDs de tenant. | **NO** | Identificadores sin valor de autorización por sí mismos. |
| **Dummy / Placeholder Demostrable** | Cadenas obvias como `password123`, `your-api-key-here`, `sk_test_000000`. | **NO** | Baja entropía, nombres genéricos documentados. |

---

## 🛠️ Procedimiento de Remediación Defensiva

1. **Invalidación y Rotación Inmediata:**  
   Asumir la clave como comprometida de forma irrevocable. Revocar en el proveedor y emitir una nueva credencial.
2. **Eliminación del Historial de Control de Versiones:**  
   Un commit que elimina el secreto no lo borra del historial de Git (`git filter-repo` o `BFG Repo-Cleaner`).
3. **Migración a Secret Manager:**  
   Inyectar variables de entorno en runtime mediante bóvedas seguras (HashiCorp Vault, AWS Secrets Manager, Doppler).
