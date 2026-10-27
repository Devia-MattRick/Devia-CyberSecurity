# Manifiestos de Integridad de Paquetes y Rúbrica de Evaluación de Riesgo de Parches

Este documento formaliza las directivas para la verificación criptográfica de la cadena de distribución de paquetes y la rúbrica de evaluación de riesgo operacional al aplicar parches de seguridad.

---

## 1. Manifiestos de Integridad Criptográfica de Distribución (`integrity.json`)

En ecosistemas de software empaquetado y plugins de agentes autónomos, la verificación de integridad debe extenderse a cada archivo distribuido para prevenir ataques de intermediarios (*Man-in-the-Middle*) o paquetes adulterados:

- **Estructura del Manifiesto:**  
  Un archivo canónico `integrity.json` en la raíz del paquete que mapea cada ruta relativa a su digest SHA-256 exacto y su tamaño en bytes.
  ```json
  {
    "package/manifest.json": {
      "sha256": "4b92b...",
      "size": 1450
    },
    "package/scripts/tool.py": {
      "sha256": "e3b0c...",
      "size": 3200
    }
  }
  ```
- **Procedimiento de Auditoría:**  
  1. Recorrer todos los archivos físicos del paquete.
  2. Calcular el hash SHA-256 de cada archivo en memoria sin ejecutarlo.
  3. Comparar contra el manifiesto `integrity.json`. Cualquier discrepancia señala manipulación en tránsito o corrupción.

---

## 2. Rúbrica de Evaluación de Riesgo de Parches (*Patch Risk Assessment*)

La aplicación de un parche de seguridad no es un acto exento de riesgo. Para evaluar si un parche o remediación introduce regresiones operacionales o nuevos vectores de ataque, se aplica la siguiente rúbrica multidimensional:

### Dimensiones de la Rúbrica de Riesgo

| Dimensión | Criterio de Bajo Riesgo (Verde) | Criterio de Alto Riesgo (Rojo) |
| :--- | :--- | :--- |
| **Radio de Impacto (*Blast Radius*)** | Modifica una función helper aislada o un archivo interno. | Modifica interfaces públicas, firmas de métodos exportados o middleware global. |
| **Primitivas de Seguridad Modificadas** | Ajusta un umbral numérico o añade una comprobación de tipo. | Modifica la lógica criptográfica central, generación de tokens o autenticación. |
| **Ruptura de Compatibilidad (*Breaking Changes*)** | Preserva 100% la interfaz y tipos hacia atrás. | Altera contratos, tipos de parámetros o lanza nuevas excepciones no documentadas. |
| **Mecanismo de Deshacer (*Rollback Complexity*)** | Reversión atómica simple con `git revert`. | Requiere migraciones irreversibles de esquemas de base de datos o invalida sesiones activas. |
| **Cobertura de Pruebas de Regresión** | Incluye tests unitarios que reproducen la falla y verifican el fix. | Carece de pruebas automáticas que validen la contención del bug. |

### Matriz de Decisión de Aprobación de Parches:
- **`LOW RISK` (Aprobación Inmediata):** Bajo blast radius + sin breaking changes + tests de regresión incluidos.
- **`MEDIUM RISK` (Revisión Paritaria Requerida):** Blast radius moderado o afecta servicios dependientes. Requiere validación cruzada.
- **`HIGH RISK` (Despliegue Escalonado / Canary):** Modifica controles de autenticación centrales o altera contratos de API. Exige verificación en entorno de staging y plan de rollback explícito.
