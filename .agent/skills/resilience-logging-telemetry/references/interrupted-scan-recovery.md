# Recuperación de Auditorías Interrumpidas y Principio de Inconclusión

Este documento establece los principios de resiliencia y tratamiento epistemológico ante auditorías de seguridad que se detienen, cancelan o fallan antes de completar su alcance previsto.

---

## 🏛️ El Principio Epistemológico de Inconclusión

> [!CAUTION]
> **Prohibición de Asumir Seguridad ante Auditorías Parciales:**  
> Si una sesión de escaneo, auditoría SAST o modelado de amenazas concluye con estado distinto de `completed` (`failed`, `canceled`, `interrupted`):
> - Los hallazgos confirmados y retenidos hasta el checkpoint deben preservarse.
> - **La ausencia de hallazgos en las áreas no evaluadas o parcialmente evaluadas es estrictamente INCONCLUSA.**
> - Queda terminantemente prohibido certificar que el sistema es seguro o emitir veredictos de "cero vulnerabilidades" sobre un escaneo no completado.

---

## 💾 Arquitectura de Checkpoints y Recuperación Transaccional

Para evitar la pérdida total del esfuerzo de auditoría ante excepciones no controladas o límites de timeout:

1. **Checkpoints Incrementales (`complete: false`):**
   - El motor de auditoría debe persistir borradores semánticos provisionales a medida que se completan fases críticas (e.g. Threat Model generado, candidatos validados).
   - Los candidatos pendientes de validación se registran en `deferred` con su respectiva justificación.
2. **Recuperación Post-Fallo (`recover-scan-results`):**
   - Ante una falla no recuperable, un runner de recuperación puede admitir exclusivamente los checkpoints que superen la validación de integridad de fuentes.
   - No se admite la inclusión arbitraria de nuevos datos posteriores a la detención del proceso.
3. **Resiliencia en Bases de Datos SQLite (Manejo de Inodos en Windows):**
   - En plataformas Windows y sistemas modernos (Python 3.12+), los identificadores de dispositivo pueden tener 64 bits y los inodos hasta 128 bits.
   - Para prevenir excepciones de desbordamiento en columnas de tipo entero en SQLite (`INTEGER` firmado de 64 bits), los valores que excedan el rango $[-(2^{63}), 2^{63}-1]$ deben serializarse de forma segura como strings prefijados (e.g. `stat:<hex>`).
