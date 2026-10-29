# Guía de Auditoría: Minería de Roles RBAC, Erradicación de Role Explosion y Menor Privilegio

Este documento técnico de referencia para la Skill **`identity-access-session`** establece las metodologías, algoritmos y directivas de auditoría para evaluar arquitecturas de control de acceso basado en roles (**RBAC**), detectar la dispersión descontrolada de permisos (**Role Explosion**) y calcular matrices de consolidación óptimas mediante algoritmos deterministas.

---

## 🏛️ Contexto y Mecanismo del Fallo (VULN-IAM-012)

En organizaciones en crecimiento o entornos multicloud complejos (AWS IAM, Azure Entra ID, Kubernetes RBAC), los permisos suelen asignarse de manera ad-hoc o mediante herencia acumulativa conforme los usuarios cambian de función (antipatrón *Joiner-Mover-Leaver Drift*).

### La Anatomía de la "Role Explosion"
1. **Proliferación de Roles Singulares (*Kitchen Sink Roles*):** Creación de un rol por cada combinación puntual de necesidades (`Role_Developer_ProjectAlpha_S3_Temp`), generando una proporción $\frac{\text{Roles}}{\text{Usuarios}} \approx 1.0$.
2. **Privilegios Zombi Residuales:** Concesiones temporales que jamás se revocan al finalizar el proyecto.
3. **Pérdida de Gobernanza:** Los auditores no pueden determinar qué permisos son realmente necesarios para cada función de negocio, invalidando el principio de menor privilegio (*Least Privilege*).

---

## 🔬 Algoritmos Deterministas de Minería de Roles

### 1. Enfoque Bottom-Up (Consolidación Exacta)
- **Mecanismo:** Agrupa a todos los usuarios que poseen conjuntos idénticos de asignaciones atómicas (`sistema:permiso`).
- **Condición de Fusión:** Si un conjunto de permisos es compartido por $\ge K$ usuarios ($K = \text{min\_users}$), se acuña un rol canónico inmutable (`ROLE-XXX`).
- **Complejidad:** $O(N \log N)$ mediante hashing ordenado de tuplas de permisos.

### 2. Enfoque Top-Down con Coeficiente de Similitud de Jaccard
Para usuarios con asignaciones heterogéneas pero sustancialmente superpuestas:
$$J(U_1, U_2) = \frac{|P_1 \cap P_2|}{|P_1 \cup P_2|}$$

- **Heurística de Clustering:** Si $J(U_1, U_2) \ge \tau$ (e.g. $\tau = 0.75$), se extrae la intersección común $P_1 \cap P_2$ como el núcleo del rol consolidado.
- **Manejo de Residuos:** Los permisos periféricos $(P_1 \setminus P_2)$ permanecen como asignaciones directas temporales que exigen justificación de excepción y fecha de expiración obligatoria.

---

## 📊 Métricas Cuantitativas de Salud de RBAC

| Métrica | Definición Matemática | Umbral Óptimo | Nivel Crítico |
| :--- | :--- | :--- | :--- |
| **Role Explosion Ratio** | $\frac{\text{Conjuntos Únicos de Permisos}}{\text{Total Usuarios}}$ | $< 0.25$ | $\ge 0.75$ |
| **Porcentaje de Reducción** | $\frac{\text{Asignaciones Iniciales} - \text{Nuevas Asignaciones}}{\text{Asignaciones Iniciales}} \times 100$ | $\ge 40\%$ | $< 10\%$ |
| **Tasa de Asignaciones Directas Residuales** | $\frac{\text{Permisos Fuera de Rol}}{\text{Total Asignaciones}} \times 100$ | $< 5\%$ | $> 25\%$ |

---

## 🛠️ Ejecución con el Motor Determinado de Devia-CyberSecurity

El análisis se ejecuta deterministamente en Capa 3 mediante [`src/scripts/role_mining_analyzer.py`](file:///src/scripts/role_mining_analyzer.py) validando contra [`src/schemas/role-mining.schema.ts`](file:///src/schemas/role-mining.schema.ts):

```bash
# Analizar exportación de identidades y generar plan de optimización
python src/scripts/role_mining_analyzer.py "audits/target/entitlements.csv" --min-users 3 --threshold 0.8 --json
```

---

## ✅ Checklist de Remediación

- [ ] Identificar y fusionar roles duplicados con $>90\%$ de permisos compartidos.
- [ ] Eliminar privilegios zombi que no hayan registrado invocación en telemetría en los últimos 90 días.
- [ ] Reemplazar asignaciones directas a nivel de usuario por pertenencia a grupos/roles institucionales.
- [ ] Exigir revisión periódica de accesos (Access Certification Reviews) cada 90 días para roles privilegiados.
