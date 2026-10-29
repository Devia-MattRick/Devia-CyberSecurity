# Matriz de Escalada de Privilegios en Kubernetes RBAC (Las 9 Primitivas Críticas)

Este documento constituye la **Guía Canónica de Auditoría y Remediación de Escalada de Privilegios en Kubernetes RBAC** dentro del ecosistema **Devia-CyberSecurity**. Detalla los mecanismos de abuso de permisos sobre roles y enlaces (`Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`) que permiten a un sujeto (usuario, grupo o cuenta de servicio / service account) escalar hacia privilegios equivalentes a `cluster-admin`.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-269 (Improper Privilege Management), CWE-250 (Execution with Unnecessary Privileges)
- **MITRE ATT&CK:** T1078 (Valid Accounts), T1098.006 (Account Manipulation: Additional Cloud Roles), T1528 (Steal Application Access Token), T1611 (Escape to Host)
- **Vulnerabilidad Canónica:** `VULN-IAM-008`
- **Dimensión:** `IDENTITY_ACCESS_SESSION`

En Kubernetes, las cargas de trabajo (*workloads*) ejecutan pods con tokens de cuenta de servicio montados automáticamente (`/var/run/secrets/kubernetes.io/serviceaccount/token`). Si una cuenta de servicio cuenta con permisos mal configurados o excesivos, el compromiso de un único pod permite tomar el control de todo el cluster (*Full Cluster Takeover*).

---

## ⚔️ Las 9 Primitivas Equivalentes a `cluster-admin`

A continuación se detalla la matriz de las 9 primitivas que deben ser tratadas con la máxima severidad en cualquier auditoría:

| N° | Primitiva RBAC | Recurso Afectado | Verbo / Acción | Impacto y Mecanismo de Abuso |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Escalación de Roles** | `roles`, `clusterroles` | `escalate` | Permite al sujeto otorgarse a sí mismo cualquier permiso sobre roles, eludiendo la restricción que prohíbe dar permisos que no se poseen. |
| **2** | **Enlace Arbitrario** | `clusterroles`, `roles` | `bind` | Permite crear un `RoleBinding` o `ClusterRoleBinding` hacia roles privilegiados preexistentes como `cluster-admin`. |
| **3** | **Suplantación de Sujetos** | `users`, `groups`, `serviceaccounts` | `impersonate` | Permite al sujeto ejecutar cualquier llamada API suplantando a otro usuario o grupo (e.g. `system:masters`). |
| **4** | **Despliegue de Pod Host-Escape** | `pods` | `create`, `update`, `patch` | Permite programar un pod privilegiado (`privileged: true`, `hostPID: true`, `hostNetwork: true`, `hostPath: /`), logrando escape inmediato al nodo anfitrión (T1611). |
| **5** | **Inyección de Código en Pods** | `pods/exec`, `pods/attach`, `pods/ephemeralcontainers` | `create` | Permite abrir shells interactivas en cualquier pod en ejecución dentro del namespace y heredar sus credenciales y tokens. |
| **6** | **Lectura Masiva de Secretos** | `secrets` | `get`, `list`, `watch` | `list` o `watch` sobre secretos retorna el contenido descifrado de todos los secretos del namespace, incluyendo tokens de tokens de service accounts administradoras. |
| **7** | **Acuñación Directa de Tokens** | `serviceaccounts/token` | `create` | Permite solicitar directamente a la API de Kubernetes un token JWT firmado para cuentas de servicio con mayores privilegios. |
| **8** | **Mutación de Webhooks y Proxies** | `validatingwebhookconfigurations`, `mutatingwebhookconfigurations`, `nodes/proxy` | `update`, `patch`, `create` | Permite redirigir las peticiones de admisión hacia un servidor controlado o interactuar con el kubelet del nodo sin pasar por el API server. |
| **9** | **Comodines de Verbo y Recurso** | `*` en `verbs` o `*` en `resources` | `*` | Super-privilegio implícito: otorga acceso irrestricto sobre la totalidad de la API del cluster. |

---

## 🔍 Comandos de Auditoría e Inspección Determinista

Para evaluar si un sujeto o cuenta de servicio puede alcanzar `cluster-admin`, ejecutar:

```bash
# 1. Comprobar escalada directa de roles
kubectl auth can-i escalate roles --as=system:serviceaccount:default:target-sa
kubectl auth can-i bind clusterroles --as=system:serviceaccount:default:target-sa
kubectl auth can-i impersonate users --as=system:serviceaccount:default:target-sa

# 2. Comprobar lectura de secretos y acuñación de tokens
kubectl auth can-i get secrets --as=system:serviceaccount:default:target-sa
kubectl auth can-i create serviceaccounts/token --as=system:serviceaccount:default:target-sa

# 3. Comprobar ejecución y creación de pods privilegiados
kubectl auth can-i create pods --as=system:serviceaccount:default:target-sa
kubectl auth can-i create pods/exec --as=system:serviceaccount:default:target-sa

# 4. Enumerar qué sujetos pueden realizar una acción sensible (requiere kubectl-who-can)
kubectl who-can create pods/exec -n kube-system
kubectl who-can get secrets --all-namespaces
```

---

## 🛡️ Principios de Remediación y Bastionado

1. **Desactivar Automount de Tokens por Defecto:**
   En todos los pods y ServiceAccounts que no interactúen con el API server de Kubernetes:
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata:
     name: worker-sa
   automountServiceAccountToken: false
   ```
2. **Erradicación de Wildcards (`*`):**
   Prohibir terminantemente el uso de `verbs: ["*"]` o `resources: ["*"]` en roles de aplicación. Especificar verbos idempotentes mínimos (`get`, `list`).
3. **Restricción de Recursos Sensibles a Admins de Infraestructura:**
   Nunca otorgar `bind`, `escalate` ni `impersonate` a identidades automatizadas de pipelines o aplicaciones.
4. **Validación de Políticas de Admisión (Pod Security Standards):**
   Enforzar `pod-security.kubernetes.io/enforce: baseline` o `restricted` en todos los namespaces para bloquear pods privilegiados o con monturas `hostPath`.
