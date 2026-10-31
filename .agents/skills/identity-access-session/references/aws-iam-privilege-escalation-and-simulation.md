# Escalada de Privilegios en AWS IAM y Verificación Read-Only de Políticas

Este documento define la metodología autoritativa para la auditoría, detección estática y evaluación de rutas de escalada de privilegios en **Amazon Web Services (AWS) Identity and Access Management (IAM)**, su mapeo a **MITRE ATT&CK Cloud** y el protocolo de verificación determinista en modo de solo lectura.

---

## 1. Taxonomía Multimarco y Mapeo Canónico

- **Dimensión Canónica:** `IDENTITY_ACCESS_SESSION`
- **Identificadores Devia:** `VULN-IAM-002` (Escalada / Bypass), `VULN-IAM-003` (Control de Acceso a Nivel de Función), `VULN-IAM-012` (Role Explosion / Privilege Creep).
- **CWEs Primarios:**
  - `CWE-269`: Improper Privilege Management
  - `CWE-284`: Improper Access Control
  - `CWE-732`: Incorrect Permission Assignment for Critical Resource
- **OWASP Top 10:** A01:2021-Broken Access Control

---

## 2. Matriz Canónica de Rutas de Escalada en AWS IAM

A continuación se catalogan las primitivas de escalada más comunes, su impacto técnico y su mapeo a las técnicas oficiales de MITRE ATT&CK Cloud:

| Primitiva IAM (Permiso Clave) | Vector de Ataque y Resultado | Técnica ATT&CK Cloud | Severidad |
| :--- | :--- | :--- | :--- |
| **`iam:CreateAccessKey`** sobre otro usuario | Generación de credenciales persistentes de un usuario de mayor privilegio. | `T1098.001` Additional Cloud Credentials | **CRITICAL** |
| **`iam:CreateLoginProfile`** / **`iam:UpdateLoginProfile`** | Creación o reseteo de contraseña de consola web sobre cuentas sin MFA. | `T1098` Account Manipulation | **CRITICAL** |
| **`iam:AttachUserPolicy`** / **`iam:PutUserPolicy`** | Auto-asignación directa de la política administrada `AdministratorAccess`. | `T1548` Abuse Elevation Control | **CRITICAL** |
| **`iam:AddUserToGroup`** | Incorporación de la propia identidad a grupos con permisos de administración. | `T1098` Account Manipulation | **HIGH** |
| **`iam:CreatePolicyVersion`** + **`iam:SetDefaultPolicyVersion`** | Modificación in-place de una política existente para conceder permisos `*:*`. | `T1548` Abuse Elevation Control | **CRITICAL** |
| **`iam:UpdateAssumeRolePolicy`** | Alteración de la política de confianza de un rol privilegiado para permitir `sts:AssumeRole`. | `T1098` Account Manipulation | **CRITICAL** |
| **`iam:PassRole`** + **`lambda:CreateFunction`** + **`lambda:InvokeFunction`** | Despliegue y ejecución de código serverless asumiendo un rol de alto privilegio. | `T1078.004` Valid Accounts: Cloud<br>`T1059` Command & Scripting | **HIGH** |
| **`iam:PassRole`** + **`ec2:RunInstances`** | Creación de instancia EC2 con perfil de instancia privilegiado y extracción de credenciales vía IMDSv1/v2. | `T1078.004` Valid Accounts: Cloud<br>`T1552.005` Cloud Instance Metadata | **HIGH** |
| **`iam:PassRole`** + **`cloudformation:CreateStack`** | Despliegue de plantilla CloudFormation que ejecuta acciones arbitrarias con el rol del stack. | `T1078.004` Valid Accounts: Cloud | **HIGH** |
| **`glue:UpdateDevEndpoint`** | Inyección de clave pública SSH en endpoint Glue para obtener ejecución remota con el rol asignado. | `T1059` Command and Scripting Interpreter | **HIGH** |
| **`ssm:SendCommand`** / **`ssm:StartSession`** | Ejecución de comandos o inicio de sesión interactiva en instancias EC2 administradas por Systems Manager. | `T1651` Cloud Administration Command | **HIGH** |
| **`sts:AssumeRole`** | Asunción directa de un rol que mantiene una relación de confianza laxa o abierta (`Principal: "*"`). | `T1548` Abuse Elevation Control | **HIGH** |

---

## 3. Protocolo de Verificación Read-Only Pre-Vuelo (`SimulatePrincipalPolicy`)

Un auditor o agente nunca debe alterar la infraestructura ni explotar una política sin verificar previamente de forma estricta que la política evaluada concede efectivamente el permiso deseado.

### Principio de Simulación Segura:
La API `iam:SimulatePrincipalPolicy` es **100% de solo lectura (*read-only*)**: evalúa las políticas asociadas al ARN de una identidad sin modificar el estado de la cuenta ni generar ruido en los registros de auditoría operativa.

```python
import boto3

def verify_privesc_permission_safely(principal_arn: str, action_name: str, resource_arn: str = "*") -> bool:
    """Verifica si un principal puede ejecutar una acción sensible sin realizar cambios en la cuenta."""
    client = boto3.client("iam")
    response = client.simulate_principal_policy(
        PolicySourceArn=principal_arn,
        ActionNames=[action_name],
        ResourceArns=[resource_arn]
    )
    for res in response.get("EvaluationResults", []):
        if res.get("EvalDecision") == "allowed":
            return True
    return False
```

Si la simulación devuelve `explicitDeny` o `implicitDeny` (por ejemplo, debido a una Service Control Policy - SCP de AWS Organizations o una Permission Boundary), **el hallazgo se clasifica como `discarded` o `hypothesis`, impidiendo un falso positivo**.

---

## 4. Directiva Innegociable de Trazabilidad y Reversibilidad

En cualquier auditoría activa o ejercicio de emulación adversarial:

1. **Etiquetado Obligatorio:** Todo recurso creado debe llevar la etiqueta identificable:
   `Key=audit-engagement,Value=<ID_AUDITORIA>` o el prefijo en el nombre `audit-<ID>-<recurso>`.
2. **Registro de Acciones Mutantes:** Cada acción que modifique el estado de la cuenta debe registrarse inmediatamente en el ledger de la auditoría con su comando inverso de reversión:
   - *Acción ejecutada:* `aws iam create-access-key --user-name Alice`
   - *Comando de reversión:* `aws iam delete-access-key --user-name Alice --access-key-id AKIA...`
3. **Restauración Obligatoria al Cierre:** Al finalizar la evaluación, el operador o agente debe ejecutar la lista de limpieza, verificando que no queden claves huérfanas, perfiles de inicio de sesión creados ni relaciones de confianza debilitadas.
