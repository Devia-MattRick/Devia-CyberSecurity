# Hardening Multicloud CIS Benchmarks e Infraestructura como Código (IaC)

Este documento establece la **Guía Canónica de Bastionado de Infraestructura Cloud y Auditoría de Código Terraform** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-16 (Configuration), CWE-732 (Incorrect Permission Assignment for Critical Resource), CWE-1188 (Insecure Default Initialization of Resource)
- **MITRE ATT&CK:** T1530 (Data from Cloud Storage Object), T1078.004 (Valid Accounts: Cloud Accounts), T1190 (Exploit Public-Facing Application)
- **Vulnerabilidad Canónica:** `VULN-CONF-013` (y `VULN-CONF-003`)
- **Dimensión:** `CONFIGURATION_HARDENING`

---

## ☁️ Cobertura CIS Foundations Benchmarks (AWS, Azure, GCP)

Los benchmarks de CIS estructuran los controles en dos niveles de madurez operativa:

- **Nivel 1 (Baseline):** Configuraciones prácticas de seguridad que no impactan significativamente en el rendimiento ni limitan la funcionalidad operativa.
- **Nivel 2 (Defense-in-Depth):** Configuraciones de máxima rigidez defensiva orientadas a entornos de alta sensibilidad (e.g. PCI-DSS, HIPAA), que pueden requerir arquitectura adicional o reducir flexibilidad.

### Áreas Críticas de Auditoría por Proveedor

| Dominio CIS | AWS Foundations v5.0 | Azure Foundations v4.0 | GCP Foundations v4.0 |
| :--- | :--- | :--- | :--- |
| **Identidad (IAM)** | MFA forzado en root/admins; rotación de claves <90d; sin credenciales consolas | PIM activado; sin admins permanentes; bloqueo de auth heredada | Cero uso de roles primitivos (`Owner`/`Editor`); claves de SA gestionadas por Google |
| **Almacenamiento** | S3 Block Public Access a nivel cuenta; cifrado KMS obligatorio | Cifrado de Storage Accounts; HTTPS forzado; sin acceso blob anónimo | Bloqueo de acceso público (Uniform Bucket-Level Access); cifrado CMEK |
| **Logging y Auditoría** | CloudTrail multi-región con validación de integridad; S3 access logs | Activity Logs retenidos $\ge 365$ días; Diagnostic Settings en todos los recursos | Cloud Audit Logs activados para todas las llamadas de lectura/escritura |
| **Redes** | Puertos 22/3389 cerrados al mundo (`0.0.0.0/0`); VPC Flow Logs activos | NSG restringiendo tráfico entrante; Azure Bastion; sin IPs públicas directas | Reglas de firewall sin `0.0.0.0/0` en puertos de administración; Private Google Access |

---

## 🪣 Bastionado Preventivo de AWS S3: Block Public Access

Para erradicar fugas de datos en cubos S3, se debe aplicar el bloqueo a nivel de toda la cuenta AWS mediante AWS CLI o Terraform:

### 1. Enforzamiento a Nivel de Cuenta (AWS CLI)
```bash
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
```

### 2. Definición Canónica en Terraform (HCL Seguro)
```hcl
# Bloqueo a nivel de cuenta
resource "aws_s3_account_public_access_block" "account_wide" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Configuración segura para cubo de datos
resource "aws_s3_bucket" "secure_storage" {
  bucket = "company-secure-data-prod"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "alias/aws/s3"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

---

## 📜 Escaneo Estático de Infraestructura como Código (IaC)

Para prevenir el despliegue de configuraciones erróneas, los pipelines CI/CD deben analizar no solo los archivos `.tf`, sino también el plan compilado (`tfplan.json`):

```bash
# 1. Generar plan de infraestructura
terraform init
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json

# 2. Análisis estático del plan con Checkov
checkov -f tfplan.json --framework terraform_plan --output json > checkov-report.json

# 3. Análisis nativo con tfsec con severidad mínima HIGH
tfsec ./terraform/ --minimum-severity HIGH --format json > tfsec-report.json
```
