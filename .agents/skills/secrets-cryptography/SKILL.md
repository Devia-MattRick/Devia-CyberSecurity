---
name: secrets-cryptography
description: Escaneo exhaustivo de credenciales hardcodeadas, cálculo de entropía de Shannon, validación de la postura criptográfica (algoritmos obsoletos, modos de cifrado, generadores pseudoaleatorios) y ciclo de vida de claves.
---

# Secrets & Cryptographic Posture

**Dimensión Canónica:** `SECRETS_CRYPTOGRAPHY` (Dimensión 3)

---

## 🎯 Objetivo Delegado y Asignado

Esta Skill gobierna la dimensión de **Secretos y Postura Criptográfica**. Su responsabilidad primordial es:
1. Escanear repositorios y árboles de archivos en busca de credenciales, claves privadas, certificados, API keys y tokens hardcodeados.
2. Aplicar algoritmos de cálculo de entropía de Shannon para detectar cadenas de alta aleatoriedad con filtrado de falsos positivos.
3. Evaluar la robustez de los primitivos criptográficos implementados: detectar algoritmos obsoletos o rotos (MD5, SHA-1, DES, 3DES, RC4).
4. Verificar modos de operación de cifrado (prohibir AES en modo ECB, exigir AES-GCM o ChaCha20-Poly1305 con IV/nonce únicos).
5. Auditar el uso de generadores de números aleatorios: asegurar el uso de CSPRNG (`crypto.randomBytes`, `secrets`, `/dev/urandom`) frente a PRNGs débiles (`Math.random`, `random`).
6. Revisar el ciclo de vida de gestión de claves: almacenamiento seguro, rotación, derivación (PBKDF2, Argon2, scrypt) y destrucción en memoria.

---

## 📂 Organización Interna

- `references/`: Tablas de algoritmos criptográficos recomendados vs prohibidos, heurísticas de entropía y firmas de tokens de proveedores (6 referencias técnicas).
  - [`source-exposed-secrets-standard.md`](references/source-exposed-secrets-standard.md): Estándar de divulgación de secretos por lectura de código fuente (sin requisito de ejecución ni ruta de ataque runtime).

---

## 🛠️ Herramientas de Capa 3 Asignadas (`src/scripts/`)

Esta Skill consume y orquesta los siguientes motores de análisis determinista en Python 3.11+:

| Script Ejecutable | Contrato Zod (Capa 2) | Rol y Capacidades | Test Unitario |
| :--- | :--- | :--- | :--- |
| [`src/scripts/scan_secrets.py`](file:///k:/Devia-CyberSecurity/src/scripts/scan_secrets.py) | [`finding.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/finding.schema.ts) | Escáner determinista de secretos con cálculo de entropía de Shannon y firmas de proveedores. | [`test_scan_secrets.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_scan_secrets.py) |
| [`src/scripts/pqc_inventory_scanner.py`](file:///k:/Devia-CyberSecurity/src/scripts/pqc_inventory_scanner.py) | [`cryptographic-inventory.schema.ts`](file:///k:/Devia-CyberSecurity/src/schemas/cryptographic-inventory.schema.ts) | Auditoría de inventario criptográfico y preparación para migración Post-Cuántica (PQC FIPS 203/204). | [`test_pqc_inventory_scanner.py`](file:///k:/Devia-CyberSecurity/src/scripts/test_pqc_inventory_scanner.py) |
