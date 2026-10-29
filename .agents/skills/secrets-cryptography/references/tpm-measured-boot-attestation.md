# Atestación de Medición de Arranque con TPM 2.0 y Replay de Event Log

Este documento describe el protocolo de auditoría forense para verificar la **Raíz de Confianza Hardware (Hardware Root of Trust)**, el arranque medido (*Measured Boot*) y la atestación remota mediante **TPM 2.0 (Trusted Platform Module)** dentro de **Devia-CyberSecurity**.

---

## 🏛️ Taxonomía y Mapeo Dimensional

- **Dimensión Canónica:** `SECRETS_CRYPTOGRAPHY`
- **Skill Responsable:** [`secrets-cryptography`](file:///.agents/skills/secrets-cryptography/SKILL.md)
- **Vulnerabilidades Asociadas:**
  - [`VULN-CRYP-004`: Insufficiently Random Values / Weak Hardware PRNG](file:///docs/VULNERABILITIES.md)
  - [`VULN-TM-003`: Peripheral Blind Spots (Firmware / Bootkits)](file:///docs/VULNERABILITIES.md)
- **Taxonomía:** CWE-353 (Missing Support for Integrity Check), CWE-327, OWASP A02:2021/2025, MITRE T1542.001 (Pre-OS Boot / Bootkit)

---

## 🧩 1. Asignación de Registros de Configuración de Plataforma (PCR)

El microchip TPM 2.0 almacena hashes de un solo sentido calculados secuencialmente mediante la operación extendida de hash:
$$\text{PCR}_{\text{new}} = \text{SHA-256}(\text{PCR}_{\text{old}} \mathbin{\Vert} \text{Measurement})$$

| Registro PCR | Componente Medido de la Plataforma | Riesgo de Alteración no Autorizada |
| :--- | :--- | :--- |
| **PCR 0** | Firmware de la placa base (CRTM, código UEFI/BIOS, microcódigo CPU). | Infección por bootkit o firmware malicioso en memoria flash SPI. |
| **PCR 1** | Configuración de hardware de la placa base y tablas ACPI. | Adición de dispositivos maliciosos o interfaces DMA hostiles. |
| **PCR 2** | Código de controladores Option ROM (tarjetas de red, controladoras RAID). | Ejecución de código malicioso durante la fase de inicialización PCI. |
| **PCR 4** | Código del gestor de arranque primario (Boot Manager, shim, GRUB). | Sustitución o bypass del bootloader seguro. |
| **PCR 5** | Configuración y tablas de particiones del disco (GPT/MBR). | Modificación encubierta de la tabla de particiones o sector de arranque. |
| **PCR 7** | Estado de Secure Boot y certificados PK, KEK, db y dbx. | Desactivación de Secure Boot o inyección de certificados comprometidos. |
| **PCR 8-9** | Parámetros del kernel de Linux, initramfs y línea de comandos de arranque. | Inyección de argumentos de depuración o initramfs troyanizado. |

---

## 🔬 2. Metodología de Reproducción Determinista (Event Log Replay)

Para certificar que los valores de los registros PCR reflejan un estado de software legítimo y no una manipulación encubierta:

```bash
# 1. Volcar los valores actuales de los PCRs del banco SHA-256
tpm2_pcrread sha256:0,1,2,4,5,7 > current_pcrs.txt

# 2. Extraer el registro binario de eventos del sistema (TCG Event Log)
cp /sys/kernel/security/tpm0/binary_bios_measurements bios_event_log.bin

# 3. Simular la secuencia de eventos recalculando los PCRs desde el estado 0
# Cada evento registrado en bios_event_log debe coincidir exactamente con el valor final
python3 -c '
import hashlib, struct

# Iniciar PCR 0 con 32 bytes de ceros
pcr0 = b"\x00" * 32
# Por cada evento medido en el log:
# pcr0 = hashlib.sha256(pcr0 + digest_evento).digest()
'

# 4. Generar y verificar la Cita Criptográfica (TPM Quote) firmada por la Clave de Atestación (AK)
tpm2_quote \
  --key-context ak.ctx \
  --pcr-list sha256:0,1,2,4,7 \
  --qualification "$NONCE" \
  --signature quote.sig \
  --message quote.msg

# 5. Validar la firma con la clave pública de la AK certificada por la CA corporativa
openssl dgst -sha256 -verify ak_public.pem -signature quote.sig quote.msg
```

---

## 🛡️ 3. Reglas de Diagnóstico y Remediación para Auditores

1. **Discrepancia en PCR 7 (Secure Boot Compromise):**
   Si el valor de PCR 7 difiere del valor de referencia de la flota, el equipo ha sufrido una alteración en la base de firmas `db/dbx` o el Secure Boot fue deshabilitado temporalmente.
2. **Ausencia de Eventos en el Log para un PCR no nulo:**
   Si un PCR contiene un hash no trivial pero el log de eventos no registra las operaciones intermedias que llevaron a ese hash, se considera un **hallazgo crítico de integridad de telemetría**: el registro fue manipulado o la medición ocurrió fuera del canal estándar.
3. **Validación de Nonce en Citas:**
   La cita criptográfica (`tpm2_quote`) debe exigir obligatoriamente un nonce efímero emitido por el verificador para neutralizar ataques de repetición (*Replay Attacks*).
