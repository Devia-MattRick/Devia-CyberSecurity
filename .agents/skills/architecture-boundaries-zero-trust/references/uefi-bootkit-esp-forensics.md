# Auditoría Forense de la Partición EFI (ESP) y Detección de Bootkits Pre-OS

Este documento establece la **Metodología Canónica de Caza y Verificación de Integridad de la EFI System Partition (ESP)** para la Skill **`architecture-boundaries-zero-trust`** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza (MITRE ATT&CK T1542.003)

- **Taxonomía:** CWE-1274 (Improper Access Control for Volatile Memory Registers), CWE-347 (Improper Verification of Cryptographic Signature)
- **Técnica:** T1542.003 (Pre-OS Boot: Bootkit)
- **Vulnerabilidad Canónica:** `VULN-ARCH-008` (y `VULN-ARCH-021`)
- **Dimensión:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`

La partición del sistema EFI (ESP) es un volumen con formato FAT32 que el firmware de la placa base monta durante el arranque para localizar y ejecutar el cargador de arranque del sistema operativo (`bootmgfw.efi` en Windows, `grubx64.efi` o `shimx64.efi` en Linux). Debido a que se ejecuta **antes** de que el kernel, los controladores de seguridad y los agentes EDR se inicien, la ESP constituye una de las ubicaciones de persistencia más codiciadas por adversarios avanzados.

### Familias Notables de Bootkits en ESP:
1. **ESPecter (ESET):** Sustituye el administrador de arranque legítimo de Windows (`bootmgfw.efi`) en la ESP y carga controladores en modo kernel maliciosos. Marcó la transición táctica desde el reflasheo de chips SPI físicos hacia la ESP en disco.
2. **BlackLotus (2023):** Primer bootkit in-the-wild capaz de eludir Secure Boot en Windows 11 completamente actualizado mediante la explotación de la vulnerabilidad de revocación CVE-2022-21894 ("baton drop"), alojando un binario vulnerable legítimamente firmado en la ESP.
3. **Bootkitty (2024):** Primer bootkit UEFI dirigido a sistemas Linux, depositado directamente en la ESP.
4. **Glupteba UEFI:** Variante de malware commodity que modifica la partición EFI para garantizar persistencia tras formateos de la partición del SO.

---

## 🔍 Heurística Central de Detección

> [!IMPORTANT]
> **Axioma de Inmutabilidad de la ESP:**  
> Los binarios en la ESP solo sufren modificaciones durante actualizaciones oficiales de firmware o del sistema operativo. Cualquier archivo en la raíz de la ESP que no resida bajo la estructura canónica `EFI/`, o cualquier cambio de hash fuera de ventanas programadas de parcheo, constituye un **indicador de compromiso de severidad crítica**.

---

## 🛠️ Procedimiento de Caza y Verificación Estática

### 1. Extracción e Inventario Determinista de la ESP
- Montar la partición en modo estrictamente de solo lectura (`mount -o ro,umask=077 <device> <mountpoint>`).
- En entornos forenses offline, adquirir la imagen RAW del volumen FAT32 sin alterar marcas de tiempo.
- Catalogar todos los archivos ejecutables PE (`.efi`, `.sys`, `.dll`) y calcular huellas primarias SHA-256.

### 2. Contraste contra Golden Baseline
- Comparar cada hash SHA-256 contra una línea base dorada (*golden baseline*) generada en una estación recién clonada con la misma versión del sistema operativo y fabricante.
- Alertar inmediatamente sobre:
  - Presencia de ejecutables desconocidos no catalogados en el baseline del SO.
  - Modificaciones en `\EFI\Microsoft\Boot\bootmgfw.efi` o `\EFI\Boot\bootx64.efi`.
  - Archivos fuera del directorio `EFI/` (e.g. scripts, controladores o archivos binarios en la raíz FAT32).

### 3. Verificación de Firmas Authenticode y Secure Boot
- Verificar criptográficamente la validez de la firma digital de los binarios UEFI:
  ```bash
  sbverify --list /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi
  ```
- Comprobar que el certificado emisor pertenezca a la CA oficial de Microsoft UEFI o del OEM reconocido y que la clave no esté listada en la base de datos de revocación (`dbx`).

### 4. Detección de Degeneración de Versión (Downgrade / Baton Drop)
- Si un archivo `bootmgfw.efi` en la ESP está firmado legítimamente por Microsoft pero su versión es anterior al umbral de revocación de CVE-2022-21894, el objetivo es vulnerable o está siendo explotado mediante degradación de binario para eludir Secure Boot.

---

## 📋 Checklist de Auditoría para Analistas

- [ ] ¿La partición ESP contiene archivos fuera del árbol `/EFI/`?
- [ ] ¿Todos los ejecutables `.efi` poseen hashes verificados contra la base de datos oficial del SO?
- [ ] ¿Los binarios UEFI superan la verificación de firma `sbverify` contra las claves autorizadas en `db`?
- [ ] ¿Se contrastó la lista de revocaciones `dbx` del firmware contra CVE-2022-21894 y CVE-2023-24932?
- [ ] ¿Existen registros de arranque NVRAM huérfanos (`efibootmgr -v`) que apunten a cargadores eliminados?
