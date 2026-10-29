# Seguridad de Firmware UEFI, Bloqueos SPI Flash y Análisis con CHIPSEC

Este documento establece la **Guía de Auditoría de Plataforma y Seguridad Pre-OS en Hardware x86** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-1274 (Improper Access Control for Volatile Memory Registers), CWE-250 (Execution with Unnecessary Privileges)
- **MITRE ATT&CK:** T1542.001 (Pre-OS Boot: System Firmware)
- **Vulnerabilidad Canónica:** `VULN-ARCH-021` (y `VULN-CRYP-004`)
- **Dimensión:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`

Los adversarios que logran implantar código en el firmware de la placa base (BIOS/UEFI en memoria flash SPI) obtienen persistencia total invisible al sistema operativo, resistente a formateos de disco o reinstalaciones del SO, y con control directo sobre el System Management Mode (SMM / Ring -2).

---

## 🔒 Controles Críticos de Hardware y Registros de Bloqueo

CHIPSEC (Intel Platform Security Assessment Framework) evalúa que los candados de silicio estén activados por el fabricante (OEM) antes de ceder el control al gestor de arranque:

### 1. Protección contra Escritura del BIOS (`common.bios_wp`)
- **Registro:** `BIOS_CNTL` (BIOS Control Register en el chipset PCH/LPC).
- **Bits Críticos:**
  - `BLE` (BIOS Lock Enable): Al estar en `1`, cualquier intento de escritura en el registro genera un System Management Interrupt (SMI), forzando a que la escritura sea validada por SMM.
  - `SMM_BWP` (SMM BIOS Write Protect): Al estar en `1`, el espacio flash de BIOS solo puede ser modificado si todos los núcleos del procesador están en modo SMM. Si `SMM_BWP = 0`, basta con que un solo hilo comprometa el driver del SO para reprogramar el BIOS.

### 2. Bloqueo del Descriptor de Memoria Flash SPI (`common.spi_lock`)
- **Registro:** `FLOCKDN` (Flash Configuration Lock-Down).
- **Mecanismo:** El chip SPI flash está dividido en regiones (Descriptor, BIOS, ME/CSME, Gigabit Ethernet). Cuando `FLOCKDN` está activo, la tabla de permisos de lectura y escritura de regiones queda inmutable hasta el siguiente reinicio por hardware. Si no está bloqueado, un proceso con privilegios de root/administrador puede reescribir regiones protegidas.

### 3. Aislamiento de Memoria del Sistema (SMRAM / SMRR) (`common.smrr`)
- **Mecanismo:** `SMRR` (System Management Range Registers) protege el rango de memoria física de SMM para que solo pueda ser accedido por el procesador cuando opera en modo SMM. Si los SMRR están deshabilitados o mal configurados, el kernel del sistema operativo (Ring 0) puede leer o escribir en la memoria de SMM, permitiendo escalada de privilegios a Ring -2.

### 4. Protección de Variables de Secure Boot (`common.secureboot.variables`)
- **Mecanismo:** Variables UEFI autoritativas (`PK`, `KEK`, `db`, `dbx`) deben estar protegidas con el atributo `EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS` o `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS`. Si las variables pueden modificarse sin firma criptográfica válida, Secure Boot puede ser desactivado o puenteado para cargar bootkits.

---

## 🛠️ Procedimientos de Auditoría Offline y Clean-Room

1. **Volcado Forense de Imagen SPI Flash:**
   ```bash
   # Volcar la imagen completa para análisis estático sin ejecutar código en el host auditado
   sudo chipsec_util spi dump spi_image.bin
   ```
2. **Desempaquetado y Análisis de Módulos UEFI:**
   - Inspeccionar la estructura de volúmenes de firmware (FV) mediante herramientas estáticas (`UEFITool`, `fwhunt-scan`).
   - Comprobar hashes SHA-256 de los ejecutables EFI contra la base de datos de imágenes firmadas de fábrica del fabricante.
3. **Inspección de NVRAM y Variables UEFI:**
   - Extraer la lista de variables NVRAM en busca de nombres anómalos o variables creadas dinámicamente con permisos de escritura no autenticada.
