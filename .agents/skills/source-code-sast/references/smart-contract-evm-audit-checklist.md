# Checklist de Auditoría de Smart Contracts EVM y Pruebas de Invariantes (Foundry / Solidity)

Este documento constituye la **Guía Canónica de Auditoría Estática, Dinámica y de Invariantes para Smart Contracts Solidity/EVM** en **Devia-CyberSecurity**.

---

## 🏛️ Contexto y Amenaza

- **Taxonomía:** CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-682 (Incorrect Calculation), CWE-798 (Use of Hard-coded Credentials)
- **SWC Registry:** SWC-107 (Reentrancy), SWC-105 (Unprotected Ether Withdrawal), SWC-101 (Integer Overflow and Underflow), SWC-104 (Unchecked Call Return Value)
- **Vulnerabilidad Canónica:** `VULN-SAST-015`
- **Dimensión:** `SOURCE_CODE_SAST`

En entornos EVM, el código desplegado es **inmutable** y custodia activos financieros en tiempo real. Un fallo no corregido pre-despliegue es directamente explotable mediante drenaje de fondos (*Drain of Funds*).

---

## 📋 Las 11 Clases Críticas de Vulnerabilidad en Solidity

### 1. Reentrancia Clásica y Cross-Function (SWC-107)
- **Riesgo:** Ejecutar llamadas externas (`call{value: ...}("")`, hooks ERC-777, `onERC721Received`) **antes** de actualizar el estado interno del contrato.
- **Patrón Seguro:** Aplicar rigurosamente el patrón *Checks-Effects-Interactions* (CEI) y utilizar modificadores `nonReentrant` (OpenZeppelin `ReentrancyGuard`). Preferir mecanismos de retiro pasivo (*Pull over Push*).

### 2. Control de Acceso y Modificadores Huérfanos (SWC-105 / SWC-106)
- **Riesgo:** Funciones administrativas que modifican parámetros críticos sin modificador de guardia (`onlyOwner`, `AccessControl`), o uso de `tx.origin` para autorización (vulnerable a phishing).
- **Patrón Seguro:** Utilizar siempre `msg.sender`. Implementar `Ownable2Step` para evitar transferencias irreversibles a direcciones erróneas.

### 3. Manipulación de Oráculos y Flash Loans (DeFi #1 Exploit Class)
- **Riesgo:** Calcular precios de activos consultando el balance spot de un pool AMM (`getReserves()`). Un atacante utiliza un flash loan multimillonario para distorsionar el balance en una sola transacción y drenar el protocolo.
- **Patrón Seguro:** Utilizar oráculos TWAP (Time-Weighted Average Price) u oráculos descentralizados (Chainlink) con validaciones explícitas de:
  - `updatedAt`: comprobar frescura de datos contra umbral máximo.
  - `answeredInRound`: verificar que la respuesta pertenezca a la ronda actual.
  - Comprobación de límites min/max (`minAnswer`, `maxAnswer`).

### 4. Aritmética, Redondeo e Inflación de Acciones (SWC-101)
- **Riesgo:** División antes de multiplicación con pérdida severa de precisión; o ataque del primer depositante (*Share Inflation Attack*) en bóvedas ERC-4626 donde se donan activos directamente para inflar el precio por acción.
- **Patrón Seguro:** Utilizar Solidity ^0.8.x con comprobación de desbordamiento automática. Emplear `Math.mulDiv` con redondeo explícito a favor del protocolo (`Rounding.Floor` o `Rounding.Ceil`). En bóvedas ERC-4626, incorporar acciones virtuales (*virtual shares / offset*).

### 5. Llamadas Externas de Bajo Nivel No Comprobadas (SWC-104)
- **Riesgo:** Ignorar el booleano retornado por `addr.call(...)` o `token.transfer(...)` (especialmente tokens que no retornan `bool` como USDT).
- **Patrón Seguro:** Utilizar siempre `SafeERC20` de OpenZeppelin (`safeTransfer`, `safeTransferFrom`).

### 6. Desalineación de Almacenamiento en Proxies (SWC-112)
- **Riesgo:** En contratos actualizables (UUPS / Transparent), reordenar o alterar variables de estado entre versiones de implementación, corrompiendo el almacenamiento (*Storage Collision*).
- **Patrón Seguro:** Añadir siempre gaps de almacenamiento (`uint256[50] private __gap;`) y utilizar linters de layout (e.g. Slither `storage-layout diff`). Invocar `_disableInitializers()` en el constructor de la lógica.

### 7. Front-Running y Dependencia del Orden de Transacción (MEV / SWC-114)
- **Riesgo:** Parámetros de intercambio o acuñación sin tolerancia a deslizamiento (`slippage`) ni fecha límite (`deadline`).
- **Patrón Seguro:** Exigir siempre parámetros obligatorios `minAmountOut` y `deadline`.

### 8. Pseudo-Aleatoriedad en la Cadena (SWC-120)
- **Riesgo:** Utilizar `block.timestamp`, `blockhash` o `prevrandao` para determinar ganadores o pagos. Los validadores/mineros pueden manipular o retener bloques.
- **Patrón Seguro:** Utilizar Chainlink VRF (Verifiable Random Function) o esquemas commit-reveal off-chain.

### 9. Denegación de Servicio por Bucles y Reversiones (SWC-113 / SWC-128)
- **Riesgo:** Iterar sobre arrays de tamaño dinámico controlado por el usuario, o pagos push donde la reversión de un receptor bloquea la ejecución para todos los demás usuarios.
- **Patrón Seguro:** Bounded iteration, paginación y pagos pull.

### 10. Peculiaridades de Estándares ERC
- **Riesgo:** Asumir que todos los tokens ERC-20 tienen 18 decimales, no cobran comisión por transferencia (*fee-on-transfer*) o no son rebasificables.
- **Patrón Seguro:** Medir el delta de balance real (`balanceAfter - balanceBefore`) en lugar de confiar ciegamente en el parámetro transferido.

### 11. Higiene Criptográfica y Keystores Cifrados (Regla Tolerancia Cero)
- **Riesgo:** Almacenar claves privadas en texto claro en `.env` (`PRIVATE_KEY=0x...`) o pasarlas como argumentos en CLI (`--private-key`).
- **Patrón Seguro:**
  ```bash
  # Importar clave de forma interactiva en keystore cifrado
  cast wallet import deployer --interactive

  # Despliegue seguro usando la cuenta cifrada por nombre
  forge script script/Deploy.s.sol --account deployer --rpc-url <RPC> --broadcast --verify
  ```
