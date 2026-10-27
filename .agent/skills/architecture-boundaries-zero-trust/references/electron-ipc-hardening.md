# Guía de Hardening de Procesos e IPC para Arquitecturas Electron

> **Dimensión:** `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`  
> **Taxonomía:** CWE-668 / CWE-250 / CWE-22 / OWASP A05:2021  
> **Origen de Absorción:** `security-audit/cybersecurity-engineer/references/electron-security-advanced.md` (Acción `ABS-006`)  
> **Vulnerabilidad Asociada:** `VULN-ARCH-002` (Insecure IPC Message Dispatch)  

---

## 🏛️ El Límite de Confianza Renderer $\to$ Main Process

En Electron, el proceso de renderizado (*Renderer Process*) es equivalente a un navegador web: ejecuta código que manipula la interfaz de usuario y que potencialmente podría ser comprometido mediante XSS o dependencias frontend maliciosas.

Por el contrario, el proceso principal (*Main Process*) tiene acceso directo al sistema operativo (`node:fs`, `node:child_process`, sockets de red nativos). Por consiguiente:
> [!CRITICAL]
> **Todo mensaje recibido en un handler `ipcMain.handle` o `ipcMain.on` procede de un límite de confianza no autenticado y debe ser tratado como dato hostil.**

---

## 🔒 1. Validación Estricta de Payloads con Esquemas Zod

Nunca confíe en que el Renderer envía los argumentos esperados. Todo handler IPC debe validar su entrada con Zod antes de ejecutar cualquier operación del sistema:

```typescript
// electron/schemas/ipc-schemas.ts
import { z } from 'zod';

export const ReadFilePayloadSchema = z.object({
  fileId: z.string().uuid(),
  relativePath: z.string().min(1).max(255).regex(/^[\w\-./]+$/),
});

export type ReadFilePayload = z.infer<typeof ReadFilePayloadSchema>;

// electron/main.ts
import { ipcMain } from 'electron';
import { ReadFilePayloadSchema } from './schemas/ipc-schemas.js';

ipcMain.handle('app:read-file', async (event, rawPayload: unknown) => {
  // 1. Validar esquema contract-first
  const parseResult = ReadFilePayloadSchema.safeParse(rawPayload);
  if (!parseResult.success) {
    return {
      success: false,
      error: 'INVALID_PAYLOAD',
      details: parseResult.error.format()
    };
  }

  const { fileId, relativePath } = parseResult.data;

  // 2. Ejecutar operación contenida
  return await safeFileService.readFile(fileId, relativePath);
});
```

---

## 📁 2. Contención de Acceso al Sistema de Archivos con Allowlist

El atacante que comprometa el Renderer suele intentar inyectar secuencias `../` para leer archivos del sistema (`/etc/passwd` o `%SystemRoot%\System32`).

*Patrón Defensivo Canónico:*
```typescript
import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import { app } from 'electron';

export class SafeFileSystemService {
  private allowedRoots: string[];

  constructor() {
    this.allowedRoots = [
      path.resolve(app.getPath('userData')),
      path.resolve(app.getPath('downloads')),
      path.resolve(app.getPath('documents')),
    ];
  }

  public isPathContained(targetPath: string): boolean {
    const resolved = path.resolve(targetPath);
    return this.allowedRoots.some(root => resolved.startsWith(root + path.sep));
  }

  public async readFile(baseDir: string, relativePath: string): Promise<string> {
    const candidatePath = path.resolve(baseDir, relativePath);

    // Verificación estricta de contención
    if (!this.isPathContained(candidatePath)) {
      throw new SecurityError(`Path traversal attempt blocked: ${candidatePath}`);
    }

    return await fs.readFile(candidatePath, 'utf-8');
  }
}
```

---

## 🔄 3. Hardening de Actualizaciones Automáticas (`electron-updater`)

Las actualizaciones automáticas mal configuradas permiten el secuestro de la aplicación mediante la descarga de binarios fraudulentos por HTTP o servidores comprometidos:

1. **Desactivar descarga automática inmediata:** `autoUpdater.autoDownload = false`.
2. **Canales HTTPS estrictos:** Forzar URLs TLS validadas sin tolerar certificados autofirmados.
3. **Verificación Criptográfica de Firmas Digitales:** Antes de ordenar `autoUpdater.quitAndInstall()`, verificar la firma digital del binario descargado utilizando claves públicas asimétricas incrustadas en el build de producción.
