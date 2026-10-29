# Bastionado de Contenedores y Detección de Escape en Runtime con Falco

Este documento establece las directivas arquitectónicas y las reglas de detección en tiempo de ejecución para entornos de contenedores (Docker, containerd, CRI-O, Kubernetes) utilizando el motor eBPF / kmod de **Falco**, enfocado en la prevención y detección de rupturas de aislamiento (Escape de Contenedor - MITRE ATT&CK T1611).

---

## 🏛️ 1. Vectores Canónicos de Escape de Contenedores (T1611)

| Vector de Escape | Mecanismo Técnico | Riesgo / Impacto |
| :--- | :--- | :--- |
| **Exposición del Socket de Docker** | Montaje de `/var/run/docker.sock` dentro del contenedor. | Control total del daemon Docker del host anfitrión; permite levantar contenedores privilegiados con la raíz montada (`/:/host`). |
| **Contenedores Privilegiados (`--privileged`)** | Desactiva AppArmor, Seccomp y otorga todas las capacidades Linux (`CAP_SYS_ADMIN`, `CAP_SYS_RAWIO`). | Acceso directo a dispositivos del host (`/dev/sda1`) y desbordamiento de memoria de kernel. |
| **Abuso de cgroups `release_agent`** | Manipulación del archivo `release_agent` y notificación en cgroups v1. | Ejecución arbitraria de comandos en el host anfitrión con privilegios de root del kernel cuando el último proceso del cgroup termina. |
| **Escape por Namespace de Host** | Ejecución con `--pid=host`, `--net=host` o `--ipc=host`. | Visibilidad y manipulación de procesos del host (`kill -9`, inyección ptrace) y sniffing de red. |
| **Carga de Módulos de Kernel** | Invocación de llamadas al sistema `init_module` o `finit_module`. | Inserción de rootkits de kernel directamente desde el espacio del contenedor. |

---

## 🛡️ 2. Reglas Canónicas de Falco para Detección de Escape

A continuación se presentan las definiciones autoritativas de reglas Falco para mitigar T1611:

### 2.1. Detección de Modificación de `release_agent` en cgroups
```yaml
- rule: Container Escape via cgroups release_agent
  desc: Detecta intentos de escribir en release_agent para forzar ejecucion en el host
  condition: >
    open_write and container and
    (fd.name startswith "/sys/fs/cgroup" and fd.name endswith "/release_agent")
  output: >
    Posible intento de escape de contenedor modificando cgroups release_agent
    (user=%user.name command=%proc.cmdline file=%fd.name container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, escape, T1611, cgroup]
```

### 2.2. Detección de Acceso no Autorizado a `/var/run/docker.sock`
```yaml
- rule: Access to Docker Socket Inside Container
  desc: Detecta la apertura del descriptor de socket de Docker desde un contenedor
  condition: >
    container and fd.name = "/var/run/docker.sock" and
    not proc.name in (docker_authorized_binaries)
  output: >
    Proceso no autorizado interactuando con el socket de Docker en contenedor
    (user=%user.name command=%proc.cmdline container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [container, docker_socket, privilege_escalation, T1611]
```

### 2.3. Transición o Inyección en Namespaces del Host (`setns`)
```yaml
- rule: Setns or Namespace Change from Container
  desc: Detecta la invocacion de la syscall setns intentando cambiar a un namespace de host
  condition: >
    evt.type = setns and container and
    not proc.name in (runc, containerd, dockerd)
  output: >
    Llamada setns no autorizada desde contenedor para eludir frontera de aislamiento
    (user=%user.name command=%proc.cmdline container_id=%container.id)
  priority: CRITICAL
  tags: [container, escape, T1611, namespace]
```

---

## 🔍 3. Detección de Deriva de Contenedores en Tiempo de Ejecución (*Container Drift*)

El principio fundamental de contenedores inmutables dicta que ningún ejecutable o binario debe compilarse o instalarse en la capa de lectura/escritura del contenedor tras su despliegue:

1. **Detección de Binarios Ejecutados en Capa RW:**
   - Monitorear invocaciones a `execve` donde el binario resida en rutas mutables (`/tmp/`, `/var/tmp/`, `/dev/shm/`, `/root/`).
   - Falco rule condition: `evt.type = execve and container and (proc.name in (package_managers) or fd.name startswith "/tmp/")`.
2. **Alertar sobre Invocaciones a Gestores de Paquetes en Producción:**
   - Invocaciones a `apt`, `apt-get`, `apk`, `yum`, `pip`, `npm` dentro de pods de producción constituyen un indicador de compromiso (IoC) o violación severa de directivas.

---

## ⚙️ 4. Directivas de Endurecimiento Defensivo (*Secure by Default*)

1. **Sistemas de Archivos de Solo Lectura:** Desplegar siempre contenedores con `--read-only` (`readOnlyRootFilesystem: true` en Kubernetes).
2. **Eliminación Total de Capacidades Innecesarias:** Configurar `cap_drop: ["ALL"]` y añadir exclusivamente las mínimas necesarias (e.g. `NET_BIND_SERVICE`). Prohibir taxativamente `CAP_SYS_ADMIN`.
3. **No-New-Privileges:** Configurar `security_opt: ["no-new-privileges:true"]` para neutralizar binarios SUID.
4. **Mapeo Dimensional MECE:** Toda auditoría de escape de contenedores y fronteras de kernel se clasifica en `ARCHITECTURE_BOUNDARIES_ZERO_TRUST`.
