# Orquestación Estigmérgica de Enjambres y Modelado de Grafos de Ataque Probabilísticos

Este documento establece la especificación técnica y las heurísticas de ingeniería para el **Modelado de Amenazas y Planificación de Cadenas de Ataque** mediante **Inteligencia de Enjambre Estigmérgica** y **Grafos de Ataque Ponderados** dentro del ecosistema **Devia-CyberSecurity**.

---

## 🐝 1. Paradigma: Enjambre Estigmérgico vs. Pipeline Secuencial

En sistemas tradicionales de auditoría y pentesting multi-agente, un planificador central (*central planner*) coordina las tareas mediante un pipeline rígido y secuencial:
$$\text{Recon} \longrightarrow \text{Classify} \longrightarrow \text{Exploit} \longrightarrow \text{Report}$$

### Limitaciones Críticas del Pipeline Centralizado:
1. **Cuello de Botella Monolítico:** La velocidad del sistema queda acotada por la etapa más lenta.
2. **Incapacidad de Retroalimentación Inmediata:** Si durante la explotación se descubren subdominios, endpoints o parámetros adicionales, el pipeline no puede regresar de manera orgánica a la fase de reconocimiento.
3. **Saturación del Contexto:** El orquestador acumula un volumen masivo de estado que degrada el razonamiento del LLM.

### Principios del Enjambre Estigmérgico (Stigmergy):
- **Descentralización y Desacoplamiento:** Los agentes no se comunican directamente entre sí ni son despachados por un orquestador central imperativo. Se coordinan indirectamente mediante la lectura y escritura de hechos (*findings*) en una **Pizarra Compartida (*Shared Blackboard*)**.
- **Predicados de Activación (*Trigger Predicates*):** Cada agente define su propio predicado de activación (e.g. tipo de hallazgo, prefijo de objetivo o umbral de feromona). Cuando aparece estado relevante en la pizarra, el agente despierta de manera reactiva y autónoma.
- **Emergencia de Cadenas de Ataque:** Cadenas complejas de explotación (e.g. fuga de memoria $\to$ token robado $\to$ falsificación JWT $\to$ BOLA/IDOR $\to$ RCE) emergen de la interacción del enjambre sin haber sido pre-programadas de forma monolítica.

---

## 🧪 2. Dinámica de Feromonas y Decaimiento Exponencial

Para priorizar observaciones recientes y permitir que las vías muertas (*dead ends*) pierdan relevancia de forma natural sin sobrecargar la memoria, cada hallazgo en la pizarra posee un peso de feromona $P(t)$ que decae exponencialmente según su vida media ($t_{1/2}$):

$$P(t) = P_{\text{base}} \cdot 2^{-\frac{\Delta t}{t_{1/2}}} = P_{\text{base}} \cdot \left(\frac{1}{2}\right)^{\frac{t - t_0}{t_{1/2}}}$$

Donde:
- $P_{\text{base}} \in [0.0, 1.0]$: Peso inicial asignado a la observación.
- $t_{1/2} \in \mathbb{N}^+$: Vida media en segundos configurada según el tipo de hallazgo:
  - Puertos y servicios (`PORT_OPEN`, `SERVICE`): $t_{1/2} \approx 3600\text{ s}$ (estables en el tiempo).
  - Puntos de entrada HTTP (`HTTP_ENDPOINT`): $t_{1/2} \approx 1800\text{ s}$.
  - Sesiones y tokens volátiles (`SESSION`, `TOKEN`): $t_{1/2} \approx 300\text{ s}$ (expiran rápidamente).

### 🛡️ Invariante de Seguridad: Mitigación de Inyecciones de Peso (MINJA Defense)
Un vector de ataque en sistemas de memoria compartida con LLMs consiste en inyectar pesos arbitrariamente altos ($P_{\text{base}} = 9999$) para monopolizar los predicados de activación de otros agentes.

```typescript
// Patrón de Clamp Inmutable en Blackboard:
export function clampPheromone(base: number): number {
  if (base > 1.0) return 1.0;
  if (base < 0.0) return 0.0;
  return base;
}
```

---

## 🕸️ 3. Modelado de Grafo de Ataque Multigrafo (BloodHound para Capa App/Cloud)

El objetivo se modela formalmente como un **grafo dirigido multigraph** $G = (V, E)$, donde:

### Vértices Tipados ($V$):
| Tipo de Nodo (`NodeType`) | Descripción Semántica | Ejemplo Concreto |
| :--- | :--- | :--- |
| `entry` | Punto de partida del atacante (no autenticado). | `entry:internet` |
| `asset` | Host, máquina virtual, microservicio o contenedor. | `asset:api-gateway.internal` |
| `endpoint` | Ruta URL o método API expuesto. | `endpoint:POST /v1/auth/login` |
| `identity` | Usuario, rol, cuenta de servicio o entidad IAM. | `identity:tenant_admin` |
| `token` | Credencial en memoria, sesión, cookie o JWT. | `token:jwt_bearer_victim` |
| `secret` | Clave API, secreto de firma o credencial de BD. | `secret:hmac_signing_key` |
| `object_ref` | Identificador de entidad/recurso (pivote IDOR/BOLA). | `object_ref:order_id_4492` |
| `capability` | Capacidad táctica adquirida por el atacante. | `capability:arbitrary_file_read` |
| `objective` | Activo crítico o "joya de la corona" perseguida. | `objective:database_dump` |

### Aristas Dirigidas Ponderadas ($E$):
Cada transición entre nodos $e = (u, v) \in E$ posee:
- `Type`: `reaches`, `auth_as`, `leaks`, `escalates_to`, `exploits`.
- `Exploitability` $\in (0.0, 1.0]$: Probabilidad empírica de éxito en la transición.
- `Verified`: Booleano que certifica si la arista fue demostrada empíricamente por un oráculo externo no-LLM (fijando `Exploitability = 1.0`).

---

## 📐 4. Cálculo de Ruta Óptima mediante Dijkstra sobre $-\ln(\text{Exploitability})$

### El Problema de la Saturación en Modelos Aditivos:
Sumar puntuaciones lineales ($\sum S_i$) o promediar severidades distorsiona la probabilidad compuesta y satura artificialmente en 100. En una cadena de explotación secuencial, la probabilidad de éxito de la ruta completa es el **producto de las probabilidades individuales**:

$$P(\text{Path}) = \prod_{i=1}^k P(e_i)$$

### La Solución Matemática: Transformación Logarítmica:
Maximizar el producto de probabilidades en $(0, 1]$ equivale formalmente a minimizar la suma de sus logaritmos negativos:

$$\max \prod_{i=1}^k P(e_i) \iff \min \sum_{i=1}^k -\ln(P(e_i))$$

Definiendo el coste de cada arista como:
$$c(e) = -\ln(P(e)) \ge 0 \quad (\text{dado que } P(e) \in (0, 1])$$

El problema se reduce a encontrar el camino más corto (*shortest path*) sobre pesos no negativos, resuelto deterministamente en complejidad $O(|E| + |V| \log |V|)$ mediante el **Algoritmo de Dijkstra**.

```python
import math
import heapq

def shortest_attack_path(graph, source, target):
    dist = {v: math.inf for v in graph.nodes}
    dist[source] = 0.0
    prev = {}
    pq = [(0.0, source)]

    while pq:
        d, u = heapq.heappop(pq)
        if d > dist[u]:
            continue
        if u == target:
            break

        for edge in graph.adj.get(u, []):
            cost = -math.log(max(edge.exploitability, 0.001))
            if dist[u] + cost < dist[edge.to]:
                dist[edge.to] = dist[u] + cost
                prev[edge.to] = edge
                heapq.heappush(pq, (dist[edge.to], edge.to))

    if math.isinf(dist[target]):
        return None, 0.0

    # Reconstrucción de la ruta y cálculo del producto de probabilidad
    path = []
    curr = target
    while curr in prev:
        edge = prev[curr]
        path.append(edge)
        curr = edge.from_node
    path.reverse()

    probability = math.exp(-dist[target])
    return path, probability
```
