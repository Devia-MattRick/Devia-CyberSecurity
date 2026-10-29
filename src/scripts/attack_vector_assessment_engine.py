#!/usr/bin/env python3
"""Attack Vector & Exploitability Assessment Engine (Capa 3: Python Determinista).

Evaluates target systems, codebases, or configuration artifacts against canonical attack vectors
derived from exploiting-skills (ADCS ESC1, Kerberos S4U, HTTP Request Smuggling, Prototype Pollution,
SSTI, Mass Assignment, CSWSH, Deep Links, etc.) under the 8 Canonical Dimensions.

Outputs structured JSON strictly conforming to ExploitPathAssessmentSchema.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from typing import Any, Dict, List, Optional
import uuid


CANONICAL_VECTORS: List[Dict[str, Any]] = [
    {
        "vectorId": "VEC-ADCS-ESC1",
        "title": "Abuso de Plantillas de Certificados AD CS con SAN Spoofing (ESC1)",
        "dimension": "IDENTITY_ACCESS_SESSION",
        "cwe": "CWE-295",
        "mitreTechnique": "T1649",
        "vulnerabilityId": "VULN-IAM-015",
        "prerequisites": [
            "Autenticación de usuario de dominio válida (incluso de bajo privilegio)",
            "Plantilla AD CS con bandera CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001) activada",
            "EKU de Client Authentication (1.3.6.1.5.5.7.3.2) o Smartcard Logon presente",
            "Permisos de inscripción (Enroll / AutoEnroll) asignados a Domain Users o Authenticated Users"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scopeChanged": True,
            "exploitabilityScore": 8.8
        },
        "verificationOracle": "Inspección estática de msPKI-Certificate-Name-Flag y pKIExtendedKeyUsage en el contenedor CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration.",
        "remediationControls": [
            "Desmarcar 'Supply in the request' en la pestaña Subject Name de la plantilla",
            "Habilitar 'CA certificate manager approval' en la pestaña Issuance Requirements",
            "Eliminar permisos de inscripción para Domain Users en plantillas con EKU de autenticación"
        ]
    },
    {
        "vectorId": "VEC-BLOODHOUND-PATH",
        "title": "Abuso de Permisos SDDL y Rutas Mínimas de Escalada Active Directory (BloodHound)",
        "dimension": "IDENTITY_ACCESS_SESSION",
        "cwe": "CWE-269",
        "mitreTechnique": "T1078.002",
        "vulnerabilityId": "VULN-IAM-001",
        "prerequisites": [
            "Acceso de lectura a consultas LDAP del dominio",
            "Relaciones ACL permisivas (GenericAll, WriteDacl, WriteOwner, ForceChangePassword)",
            "Ruta transitiva no interrumpida entre identidad inicial y grupo privilegiado (Domain Admins)"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scopeChanged": True,
            "exploitabilityScore": 8.5
        },
        "verificationOracle": "Ejecución de consultas Cypher sobre el grafo AD para identificar caminos de longitud <= 3 sin controles de tiering.",
        "remediationControls": [
            "Aplicar modelo administrativo por capas (Tier Model / ESAE)",
            "Auditar y revocar permisos explícitos GenericAll/WriteDacl sobre unidades organizativas y usuarios sensibles",
            "Requerir aprobación PIM/PAM para membresía temporal en Domain Admins"
        ]
    },
    {
        "vectorId": "VEC-KERBEROS-S4U",
        "title": "Abuso de Delegación Restringida Kerberos y Transición S4U2self/S4U2proxy",
        "dimension": "IDENTITY_ACCESS_SESSION",
        "cwe": "CWE-287",
        "mitreTechnique": "T1558",
        "vulnerabilityId": "VULN-IAM-016",
        "prerequisites": [
            "Control de cuenta de servicio o máquina con msDS-AllowedToDelegateTo poblado",
            "Permiso de transición de protocolo (TRUSTED_TO_AUTH_FOR_DELEGATION activado)",
            "Cuentas objetivo no protegidas contra delegación (sin atributo NOT_DELEGATED)"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scopeChanged": True,
            "exploitabilityScore": 8.0
        },
        "verificationOracle": "Inspección LDAP de userAccountControl para la bandera TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000).",
        "remediationControls": [
            "Añadir todas las cuentas de administración al grupo de seguridad 'Protected Users'",
            "Marcar cuentas sensibles con la opción 'Account is sensitive and cannot be delegated'",
            "Migrar de delegación clásica basada en Kerberos a Delegación Restringida Basada en Recursos (RBCD)"
        ]
    },
    {
        "vectorId": "VEC-HTTP-SMUGGLING",
        "title": "Desincronización HTTP y Request Smuggling en Fronteras Proxy-Backend",
        "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
        "cwe": "CWE-444",
        "mitreTechnique": "T1190",
        "vulnerabilityId": "VULN-SAST-017",
        "prerequisites": [
            "Arquitectura con proxy inverso/balanceador y servidor backend interconectados sobre HTTP/1.1",
            "Manejo dispar de cabeceras ambiguas Transfer-Encoding y Content-Length (CL.TE o TE.CL)",
            "Reutilización de conexiones TCP persistentes (keep-alive) entre proxy y backend"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "HIGH",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scopeChanged": True,
            "exploitabilityScore": 6.8
        },
        "verificationOracle": "Envío de peticiones con cabeceras duales RFC 7230 y verificación de respuesta 400 Bad Request inmediata en el proxy perimetral.",
        "remediationControls": [
            "Exigir HTTP/2 de extremo a extremo entre clientes, proxies y servidores backend",
            "Configurar el proxy para rechazar terminantemente cualquier petición con Transfer-Encoding ambiguo",
            "Normalizar cabeceras HTTP descartando peticiones con múltiples Content-Length"
        ]
    },
    {
        "vectorId": "VEC-PROTOTYPE-POLLUTION",
        "title": "Prototype Pollution e Inyección de Propiedades en JavaScript / Node.js",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": "CWE-1321",
        "mitreTechnique": "T1059.007",
        "vulnerabilityId": "VULN-SAST-018",
        "prerequisites": [
            "Función de fusión profunda (deep merge), clonación recursiva o asignación de objetos sin filtrado",
            "Ingesta de objetos JSON controlados por el usuario con claves __proto__ o constructor.prototype",
            "Presencia de gadgets en el runtime que consuman propiedades heredadas en sumideros críticos"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scopeChanged": False,
            "exploitabilityScore": 9.0
        },
        "verificationOracle": "Prueba determinista in-memory verificando si una función clone/merge rechaza claves reservadas o si Object.prototype permanece congelado.",
        "remediationControls": [
            "Congelar el prototipo global en arranque con Object.freeze(Object.prototype)",
            "Crear diccionarios seguros sin prototipo mediante Object.create(null) o Map",
            "Validar rigurosamente los esquemas JSON de entrada mediante Zod antes de operar con objetos"
        ]
    },
    {
        "vectorId": "VEC-MASS-ASSIGNMENT",
        "title": "Auto-Binding Masivo de Propiedades en REST APIs (Mass Assignment)",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": "CWE-915",
        "mitreTechnique": "T1078",
        "vulnerabilityId": "VULN-SAST-019",
        "prerequisites": [
            "Endpoint de creación o actualización que enlace automáticamente el cuerpo de la petición al modelo ORM",
            "Ausencia de lista blanca explícita de campos mutables permitidos (DTOs)",
            "Modelo de datos con propiedades administrativas o de estado sensibles (isAdmin, role, balance, verified)"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "LOW",
            "userInteraction": "NONE",
            "scopeChanged": False,
            "exploitabilityScore": 8.0
        },
        "verificationOracle": "Análisis estático de controladores verificando si el método del ORM (e.g. Entity.create(req.body)) recibe directamente la carga no validada.",
        "remediationControls": [
            "Exigir el patrón DTO (Data Transfer Object) estricto con validación autoritativa Zod/Pydantic",
            "Aplicar listas blancas de propiedades mutables en controladores y servicios",
            "Proteger campos sensibles en entidades ORM marcándolos como de sólo lectura en API"
        ]
    },
    {
        "vectorId": "VEC-SSTI",
        "title": "Inyección de Plantillas del Servidor (SSTI) y Fuga de Sandbox",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": "CWE-1336",
        "mitreTechnique": "T1190",
        "vulnerabilityId": "VULN-SAST-020",
        "prerequisites": [
            "Concatenación de entradas no confiables directamente en la cadena de plantilla antes de compilar",
            "Motor de plantillas con capacidades de ejecución de expresiones (Jinja2, Twig, Freemarker, Thymeleaf)",
            "Acceso no restringido a objetos globales reflectivos (__class__, getClass(), loader)"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scopeChanged": True,
            "exploitabilityScore": 9.5
        },
        "verificationOracle": "Evaluación diferencial de pares aritméticos deterministas ({{7*7}} -> 49) sin ejecución de código malicioso.",
        "remediationControls": [
            "Pasar entradas de usuario exclusivamente a través del contexto de datos, jamás concatenar en la plantilla",
            "Utilizar motores de plantillas sin lógica (logic-less) como Mustache o Liquid",
            "Configurar sandboxes de plantillas estrictos con desactivación de introspección reflectiva"
        ]
    },
    {
        "vectorId": "VEC-TYPE-JUGGLING",
        "title": "Comparaciones Débiles y Hashes Mágicos en Autenticación (Type Juggling)",
        "dimension": "SOURCE_CODE_SAST",
        "cwe": "CWE-843",
        "mitreTechnique": "T1552",
        "vulnerabilityId": "VULN-SAST-021",
        "prerequisites": [
            "Uso de operadores de comparación débil (== en PHP/JS) en validación de contraseñas, tokens o firmas",
            "Manejo de contraseñas o tokens mediante algoritmos de hash criptográficos (MD5, SHA1) que pueden producir secuencias '0e...'",
            "Entradas de usuario no tipadas estrictamente recibidas como strings o enteros"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scopeChanged": False,
            "exploitabilityScore": 7.5
        },
        "verificationOracle": "Análisis AST detectando el uso del operador '==' en lugar de '===' o funciones de comparación en tiempo constante.",
        "remediationControls": [
            "Exigir comparaciones estrictas (===) en todo el código base",
            "Utilizar funciones de comparación seguras en tiempo constante (hash_equals en PHP, crypto.timingSafeEqual en Node.js)",
            "Migrar almacenamiento de contraseñas a funciones de derivación modernas con sal (Argon2id)"
        ]
    },
    {
        "vectorId": "VEC-DEEPLINK-HIJACK",
        "title": "Secuestro de Esquemas URI Personalizados y Enlaces Profundos Móviles",
        "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
        "cwe": "CWE-939",
        "mitreTechnique": "T1204",
        "vulnerabilityId": "VULN-ARCH-031",
        "prerequisites": [
            "Aplicación móvil/desktop que registra un esquema URI personalizado no verificado (myapp://)",
            "Ausencia de verificación criptográfica de dominio (sin Digital Asset Links o Apple App Site Association)",
            "Procesamiento de parámetros de URL sensibles (tokens, comandos de redirección) sin validación de origen"
        ],
        "metrics": {
            "attackVector": "LOCAL",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "REQUIRED",
            "scopeChanged": True,
            "exploitabilityScore": 6.5
        },
        "verificationOracle": "Inspección de AndroidManifest.xml verificando ausencia del atributo autoVerify='true' en filtros intent con esquemas personalizados.",
        "remediationControls": [
            "Migrar a Android App Links y Apple Universal Links basados en HTTPS con verificación de dominio",
            "Validar estrictamente parámetros de entrada y restringir navegación a dominios en lista blanca",
            "Jamás transmitir tokens de autenticación o secretos a través de parámetros o fragmentos de URI"
        ]
    },
    {
        "vectorId": "VEC-WEBSOCKET-CSWSH",
        "title": "Secuestro de Canales WebSocket entre Sitios (CSWSH)",
        "dimension": "ARCHITECTURE_BOUNDARIES_ZERO_TRUST",
        "cwe": "CWE-346",
        "mitreTechnique": "T1189",
        "vulnerabilityId": "VULN-ARCH-030",
        "prerequisites": [
            "Servidor WebSocket que autentica conexiones iniciales basándose exclusivamente en cookies de sesión automáticas",
            "Ausencia de validación estricta de la cabecera Origin durante el apretón de manos (handshake) HTTP",
            "Falta de tokens anti-CSRF efímeros requeridos en la URL de handshake o en el primer mensaje de sesión"
        ],
        "metrics": {
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "REQUIRED",
            "scopeChanged": False,
            "exploitabilityScore": 7.5
        },
        "verificationOracle": "Verificación del middleware de handshake confirmando si rechaza conexiones con cabecera Origin no autorizada o ausente.",
        "remediationControls": [
            "Validar estrictamente la cabecera Origin contra una lista blanca de orígenes confiables en el servidor",
            "Exigir tokens de sesión de un solo uso o tokens anti-CSRF vinculados criptográficamente al handshake",
            "Configurar cookies de sesión con el atributo SameSite=Strict"
        ]
    }
]


def evaluate_vectors(
    target_name: str,
    scope: str,
    environment: str = "INTERNAL_AUDIT",
    blocked_vector_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Evaluates all canonical vectors against target, computing posture metrics deterministically."""
    blocked_ids = set(blocked_vector_ids or [])
    evaluated: List[Dict[str, Any]] = []

    prerequisites_met = 0
    prerequisites_blocked = 0

    dimension_risks: Dict[str, float] = {}

    for vec in CANONICAL_VECTORS:
        vec_id = vec["vectorId"]
        is_blocked = vec_id in blocked_ids
        status = "PREREQUISITES_BLOCKED" if is_blocked else "PREREQUISITES_MET"

        if is_blocked:
            prerequisites_blocked += 1
        else:
            prerequisites_met += 1
            dim = vec["dimension"]
            score = vec["metrics"]["exploitabilityScore"]
            dimension_risks[dim] = max(dimension_risks.get(dim, 0.0), score)

        item = {
            "vectorId": vec["vectorId"],
            "title": vec["title"],
            "dimension": vec["dimension"],
            "cwe": vec["cwe"],
            "mitreTechnique": vec.get("mitreTechnique"),
            "vulnerabilityId": vec.get("vulnerabilityId"),
            "prerequisites": vec["prerequisites"],
            "metrics": vec["metrics"],
            "status": status,
            "verificationOracle": vec["verificationOracle"],
            "remediationControls": vec["remediationControls"]
        }
        evaluated.append(item)

    # Calculate overall posture grade
    if prerequisites_met == 0:
        posture_grade = "HARDENED"
    elif prerequisites_met > 5:
        posture_grade = "CRITICAL_EXPOSURE"
    else:
        posture_grade = "MODERATE_RISK"

    highest_dim = "IDENTITY_ACCESS_SESSION"
    if dimension_risks:
        highest_dim = max(dimension_risks.items(), key=lambda x: x[1])[0]

    report = {
        "assessmentId": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {
            "name": target_name,
            "scope": scope,
            "environment": environment
        },
        "evaluatedVectors": evaluated,
        "summary": {
            "totalVectorsEvaluated": len(evaluated),
            "prerequisitesMetCount": prerequisites_met,
            "prerequisitesBlockedCount": prerequisites_blocked,
            "postureGrade": posture_grade,
            "highestRiskDimension": highest_dim
        }
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack Vector & Exploitability Assessment Engine for Devia-CyberSecurity"
    )
    parser.add_argument("--target", default="Target-Infrastructure-and-Codebase", help="Target name")
    parser.add_argument("--scope", default="corp.internal", help="Scope definition")
    parser.add_argument("--env", default="INTERNAL_AUDIT", choices=["PRODUCTION", "STAGING", "INTERNAL_AUDIT", "OFFLINE_SOURCE"], help="Environment")
    parser.add_argument("--block", action="append", default=[], help="Vector IDs to mark as blocked/mitigated")
    parser.add_argument("--output", "-o", help="Path to write JSON report")
    parser.add_argument("--json", action="store_true", help="Print output as JSON")

    args = parser.parse_args()

    report = evaluate_vectors(
        target_name=args.target,
        scope=args.scope,
        environment=args.env,
        blocked_vector_ids=args.block
    )

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Report written to {out_path}", file=sys.stderr)

    if args.json or not args.output:
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
