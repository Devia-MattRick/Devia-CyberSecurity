#!/usr/bin/env python3
"""Deterministic Target Scope Guard and Rules of Engagement (RoE) Enforcement Engine (Capa 3).

Evaluates candidate command lines and target declarations against an authoritative scope file.
Applies fail-closed deterministic policy (zero DNS lookups, strict literal host matches,
CIDR network checks, and allowed port bounds) with hybrid command-line belt-and-suspenders
inspection.

Adheres strictly to Devia-CyberSecurity's Capa 3 engineering invariants:
- Pure Python 3.11+ standard library (os, sys, json, ipaddress, urllib.parse, re, argparse).
- Zero third-party dependencies.
- Structured JSON output (--json) and CLI exit codes (0 = allowed, 1 = blocked, 2 = config error).
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlsplit

_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Regex conservative for IP / Hostname extraction in command lines
_IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\'\"<>]+", re.IGNORECASE)
_HOST_PORT_RE = re.compile(r"\b([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*):(\d{1,5})\b")


class ScopeError(ValueError):
    """Fail-closed configuration or parsing error."""


@dataclass
class Target:
    raw: str
    host: str
    ip: Optional[_Address] = None
    port: Optional[int] = None


@dataclass
class ScopeConfig:
    enabled: bool
    allow_cidrs: List[_Network] = field(default_factory=list)
    allow_hosts: Set[str] = field(default_factory=set)
    deny_cidrs: List[_Network] = field(default_factory=list)
    deny_hosts: Set[str] = field(default_factory=set)
    ports: Optional[Set[int]] = None


@dataclass
class ScopeDecision:
    allowed: bool
    enforced: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)
    evaluated_targets: List[Dict[str, Any]] = field(default_factory=list)


def get_utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_scope_dict(data: Dict[str, Any]) -> ScopeConfig:
    if not isinstance(data, dict):
        raise ScopeError("Scope configuration must be a JSON object")

    enabled = bool(data.get("enabled", False))

    allow_cidrs: List[_Network] = []
    allow_hosts: Set[str] = set()
    deny_cidrs: List[_Network] = []
    deny_hosts: Set[str] = set()

    for item in data.get("allow", []):
        if not isinstance(item, dict):
            continue
        if "cidr" in item:
            try:
                allow_cidrs.append(ipaddress.ip_network(item["cidr"], strict=False))
            except ValueError as err:
                raise ScopeError(f"Invalid allow CIDR: {item['cidr']}") from err
        if "host" in item:
            allow_hosts.add(str(item["host"]).lower().strip())

    for item in data.get("deny", []):
        if not isinstance(item, dict):
            continue
        if "cidr" in item:
            try:
                deny_cidrs.append(ipaddress.ip_network(item["cidr"], strict=False))
            except ValueError as err:
                raise ScopeError(f"Invalid deny CIDR: {item['cidr']}") from err
        if "host" in item:
            deny_hosts.add(str(item["host"]).lower().strip())

    ports: Optional[Set[int]] = None
    if "ports" in data and data["ports"] is not None:
        raw_ports = data["ports"]
        if not isinstance(raw_ports, list):
            raise ScopeError("Scope 'ports' must be an array of integers")
        ports = set()
        for p in raw_ports:
            try:
                p_int = int(p)
                if 1 <= p_int <= 65535:
                    ports.add(p_int)
                else:
                    raise ScopeError(f"Port out of bounds [1-65535]: {p}")
            except (ValueError, TypeError) as err:
                raise ScopeError(f"Invalid port value: {p}") from err

    return ScopeConfig(
        enabled=enabled,
        allow_cidrs=allow_cidrs,
        allow_hosts=allow_hosts,
        deny_cidrs=deny_cidrs,
        deny_hosts=deny_hosts,
        ports=ports
    )


def load_scope_file(path: Union[str, Path]) -> Optional[ScopeConfig]:
    p = Path(path).resolve()
    if not p.is_file():
        return None
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return parse_scope_dict(data)
    except json.JSONDecodeError as err:
        raise ScopeError(f"Corrupt scope JSON at {p}: {err}") from err
    except Exception as err:
        raise ScopeError(f"Failed to read scope file at {p}: {err}") from err


def normalize_target_string(raw: str) -> Target:
    s = raw.strip()
    port: Optional[int] = None

    if "://" in s:
        try:
            parts = urlsplit(s)
            host = parts.hostname or ""
            port = parts.port
            if not port:
                if parts.scheme.lower() == "https":
                    port = 443
                elif parts.scheme.lower() == "http":
                    port = 80
        except Exception:
            host = s
    elif ":" in s and not s.endswith(":") and not s.startswith("["):
        host_part, _, port_part = s.rpartition(":")
        try:
            p_val = int(port_part)
            if 1 <= p_val <= 65535:
                port = p_val
                host = host_part
            else:
                host = s
        except ValueError:
            host = s
    else:
        host = s

    host = host.lower().strip()
    ip: Optional[_Address] = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass

    return Target(raw=raw, host=host, ip=ip, port=port)


def extract_targets_from_command(command: str) -> List[Target]:
    extracted: List[Target] = []
    if not command:
        return extracted

    for url_match in _URL_RE.findall(command):
        extracted.append(normalize_target_string(url_match))

    for ip_str in _IPV4_RE.findall(command):
        extracted.append(normalize_target_string(ip_str))

    for host, port_str in _HOST_PORT_RE.findall(command):
        try:
            p = int(port_str)
            if 1 <= p <= 65535:
                extracted.append(Target(raw=f"{host}:{port_str}", host=host.lower(), port=p))
        except ValueError:
            pass

    return extracted


def evaluate_scope(
    config: Optional[ScopeConfig],
    declared_targets: Optional[List[str]],
    command: Optional[str] = None
) -> ScopeDecision:
    # Kill switch or disabled
    if config is None or not config.enabled or os.environ.get("SCOPE_ENFORCE") == "0":
        return ScopeDecision(allowed=True, enforced=False)

    violations: List[Dict[str, Any]] = []
    evaluated_targets: List[Dict[str, Any]] = []

    # Fail-closed: with active scope, targets must be explicitly declared
    if not declared_targets:
        return ScopeDecision(
            allowed=False,
            enforced=True,
            violations=[{
                "rule": "MISSING_DECLARED_TARGETS",
                "message": "Enforcement active but no targets were declared for the operation."
            }]
        )

    # Validate each declared target
    for raw_t in declared_targets:
        target = normalize_target_string(raw_t)
        t_info = {
            "raw": target.raw,
            "host": target.host,
            "ip": str(target.ip) if target.ip else None,
            "port": target.port
        }
        evaluated_targets.append(t_info)

        # 1. Deny check has absolute priority
        if target.ip:
            if any(target.ip in net for net in config.deny_cidrs):
                violations.append({
                    "rule": "DENIED_CIDR",
                    "target": target.raw,
                    "matched": str(target.ip)
                })
                continue
        if target.host in config.deny_hosts:
            violations.append({
                "rule": "DENIED_HOST",
                "target": target.raw,
                "matched": target.host
            })
            continue

        # 2. Allow check
        is_allowed = False
        if target.ip:
            if any(target.ip in net for net in config.allow_cidrs):
                is_allowed = True
        if target.host in config.allow_hosts:
            is_allowed = True

        if not is_allowed:
            violations.append({
                "rule": "NOT_IN_ALLOW_LIST",
                "target": target.raw,
                "host": target.host,
                "ip": str(target.ip) if target.ip else None
            })
            continue

        # 3. Port check if ports restriction is defined
        if config.ports is not None and target.port is not None:
            if target.port not in config.ports:
                violations.append({
                    "rule": "PORT_NOT_ALLOWED",
                    "target": target.raw,
                    "port": target.port,
                    "allowed_ports": sorted(list(config.ports))
                })

    # Belt-and-suspenders inspection of command arguments
    if command:
        cmd_targets = extract_targets_from_command(command)
        for ct in cmd_targets:
            # If an explicit IP in the command is in deny list
            if ct.ip:
                if any(ct.ip in net for net in config.deny_cidrs):
                    violations.append({
                        "rule": "COMMAND_ARG_IN_DENY_CIDR",
                        "target": ct.raw,
                        "ip": str(ct.ip)
                    })
                # Or if the IP is not in allow CIDR and was not declared
                elif not any(ct.ip in net for net in config.allow_cidrs):
                    # Check if it was in declared targets
                    if not any(normalize_target_string(dt).host == ct.host for dt in (declared_targets or [])):
                        violations.append({
                            "rule": "COMMAND_CONTAINS_UNDECLARED_FOREIGN_IP",
                            "target": ct.raw,
                            "ip": str(ct.ip)
                        })

    allowed = len(violations) == 0
    return ScopeDecision(
        allowed=allowed,
        enforced=True,
        violations=violations,
        evaluated_targets=evaluated_targets
    )


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic Target Scope Guard and Rules of Engagement (RoE) Validator (Capa 3)"
    )
    parser.add_argument("--scope-file", "-s", required=True, help="Path to scope.json configuration")
    parser.add_argument("--target", "-t", action="append", default=[], help="Declared target (can be repeated)")
    parser.add_argument("--command", "-c", help="Candidate command line to inspect for out-of-scope targets")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args()

    try:
        cfg = load_scope_file(args.scope_file)
    except ScopeError as err:
        if args.json:
            print(json.dumps({
                "timestamp": get_utc_timestamp(),
                "error": str(err),
                "status": "CONFIG_ERROR"
            }, indent=2))
        else:
            print(f"[ERROR] Scope configuration error: {err}", file=sys.stderr)
        sys.exit(2)

    decision = evaluate_scope(cfg, args.target, args.command)

    out_obj = {
        "timestamp": get_utc_timestamp(),
        "enforced": decision.enforced,
        "allowed": decision.allowed,
        "violations": decision.violations,
        "evaluated_targets": decision.evaluated_targets
    }

    if args.json:
        print(json.dumps(out_obj, indent=2))
    else:
        if decision.allowed:
            print("[SCOPE PASS] Target evaluation allowed.")
        else:
            print(f"[SCOPE DENY] Target evaluation blocked. Violations: {len(decision.violations)}")
            for v in decision.violations:
                print(f"  - {v.get('rule')}: {v}")

    sys.exit(0 if decision.allowed else 1)


if __name__ == "__main__":
    main()
