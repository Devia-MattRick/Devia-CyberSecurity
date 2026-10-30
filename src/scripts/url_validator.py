#!/usr/bin/env python3
"""Deterministic URL safety, SSRF anti-evasion, and Cloud Metadata validator.

Absorbed and enhanced for Devia-CyberSecurity:
Validates URLs against:
- Non-HTTP(S) schemes
- Embedded credentials (user/password)
- Terminal control and escape sequences
- Private / loopback IP addresses (SSRF prevention)
- Octal and hexadecimal numeric IP evasions (0x7f000001, 0177.0.0.1)
- Encoded delimiters and unparsed netlocs
- Cloud instance metadata services:
  * IPv4 link-local IMDS (169.254.0.0/16, e.g. 169.254.169.254)
  * IPv6 AWS IMDSv6 (fd00:ec2::/64, e.g. fd00:ec2::254)
  * IPv6 Link-Local (fe80::/10)
  * IPv4-mapped IPv6 addresses (::ffff:169.254.169.254, ::ffff:127.0.0.1)
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from typing import Any
from urllib.parse import SplitResult, urlsplit

_TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\x1b]")

# Cloud Metadata and Dangerous Subnets
CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),       # IPv4 Link-Local / Cloud IMDS (AWS/Azure/GCP/Alibaba)
    ipaddress.ip_network("fd00:ec2::/64"),        # AWS IMDSv6 Endpoint
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-Local
]

BLOCKED_LINK_AGGREGATORS = {
    "linktr.ee", "carrd.co", "bio.link", "lnk.bio", "beacons.ai", "taplink.cc"
}


def has_terminal_control(text: str) -> bool:
    """Return True if text contains terminal escape or control sequences."""
    return bool(_TERMINAL_CONTROL_RE.search(text))

def looks_numeric(label: str) -> bool:
    """Check if a domain label represents an octal, decimal or hex integer."""
    lowered = label.lower()
    if lowered.startswith("0x"):
        return len(lowered) > 2 and all(c in "0123456789abcdef" for c in lowered[2:])
    return bool(lowered) and all(c.isdigit() for c in lowered)

def unwrap_ipv4_mapped(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Extract embedded IPv4 from an IPv4-mapped IPv6 address (::ffff:169.254.169.254)."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj

def is_cloud_metadata_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check whether an IP address belongs to known cloud metadata endpoints."""
    effective_ip = unwrap_ipv4_mapped(ip_obj)
    for net in CLOUD_METADATA_NETWORKS:
        if effective_ip.version == net.version and effective_ip in net:
            return True
    return False

def parse_url(value: str) -> SplitResult | None:
    """Strictly parse a URL or return None if invalid."""
    if not isinstance(value, str) or not value or has_terminal_control(value):
        return None
    if "\\" in value or any(c.isspace() for c in value):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (ValueError, TypeError):
        return None

    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or "%" in parsed.netloc
    ):
        return None

    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        return None

    if port is not None and not (1 <= port <= 65535):
        return None

    return parsed

def is_safe_external_url(url: str, *, allow_private: bool = False, block_aggregators: bool = False) -> tuple[bool, str]:
    """Validate whether a URL is a safe external HTTP(S) endpoint.

    Returns (is_safe, reason).
    """
    parsed = parse_url(url)
    if parsed is None:
        return False, "Malformed URL, unsupported scheme, invalid port, or terminal control characters detected"

    hostname = (parsed.hostname or "").lower().rstrip(".")
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        if not allow_private:
            return False, f"Localhost or internal domain '{hostname}' rejected"

    if block_aggregators:
        if hostname in BLOCKED_LINK_AGGREGATORS or any(hostname.endswith("." + agg) for agg in BLOCKED_LINK_AGGREGATORS):
            return False, f"Shared non-corporate link aggregator domain '{hostname}' rejected under sovereign anti-SSRF policy"


    # Check if host is an explicit IP address (IPv4 or IPv6 enclosed in brackets)
    try:
        ip_obj = ipaddress.ip_address(hostname)
        effective_ip = unwrap_ipv4_mapped(ip_obj)

        # Cloud metadata is rejected even in testing mode unless explicitly authorized
        if is_cloud_metadata_ip(effective_ip):
            return False, f"Cloud metadata IP address '{hostname}' (IMDS range) strictly rejected"

        if not allow_private:
            if effective_ip.is_loopback:
                return False, f"Loopback IP address '{hostname}' rejected"
            if effective_ip.is_private:
                return False, f"Private network IP address '{hostname}' rejected"
            if effective_ip.is_link_local:
                return False, f"Link-local IP address '{hostname}' rejected"
            if not effective_ip.is_global:
                return False, f"Non-global IP address '{hostname}' rejected"

        return True, "Valid global IP URL"
    except ValueError:
        pass

    # Check for numeric-looking labels (hex or decimal IP evasion)
    labels = hostname.split(".")
    if len(labels) < 2:
        return False, f"Single-label or non-FQDN host '{hostname}' rejected"

    if all(looks_numeric(label) for label in labels):
        return False, f"All-numeric or hexadecimal IP evasion detected in host '{hostname}'"

    return True, "Valid external domain URL"

def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic URL safety and Cloud Metadata validator")
    parser.add_argument("urls", nargs="+", help="URLs to validate")
    parser.add_argument("--allow-private", action="store_true", help="Allow private/internal IPs (metadata still blocked)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    results = []
    all_safe = True
    for u in args.urls:
        safe, reason = is_safe_external_url(u, allow_private=args.allow_private)
        if not safe:
            all_safe = False
        results.append({
            "url": u,
            "safe": safe,
            "reason": reason
        })

    if args.json:
        print(json.dumps({"allSafe": all_safe, "results": results}, indent=2))
    else:
        for r in results:
            status = "SAFE" if r["safe"] else "UNSAFE"
            print(f"[{status}] {r['url']} - {r['reason']}")

    return 0 if all_safe else 1

if __name__ == "__main__":
    sys.exit(main())
