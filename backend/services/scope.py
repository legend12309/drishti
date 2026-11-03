"""
DRISHTI Centralized Scope & Target Validation Service.
Defends against SSRF, unauthorized targets, domain hopping, public suffix abuse,
and DNS rebinding / scope evasion.
"""

import ipaddress
import os
import re
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

# Standard public suffixes / top-level domains where ownership challenges cannot be granted
PUBLIC_SUFFIXES: Set[str] = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "dev", "app",
    "ai", "tech", "info", "biz", "me", "online", "site", "cloud", "security",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "com.br", "com.cn", "co.in", "net.in", "org.in", "gov.in"
}

# Permitted scopes supported by DRISHTI
PERMITTED_SCOPES = {
    "FULL_ACTIVE": "Complete active assessment (Nmap, HTTPX, ZAP, Trivy, Nuclei)",
    "FULL_PASSIVE": "Complete passive reconnaissance (DNS records, topology, RDAP metadata)",
    "PASSIVE_OSINT": "Instant passive OSINT evaluation without DNS TXT challenge (Cert Transparency, DNS, CVE)",
    "PASSIVE_DNS": "Authoritative DNS record enumeration only (A, AAAA, MX, NS, TXT, CNAME)",
    "PASSIVE_METADATA": "Public registration and RDAP metadata inspection only",
}


def is_scope_authorized(granted_scope: Optional[str], requested_scope: Optional[str]) -> bool:
    """
    Determines whether a granted authorization scope satisfies the requested scanning scope.
    - PASSIVE_OSINT or FULL_PASSIVE CANNOT authorize ACTIVE or FULL_ACTIVE scanning.
    - FULL_ACTIVE satisfies both active and passive scanning scopes.
    """
    if not requested_scope:
        return True
    granted = (granted_scope or "").strip().upper()
    requested = requested_scope.strip().upper()

    if granted == requested:
        return True

    # FULL_ACTIVE grants full authority across active and passive pipelines
    if granted == "FULL_ACTIVE":
        return True

    # Active scanning strictly requires FULL_ACTIVE
    if requested in ("FULL_ACTIVE", "ACTIVE", "ACTIVE_DAG"):
        return False

    # PASSIVE_OSINT only satisfies PASSIVE_OSINT
    if requested == "PASSIVE_OSINT":
        return True

    # FULL_PASSIVE satisfies all passive sub-scopes
    if granted == "FULL_PASSIVE" and requested in ("PASSIVE_OSINT", "PASSIVE_DNS", "PASSIVE_METADATA"):
        return True

    return False

# Tier 1 Pre-Authorized Sandbox Targets (Can run active scans without DNS TXT verification)
DEFAULT_SANDBOX_TARGETS = {
    "scanme.nmap.org",
    "example.com",
    "localhost",
    "127.0.0.1",
}


def get_sandbox_allowlist() -> Set[str]:
    """Retrieves allowed sandbox targets from defaults and optional environment variable."""
    env_extra = os.getenv("SANDBOX_ALLOWLIST", "")
    targets = set(DEFAULT_SANDBOX_TARGETS)
    if env_extra:
        for t in env_extra.split(","):
            cleaned = t.strip().lower()
            if cleaned:
                targets.add(cleaned)
    return targets


def is_sandbox_target(target: str) -> bool:
    """Checks whether target domain or IP is a pre-authorized Tier 1 sandbox target."""
    if not target or not isinstance(target, str):
        return False
    clean = target.strip().lower()
    if clean in ("localhost", "127.0.0.1"):
        return True
    try:
        norm = normalize_domain(clean)
    except ValueError:
        return False
    allowlist = get_sandbox_allowlist()
    for allowed in allowlist:
        if norm == allowed or norm.endswith(f".{allowed}"):
            return True
    return False

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    """
    Normalizes a domain string:
    - Strips whitespace and lowercases
    - Strips URL schemes (http://, https://) if inadvertently supplied
    - Strips port numbers, paths, and query fragments
    - Strips trailing periods
    - Validates RFC domain syntax and lengths
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain target cannot be empty.")

    clean = domain.strip().lower()

    # If full URL supplied, extract hostname
    if "://" in clean:
        parsed = urlparse(clean)
        clean = parsed.hostname or clean
    elif "/" in clean:
        clean = clean.split("/")[0]

    # Strip port if present
    if ":" in clean:
        clean = clean.split(":")[0]

    # Strip trailing dot
    clean = clean.rstrip(".")

    if not clean:
        raise ValueError("Domain target is empty after normalization.")

    if len(clean) > 253:
        raise ValueError(f"Domain name exceeds 253 characters: {clean}")

    if not DOMAIN_REGEX.match(clean):
        raise ValueError(f"Domain name '{clean}' violates standard RFC hostname syntax.")

    # Validate individual labels
    labels = clean.split(".")
    for label in labels:
        if len(label) > 63:
            raise ValueError(f"Domain label '{label}' exceeds 63 characters.")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Domain label '{label}' cannot start or end with a hyphen.")

    return clean


def is_public_suffix(domain: str) -> bool:
    """Checks whether the domain is an apex TLD or public suffix."""
    normalized = domain.strip().lower().rstrip(".")
    return normalized in PUBLIC_SUFFIXES


def is_in_scope(target: str, authorized_domain: str) -> bool:
    """
    Strict boundary check:
    Target must match authorized_domain exactly OR be a proper subdomain of it.
    Prevents domain hopping, e.g. evil-target.com matching target.com.
    """
    try:
        norm_target = normalize_domain(target)
        norm_auth = normalize_domain(authorized_domain)
    except ValueError:
        return False

    if norm_target == norm_auth:
        return True

    # Proper subdomain check: target must end with '.<authorized_domain>'
    if norm_target.endswith(f".{norm_auth}"):
        return True

    return False


def is_lab_target_permitted() -> bool:
    """Checks if isolated lab testing override is active."""
    return os.getenv("DRISHTI_ALLOW_PRIVATE_LAB_TARGETS", "0").lower() in ("1", "true", "yes")


def validate_destination_ip(ip_str: str, allow_lab: Optional[bool] = None) -> Tuple[bool, Optional[str]]:
    """
    Validates destination IP to prevent SSRF and internal network scanning:
    - Blocks Loopback (127.0.0.0/8, ::1)
    - Blocks Link-Local (169.254.0.0/16, fe80::/10)
    - Blocks Private RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Blocks Multicast (224.0.0.0/4, ff00::/8)
    - Blocks Unspecified / Reserved (0.0.0.0/8, ::)
    """
    allow = allow_lab if allow_lab is not None else is_lab_target_permitted()

    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    if ip.is_loopback:
        if allow:
            return True, None
        return False, f"Destination IP {ip_str} is a loopback address (SSRF protection)."

    if ip.is_link_local:
        return False, f"Destination IP {ip_str} is a link-local address."

    if ip.is_private:
        if allow:
            return True, None
        return False, f"Destination IP {ip_str} is in a private network range (RFC1918)."

    if ip.is_multicast:
        return False, f"Destination IP {ip_str} is a multicast address."

    if ip.is_reserved or ip.is_unspecified:
        return False, f"Destination IP {ip_str} is a reserved/unspecified address."

    return True, None
