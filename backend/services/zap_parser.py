"""
DRISHTI — Phase 8 OWASP ZAP Alert Parser
Parses ZAP alert records defensively, sanitizes sensitive evidence,
normalizes risk & confidence ratings, and enforces scope boundaries.
"""

import html
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from backend.services.scanner_foundation import ZapAlertObservation
from backend.services.scope import is_in_scope, normalize_domain

logger = logging.getLogger("drishti.zap_parser")

MAX_EVIDENCE_LENGTH = 1000
MAX_DESCRIPTION_LENGTH = 2000
MAX_SOLUTION_LENGTH = 2000

RISK_MAPPING = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

CONFIDENCE_MAPPING = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "User Confirmed",
    "falsepositive": "False Positive",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "confirmed": "User Confirmed",
    "user confirmed": "User Confirmed",
}


def sanitize_evidence(raw_text: Optional[str]) -> str:
    """
    Sanitizes alert evidence strings:
    - Bounded length to prevent DoS via massive payloads.
    - Masks potential bearer tokens, passwords, and sensitive session cookies.
    """
    if not raw_text:
        return ""

    text = str(raw_text).strip()
    if len(text) > MAX_EVIDENCE_LENGTH:
        text = text[:MAX_EVIDENCE_LENGTH] + "... [TRUNCATED_BY_DRISHTI]"

    # Mask known sensitive patterns
    import re
    text = re.sub(r'(bearer\s+)[a-zA-Z0-9_\-\.]{15,}', r'\1[REDACTED_TOKEN]', text, flags=re.IGNORECASE)
    text = re.sub(r'(password\s*[:=]\s*)[^\s&,;]{3,}', r'\1[REDACTED_PASSWORD]', text, flags=re.IGNORECASE)
    text = re.sub(r'(sessionid\s*[:=]\s*)[^\s&,;]{6,}', r'\1[REDACTED_SESSION]', text, flags=re.IGNORECASE)

    return text


def parse_zap_alerts(
    raw_alerts: Any,
    authorized_domain: Optional[str] = None
) -> List[ZapAlertObservation]:
    """
    Defensively parses raw ZAP alerts (from JSON API list or report structures).
    Filters out any alerts associated with URLs outside the authorized scope.
    """
    if not raw_alerts:
        return []

    # If raw_alerts is a dict containing {"alerts": [...]}, extract list
    alert_list = raw_alerts
    if isinstance(raw_alerts, dict):
        alert_list = raw_alerts.get("alerts", [])

    if not isinstance(alert_list, list):
        logger.warning("ZAP parser received non-list alerts payload")
        return []

    parsed_observations: List[ZapAlertObservation] = []

    for item in alert_list:
        if not isinstance(item, dict):
            continue

        raw_url = item.get("url") or item.get("uri") or ""
        if not raw_url:
            continue

        # Extract hostname and port
        try:
            parsed_u = urlparse(raw_url)
            host = parsed_u.hostname or ""
            port = parsed_u.port or (443 if parsed_u.scheme == "https" else 80)
        except Exception:
            continue

        if not host:
            continue

        # Enforce Scope Verification: ignore any alert on an out-of-scope host
        if authorized_domain and not is_in_scope(host, authorized_domain):
            logger.info("Dropping ZAP alert on out-of-scope host: %s (auth: %s)", host, authorized_domain)
            continue

        plugin_id = str(item.get("pluginId") or item.get("id") or "0")
        alert_name = str(item.get("alert") or item.get("name") or "Unnamed ZAP Finding").strip()

        raw_risk = str(item.get("risk") or item.get("riskcode") or "Informational").lower().strip()
        risk = RISK_MAPPING.get(raw_risk, "Informational")

        raw_conf = str(item.get("confidence") or item.get("confidencecode") or "Medium").lower().strip()
        confidence = CONFIDENCE_MAPPING.get(raw_conf, "Medium")

        param = str(item.get("param") or "")[:255]
        attack = str(item.get("attack") or "")[:500]
        evidence = sanitize_evidence(item.get("evidence"))
        description = str(item.get("description") or "")[:MAX_DESCRIPTION_LENGTH]
        solution = str(item.get("solution") or "")[:MAX_SOLUTION_LENGTH]
        reference = str(item.get("reference") or "")[:1000]

        # Defensive integer conversion for CWE / WASC
        cwe_id = None
        raw_cwe = item.get("cweid") or item.get("cwe_id")
        if raw_cwe is not None:
            try:
                cwe_val = int(raw_cwe)
                if cwe_val > 0:
                    cwe_id = cwe_val
            except (ValueError, TypeError):
                cwe_id = None

        wasc_id = None
        raw_wasc = item.get("wascid") or item.get("wasc_id")
        if raw_wasc is not None:
            try:
                wasc_val = int(raw_wasc)
                if wasc_val > 0:
                    wasc_id = wasc_val
            except (ValueError, TypeError):
                wasc_id = None

        # Determine verification status:
        # High confidence alerts with concrete evidence are marked "corroborated"; others are "unverified_finding"
        verification_status = "corroborated" if (confidence in ("High", "User Confirmed") and evidence) else "unverified_finding"

        obs = ZapAlertObservation(
            plugin_id=plugin_id,
            alert_name=alert_name,
            risk=risk,
            confidence=confidence,
            url=raw_url,
            host=host,
            port=port,
            param=param,
            attack=attack,
            evidence=evidence,
            description=description,
            solution=solution,
            reference=reference,
            cwe_id=cwe_id,
            wasc_id=wasc_id,
            source_scanner="OWASP ZAP",
            verification_status=verification_status,
        )
        parsed_observations.append(obs)

    return parsed_observations
