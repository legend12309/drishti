"""
DRISHTI — Phase 9 Aqua Security Trivy Structured Output Parser
Defensively parses Trivy JSON output structures across:
  1. Dependencies & Package Vulnerabilities (`Results[].Vulnerabilities[]`)
  2. Configuration Misconfigurations (`Results[].Misconfigurations[]`)
  3. Secret Findings with strict redaction (`Results[].Secrets[]`)

Safety Rules:
- Never log or store plaintext secret values.
- Truncate oversized descriptions, remediation text, and code snippets.
- Normalize severity levels to DRISHTI standard uppercase values.
- Handle missing and malformed JSON structures gracefully.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from backend.services.scanner_foundation import TrivyFindingObservation

logger = logging.getLogger("drishti.trivy_parser")

MAX_DESC_LENGTH = 1500
MAX_REMEDIATION_LENGTH = 1000
MAX_EVIDENCE_LENGTH = 800

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "UNKNOWN",
}


def sanitize_snippet(snippet: Optional[str]) -> str:
    """Masks potential credentials, tokens, or private keys in code snippets."""
    if not snippet:
        return ""
    text = str(snippet).strip()
    if len(text) > MAX_EVIDENCE_LENGTH:
        text = text[:MAX_EVIDENCE_LENGTH] + "... [TRUNCATED_BY_DRISHTI]"

    text = re.sub(r'(bearer\s+)[a-zA-Z0-9_\-\.]{15,}', r'\1[REDACTED_TOKEN]', text, flags=re.IGNORECASE)
    text = re.sub(r'(password\s*[:=]\s*)[^\s&,;]{3,}', r'\1[REDACTED_PASSWORD]', text, flags=re.IGNORECASE)
    text = re.sub(r'(api[_\-]?key\s*[:=]\s*)[^\s&,;]{6,}', r'\1[REDACTED_KEY]', text, flags=re.IGNORECASE)
    text = re.sub(r'(secret[_\-]?access[_\-]?key\s*[:=]\s*)[^\s&,;]{6,}', r'\1[REDACTED_SECRET]', text, flags=re.IGNORECASE)
    text = re.sub(r'(secret\s*[:=]\s*)[^\s&,;]{6,}', r'\1[REDACTED_SECRET]', text, flags=re.IGNORECASE)
    return text


def parse_trivy_json(raw_json: Any, scanner_version: str = "unknown") -> List[TrivyFindingObservation]:
    """
    Parses Trivy JSON output payload into a normalized list of TrivyFindingObservation objects.
    """
    if not raw_json:
        return []

    data = raw_json
    if isinstance(raw_json, str):
        try:
            data = json.loads(raw_json)
        except Exception as ex:
            logger.warning("Failed to parse Trivy output as JSON: %s", ex)
            return []

    if not isinstance(data, dict):
        logger.warning("Trivy output JSON root must be a dict.")
        return []

    results = data.get("Results")
    if not results or not isinstance(results, list):
        return []

    findings: List[TrivyFindingObservation] = []
    seen_dedup = set()

    for res in results:
        if not isinstance(res, dict):
            continue

        target_file = str(res.get("Target") or "unknown_target").strip()

        # 1. Package & Dependency Vulnerabilities
        vulns = res.get("Vulnerabilities", [])
        if isinstance(vulns, list):
            for v in vulns:
                if not isinstance(v, dict):
                    continue

                v_id = str(v.get("VulnerabilityID") or "UNKNOWN_VULN").strip()
                pkg_name = str(v.get("PkgName") or "").strip()
                inst_ver = str(v.get("InstalledVersion") or "").strip()
                fix_ver = str(v.get("FixedVersion") or "").strip()
                raw_sev = str(v.get("Severity") or "UNKNOWN").upper().strip()
                severity = SEVERITY_MAP.get(raw_sev, "UNKNOWN")
                title = str(v.get("Title") or f"Vulnerability {v_id} in {pkg_name}").strip()
                primary_url = str(v.get("PrimaryURL") or "")

                dedup_key = ("vuln", target_file, v_id, pkg_name, inst_ver)
                if dedup_key in seen_dedup:
                    continue
                seen_dedup.add(dedup_key)

                desc = str(v.get("Description") or "")[:MAX_DESC_LENGTH]
                remediation = f"Upgrade {pkg_name} to version {fix_ver}" if fix_ver else "No direct fix version reported."

                findings.append(
                    TrivyFindingObservation(
                        target_resource=target_file,
                        finding_class="vulnerability",
                        vulnerability_id=v_id,
                        title=title,
                        severity=severity,
                        package_name=pkg_name,
                        installed_version=inst_ver,
                        fixed_version=fix_ver or None,
                        primary_url=primary_url or None,
                        description=desc,
                        remediation_guidance=remediation,
                        confidence="HIGH",
                        scanner_name="Aqua Security Trivy",
                        scanner_version=scanner_version,
                    )
                )

        # 2. Configuration Misconfigurations
        misconfs = res.get("Misconfigurations", [])
        if isinstance(misconfs, list):
            for m in misconfs:
                if not isinstance(m, dict):
                    continue

                rule_id = str(m.get("ID") or m.get("AVDID") or "MISCONF_RULE").strip()
                title = str(m.get("Title") or f"Misconfiguration {rule_id}").strip()
                raw_sev = str(m.get("Severity") or "LOW").upper().strip()
                severity = SEVERITY_MAP.get(raw_sev, "LOW")
                primary_url = str(m.get("PrimaryURL") or "")
                desc = str(m.get("Description") or "")[:MAX_DESC_LENGTH]
                msg = str(m.get("Message") or "")[:MAX_REMEDIATION_LENGTH]
                resolution = str(m.get("Resolution") or msg)[:MAX_REMEDIATION_LENGTH]

                cause_meta = m.get("CauseMetadata", {})
                code_block = cause_meta.get("Code", {}) if isinstance(cause_meta, dict) else {}
                lines = code_block.get("Lines", []) if isinstance(code_block, dict) else []
                start_line = cause_meta.get("StartLine") or code_block.get("StartLine")

                evidence_lines = []
                for ln in lines:
                    if isinstance(ln, dict):
                        evidence_lines.append(f"{ln.get('Number', '')}: {ln.get('Content', '')}")
                evidence = sanitize_snippet("\n".join(evidence_lines))

                dedup_key = ("misconf", target_file, rule_id, start_line)
                if dedup_key in seen_dedup:
                    continue
                seen_dedup.add(dedup_key)

                findings.append(
                    TrivyFindingObservation(
                        target_resource=target_file,
                        finding_class="misconfiguration",
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        primary_url=primary_url or None,
                        description=desc,
                        remediation_guidance=resolution,
                        evidence=evidence or None,
                        line_number=start_line if isinstance(start_line, int) else None,
                        confidence="HIGH",
                        scanner_name="Aqua Security Trivy",
                        scanner_version=scanner_version,
                    )
                )

        # 3. Secret Findings (Defensively masked)
        secrets = res.get("Secrets", [])
        if isinstance(secrets, list):
            for s in secrets:
                if not isinstance(s, dict):
                    continue

                rule_id = str(s.get("RuleID") or "SECRET_DETECTED").strip()
                category = str(s.get("Category") or "Secret").strip()
                title = str(s.get("Title") or f"Hardcoded {category} found ({rule_id})").strip()
                raw_sev = str(s.get("Severity") or "HIGH").upper().strip()
                severity = SEVERITY_MAP.get(raw_sev, "HIGH")
                start_line = s.get("StartLine")

                # Strictly redact secret proof
                code = s.get("Code", {})
                lines = code.get("Lines", []) if isinstance(code, dict) else []
                proof_lines = []
                for ln in lines:
                    if isinstance(ln, dict):
                        proof_lines.append(f"{ln.get('Number', '')}: {ln.get('Content', '')}")
                evidence = sanitize_snippet("\n".join(proof_lines)) or "[REDACTED_SECRET_LINE]"

                dedup_key = ("secret", target_file, rule_id, start_line)
                if dedup_key in seen_dedup:
                    continue
                seen_dedup.add(dedup_key)

                findings.append(
                    TrivyFindingObservation(
                        target_resource=target_file,
                        finding_class="secret",
                        rule_id=rule_id,
                        title=title,
                        severity=severity,
                        description="A potentially sensitive credential or cryptographic token was detected in the source code or manifest.",
                        remediation_guidance="Revoke the exposed credential immediately, replace with an environment variable/secrets manager, and rotate authentication keys.",
                        evidence=evidence,
                        line_number=start_line if isinstance(start_line, int) else None,
                        confidence="HIGH",
                        scanner_name="Aqua Security Trivy",
                        scanner_version=scanner_version,
                    )
                )

    return findings
