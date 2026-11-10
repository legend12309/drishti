"""
DRISHTI — Evidence-Based CVE Applicability Matching Engine
Implements deterministic matching against NVD affected-product CPE criteria,
version range boundaries (inclusive/exclusive), AND/OR configuration logic,
and conservative evidence handling.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from backend.services.nvd_models import (
    ApplicabilityStatus,
    AssetFingerprint,
    ConfigurationNode,
    CpeMatchCriteria,
    VulnerabilityFinding,
    VulnerabilityRecord,
)


def parse_version(v_str: str) -> List[Tuple[int, Any]]:
    """
    Parses a version string into a comparable sequence of tokens.
    Numeric segments are tagged 0 (compared numerically).
    Alphabetic segments are tagged 1 (compared lexicographically).
    e.g. '8.5p1' -> [(0, 8), (0, 5), (1, 'p'), (0, 1)]
    """
    if not v_str:
        return []

    # Clean leading v or release markers
    clean = v_str.strip().lstrip("vV")
    # Tokenize numbers and letter segments
    raw_tokens = re.findall(r"(\d+|[a-zA-Z]+)", clean)
    parsed = []
    for t in raw_tokens:
        if t.isdigit():
            parsed.append((0, int(t)))
        else:
            parsed.append((1, t.lower()))

    # Strip trailing zeroes for semantic equivalence (e.g. 2.5 == 2.5.0)
    while len(parsed) > 1 and parsed[-1] == (0, 0):
        parsed.pop()

    return parsed


def compare_versions(v1_str: str, v2_str: str) -> int:
    """
    Compares two version strings.
    Returns:
       -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    t1 = parse_version(v1_str)
    t2 = parse_version(v2_str)

    # Pad length with zeroes if one is shorter
    max_len = max(len(t1), len(t2))
    for i in range(max_len):
        seg1 = t1[i] if i < len(t1) else (0, 0)
        seg2 = t2[i] if i < len(t2) else (0, 0)

        # If types match (both numeric or both text)
        if seg1[0] == seg2[0]:
            if seg1[1] < seg2[1]:
                return -1
            elif seg1[1] > seg2[1]:
                return 1
        else:
            # Numeric takes precedence over text
            return -1 if seg1[0] > seg2[0] else 1

    return 0


def parse_cpe23(cpe: str) -> Dict[str, str]:
    """Parses a CPE 2.3 string into components."""
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return {}
    return {
        "part": parts[2],
        "vendor": parts[3].lower(),
        "product": parts[4].lower(),
        "version": parts[5] if len(parts) > 5 else "*",
        "update": parts[6] if len(parts) > 6 else "*",
    }


def is_cpe_product_match(criteria_cpe: str, fingerprint: AssetFingerprint) -> bool:
    """Checks whether criteria CPE matches asset vendor and product."""
    c_parts = parse_cpe23(criteria_cpe)
    if not c_parts:
        return False

    fp_vendor = fingerprint.vendor.lower().replace(" ", "_")
    fp_product = fingerprint.product.lower().replace(" ", "_")

    c_vendor = c_parts["vendor"]
    c_product = c_parts["product"]

    # Normalize common vendor aliases (e.g. openvpn/openvpn_technologies, f5/nginx)
    vendor_aliases = {
        "nginx": ["nginx", "f5"],
        "f5": ["nginx", "f5"],
        "openvpn": ["openvpn", "openvpn_technologies"],
        "microsoft": ["microsoft"],
        "apache": ["apache", "apache_software_foundation"],
    }

    vendor_match = (
        c_vendor == "*"
        or c_vendor == fp_vendor
        or (fp_vendor in vendor_aliases and c_vendor in vendor_aliases[fp_vendor])
    )
    product_match = (
        c_product == "*"
        or c_product == fp_product
        or fp_product in c_product
        or c_product in fp_product
    )

    return vendor_match and product_match


def check_version_in_criteria(
    version: str,
    criteria: CpeMatchCriteria
) -> Tuple[bool, str]:
    """
    Evaluates whether a version satisfies the version boundaries of a CpeMatchCriteria.
    Returns (is_in_range, reason).
    """
    # 1. Exact version in CPE string if not wildcard
    c_parts = parse_cpe23(criteria.criteria)
    c_version = c_parts.get("version", "*")
    if c_version not in ("*", "-"):
        cmp = compare_versions(version, c_version)
        if cmp == 0:
            return True, f"Exact version match with CPE version '{c_version}'"
        else:
            return False, f"Version '{version}' does not match required CPE version '{c_version}'"

    # 2. Check versionStartIncluding
    if criteria.versionStartIncluding:
        if compare_versions(version, criteria.versionStartIncluding) < 0:
            return False, f"Version '{version}' is below versionStartIncluding '{criteria.versionStartIncluding}'"

    # 3. Check versionStartExcluding
    if criteria.versionStartExcluding:
        if compare_versions(version, criteria.versionStartExcluding) <= 0:
            return False, f"Version '{version}' is not greater than versionStartExcluding '{criteria.versionStartExcluding}'"

    # 4. Check versionEndIncluding
    if criteria.versionEndIncluding:
        if compare_versions(version, criteria.versionEndIncluding) > 0:
            return False, f"Version '{version}' exceeds versionEndIncluding '{criteria.versionEndIncluding}'"

    # 5. Check versionEndExcluding
    if criteria.versionEndExcluding:
        if compare_versions(version, criteria.versionEndExcluding) >= 0:
            return False, f"Version '{version}' is not strictly less than versionEndExcluding '{criteria.versionEndExcluding}'"

    # Build description of satisfied range
    range_desc = []
    if criteria.versionStartIncluding:
        range_desc.append(f">= {criteria.versionStartIncluding}")
    elif criteria.versionStartExcluding:
        range_desc.append(f"> {criteria.versionStartExcluding}")
    if criteria.versionEndIncluding:
        range_desc.append(f"<= {criteria.versionEndIncluding}")
    elif criteria.versionEndExcluding:
        range_desc.append(f"< {criteria.versionEndExcluding}")

    range_str = ", ".join(range_desc) if range_desc else "all versions (*)"
    return True, f"Version '{version}' satisfies boundary criteria [{range_str}]"


def evaluate_cve_applicability(
    cve: VulnerabilityRecord,
    fingerprint: AssetFingerprint
) -> VulnerabilityFinding:
    """
    Evaluates applicability of a CVE against an asset fingerprint.
    Applies strict evidence policies:
    - confirmed_applicability: Version is confirmed and falls inside vulnerable boundary (and platform matches if required).
    - potential_applicability: Product matches and port/service matches, but version or OS requirement is unconfirmed.
    - insufficient_evidence: Product matches but no version was observed and range cannot be verified.
    - not_affected: Product does not match, or version is confirmed outside vulnerable range.
    """
    if not cve.configurations:
        return VulnerabilityFinding(
            scan_id=fingerprint.scan_id or "",
            asset_id=fingerprint.asset_id,
            cve_id=cve.cve_id,
            fingerprint_id=fingerprint.id,
            applicability_status=ApplicabilityStatus.INSUFFICIENT_EVIDENCE,
            confidence_score=0.2,
            match_rationale=f"CVE {cve.cve_id} has no structured NVD configuration criteria available."
        )

    matched_nodes = []
    product_matched_any = False
    inconclusive_reasons = []

    for node in cve.configurations:
        # Separate software criteria from OS/platform criteria in AND nodes
        vulnerable_criteria = [cm for cm in node.cpeMatch if cm.vulnerable]
        platform_criteria = [cm for cm in node.cpeMatch if not cm.vulnerable]

        if not vulnerable_criteria:
            continue

        for crit in vulnerable_criteria:
            if not is_cpe_product_match(crit.criteria, fingerprint):
                continue

            product_matched_any = True

            # If version is unknown / not observed:
            if not fingerprint.version:
                inconclusive_reasons.append(
                    f"Product '{fingerprint.product}' matches {crit.criteria}, but software version is unobserved."
                )
                continue

            in_range, range_reason = check_version_in_criteria(fingerprint.version, crit)
            if not in_range:
                continue

            # Software matches vulnerable version! Now check platform requirements if node.operator == 'AND'
            if node.operator == "AND" and platform_criteria:
                os_matched = False
                os_unobserved = True
                os_conflict = False

                for plat in platform_criteria:
                    p_parts = parse_cpe23(plat.criteria)
                    req_os = p_parts.get("product", "*")
                    if fingerprint.os_metadata:
                        os_unobserved = False
                        if req_os.lower() in fingerprint.os_metadata.lower() or fingerprint.os_metadata.lower() in req_os.lower():
                            os_matched = True
                        else:
                            os_conflict = True

                if os_conflict and not os_matched:
                    # Contradicting OS observed
                    continue
                elif os_unobserved:
                    # Platform requirement cannot be validated from passive observations
                    return VulnerabilityFinding(
                        scan_id=fingerprint.scan_id or "",
                        asset_id=fingerprint.asset_id,
                        cve_id=cve.cve_id,
                        fingerprint_id=fingerprint.id,
                        applicability_status=ApplicabilityStatus.POTENTIAL,
                        confidence_score=0.75,
                        match_rationale=(
                            f"Software {fingerprint.product} {fingerprint.version} matches vulnerable range, "
                            f"but required platform '{platform_criteria[0].criteria}' could not be verified from passive observations."
                        ),
                        cve_title=cve.title,
                        cve_description=cve.description,
                        cvss_score=cve.cvss_score,
                        cvss_severity=cve.cvss_severity,
                        cvss_vector=cve.cvss_vector,
                        epss_score=cve.epss_score,
                        remediation_notes=cve.remediation_notes,
                        affected_product=f"{fingerprint.vendor} {fingerprint.product}",
                        observed_version=fingerprint.version
                    )

            # Distinguish between actively confirmed scanner observations vs passive correlations
            is_active_verified = (fingerprint.fingerprint_source or "").lower() in (
                "nuclei", "zap_active", "active_probe", "verified_scan", "active_exploit", "banner"
            )

            status = ApplicabilityStatus.CONFIRMED if is_active_verified else ApplicabilityStatus.POTENTIAL
            confidence = (0.98 if not fingerprint.is_inferred else 0.85) if is_active_verified else 0.70

            if is_active_verified:
                rationale = (
                    f"Confirmed applicability: {fingerprint.vendor} {fingerprint.product} version {fingerprint.version} "
                    f"satisfies criteria for {cve.cve_id} ({range_reason}). Source: {fingerprint.fingerprint_source}."
                )
            else:
                rationale = (
                    f"CORRELATED (PASSIVE ONLY): {fingerprint.vendor} {fingerprint.product} version {fingerprint.version} "
                    f"satisfies criteria for {cve.cve_id} ({range_reason}). Source: {fingerprint.fingerprint_source}. "
                    f"Preserved in Passive Correlation pending active vulnerability scan verification."
                )

            return VulnerabilityFinding(
                scan_id=fingerprint.scan_id or "",
                asset_id=fingerprint.asset_id,
                cve_id=cve.cve_id,
                fingerprint_id=fingerprint.id,
                applicability_status=status,
                confidence_score=confidence,
                match_rationale=rationale,
                cve_title=cve.title,
                cve_description=cve.description,
                cvss_score=cve.cvss_score,
                cvss_severity=cve.cvss_severity,
                cvss_vector=cve.cvss_vector,
                epss_score=cve.epss_score,
                remediation_notes=cve.remediation_notes,
                affected_product=f"{fingerprint.vendor} {fingerprint.product}",
                observed_version=fingerprint.version
            )

    # If product matched but version was unknown
    if inconclusive_reasons:
        return VulnerabilityFinding(
            scan_id=fingerprint.scan_id or "",
            asset_id=fingerprint.asset_id,
            cve_id=cve.cve_id,
            fingerprint_id=fingerprint.id,
            applicability_status=ApplicabilityStatus.INSUFFICIENT_EVIDENCE,
            confidence_score=0.40,
            match_rationale="; ".join(inconclusive_reasons) + " Marked as insufficient_evidence to prevent false positives.",
            cve_title=cve.title,
            cve_description=cve.description,
            cvss_score=cve.cvss_score,
            cvss_severity=cve.cvss_severity,
            cvss_vector=cve.cvss_vector,
            epss_score=cve.epss_score,
            remediation_notes=cve.remediation_notes,
            affected_product=f"{fingerprint.vendor} {fingerprint.product}",
            observed_version=None
        )

    # If product was not matched or version is outside all vulnerable boundaries
    status = ApplicabilityStatus.NOT_AFFECTED
    rationale = (
        f"Asset software {fingerprint.product} {fingerprint.version or '(unspecified)'} is outside the vulnerable criteria for {cve.cve_id}."
        if product_matched_any else
        f"Asset fingerprint '{fingerprint.vendor} {fingerprint.product}' does not match affected product criteria for {cve.cve_id}."
    )
    return VulnerabilityFinding(
        scan_id=fingerprint.scan_id or "",
        asset_id=fingerprint.asset_id,
        cve_id=cve.cve_id,
        fingerprint_id=fingerprint.id,
        applicability_status=status,
        confidence_score=0.95,
        match_rationale=rationale,
        cve_title=cve.title,
        cve_description=cve.description,
        cvss_score=cve.cvss_score,
        cvss_severity=cve.cvss_severity,
        cvss_vector=cve.cvss_vector,
        epss_score=cve.epss_score,
        remediation_notes=cve.remediation_notes,
        affected_product=f"{fingerprint.vendor} {fingerprint.product}",
        observed_version=fingerprint.version
    )
