"""
DRISHTI — Asset Fingerprint Normalization Service
Parses observed technologies and banners into normalized asset fingerprints,
extracting vendor, product, version, and generating CPE 2.3 strings only when
supported by concrete evidence.
"""

import re
from typing import Any, Dict, List, Optional
from backend.services.nvd_models import AssetFingerprint

# Common product patterns: (regex, vendor, product, default_part)
KNOWN_TECHNOLOGIES = [
    (r"openvpn\s*([0-9\.]+)?", "openvpn", "openvpn", "a"),
    (r"nginx\s*([0-9\.]+)?", "nginx", "nginx", "a"),
    (r"apache\s*hugegraph\s*([0-9\.]+)?", "apache", "hugegraph", "a"),
    (r"hugegraph\s*([0-9\.]+)?", "apache", "hugegraph", "a"),
    (r"apache(?:/|\s+)([0-9\.]+)", "apache", "http_server", "a"),
    (r"apache", "apache", "http_server", "a"),
    (r"openssh(?:/|\s+)?([0-9\.p]+)?", "openbsd", "openssh", "a"),
    (r"ssh\s*([0-9\.p]+)?", "openbsd", "openssh", "a"),
    (r"php\s*([0-9\.]+)?", "php", "php", "a"),
    (r"postfix\s*([0-9\.]+)?", "postfix", "postfix", "a"),
    (r"dovecot\s*([0-9\.]+)?", "dovecot", "dovecot", "a"),
    (r"node\.?js\s*([0-9\.]+)?", "nodejs", "node.js", "a"),
    (r"next\.?js\s*([0-9\.]+)?", "vercel", "next.js", "a"),
    (r"windows\s*server\s*(2022|2025|2019)?", "microsoft", "windows_server", "o"),
    (r"cloudflare", "cloudflare", "cloudflare", "a"),
    (r"aws\s*s3", "amazon", "simple_storage_service", "a"),
    (r"openssl\s*([0-9\.[a-z]]+)?", "openssl", "openssl", "a"),
    (r"oauth2?", "ietf", "oauth_2.0", "a"),
]


def normalize_tech_banner(
    host: str,
    ip: str,
    port: Optional[int],
    tech_str: str,
    scan_id: Optional[str] = None,
    source: str = "banner"
) -> List[AssetFingerprint]:
    """
    Parses a technology banner string (e.g. 'OpenVPN 2.5, OpenSSL')
    into individual normalized AssetFingerprint objects.
    """
    if not tech_str:
        return []

    fingerprints: List[AssetFingerprint] = []
    asset_id = f"{host}:{port}" if port else host

    # Split by comma or semicolon
    raw_segments = [s.strip() for s in re.split(r"[,;]+", tech_str) if s.strip()]

    for seg in raw_segments:
        matched = False
        for pattern, vendor, product, part in KNOWN_TECHNOLOGIES:
            m = re.search(pattern, seg, re.IGNORECASE)
            if m:
                matched = True
                ver = None
                # Check if version group was captured and non-empty
                if m.groups() and m.group(1):
                    ver = m.group(1).strip()

                # Determine CPE: ONLY create if justified by vendor & product
                cpe_ver = ver if ver else "*"
                cpe23 = f"cpe:2.3:{part}:{vendor}:{product}:{cpe_ver}:*:*:*:*:*:*:*"

                # Infer OS metadata if known
                os_meta = None
                if part == "o":
                    os_meta = product
                elif "windows" in seg.lower():
                    os_meta = "Windows"
                elif "linux" in seg.lower() or "ubuntu" in seg.lower() or "debian" in seg.lower():
                    os_meta = "Linux"

                fp = AssetFingerprint(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    host=host,
                    port=port,
                    vendor=vendor,
                    product=product,
                    version=ver,
                    version_scheme="semver",
                    cpe23=cpe23,
                    os_metadata=os_meta,
                    service_metadata=seg,
                    fingerprint_source=source,
                    is_inferred=False if ver else True,
                    confidence=0.95 if ver else 0.70
                )
                fingerprints.append(fp)
                break

        # Fallback generic tokenization if segment didn't match known technologies
        if not matched:
            tokens = seg.split()
            prod_name = tokens[0].lower() if tokens else "unknown"
            ver_candidate = None
            if len(tokens) > 1 and re.match(r"^[0-9]+(\.[0-9]+)*", tokens[1]):
                ver_candidate = tokens[1]

            fp = AssetFingerprint(
                scan_id=scan_id,
                asset_id=asset_id,
                host=host,
                port=port,
                vendor=prod_name,
                product=prod_name,
                version=ver_candidate,
                version_scheme="semver",
                cpe23=f"cpe:2.3:a:{prod_name}:{prod_name}:{ver_candidate or '*'}:*:*:*:*:*:*:*",
                fingerprint_source=source,
                is_inferred=True,
                confidence=0.50
            )
            fingerprints.append(fp)

    return fingerprints
