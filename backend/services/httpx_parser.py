"""
DRISHTI — Phase 7 ProjectDiscovery httpx JSONL Parser (Security Hardened)
Parses structured JSON Lines output (-json -silent) emitted by ProjectDiscovery's httpx.

Security Requirements:
- Treats all scanner records as untrusted input.
- Parses records incrementally line by line (never loads unbounded blobs in memory).
- Rejects oversized outputs (> 15 MB) and excessively long lines (> 64 KB).
- Validates redirect destinations to prevent out-of-scope domain hopping.
- Preserves the distinction between observed facts and unconfirmed technologies.
"""

from datetime import datetime, timezone
import json
import logging
from typing import List, Optional
from urllib.parse import urlparse

from backend.services.scanner_foundation import HttpServiceObservation
from backend.services.scope import is_in_scope, normalize_domain

logger = logging.getLogger("drishti.httpx_parser")

MAX_TOTAL_BYTES = 15 * 1024 * 1024  # 15 MB
MAX_LINE_BYTES = 64 * 1024          # 64 KB per JSON record


class HttpxJSONLParsingError(Exception):
    """Raised when httpx JSONL output exceeds safety bounds or is corrupt."""
    pass


def parse_httpx_jsonl(
    jsonl_content: str,
    authorized_domain: Optional[str] = None
) -> List[HttpServiceObservation]:
    """
    Safely parses JSON Lines string emitted by ProjectDiscovery httpx into normalized
    HttpServiceObservation instances.
    """
    if not jsonl_content or not jsonl_content.strip():
        return []

    # Enforce total payload size boundary
    if len(jsonl_content.encode("utf-8")) > MAX_TOTAL_BYTES:
        raise HttpxJSONLParsingError(
            f"httpx JSONL output exceeds safety ceiling of {MAX_TOTAL_BYTES} bytes."
        )

    observations: List[HttpServiceObservation] = []
    lines = jsonl_content.strip().splitlines()

    for idx, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            logger.warning("Skipping oversized JSON line (%d bytes) at line %d", len(line), idx)
            continue

        try:
            record = json.loads(line)
        except json.JSONDecodeError as err:
            logger.warning("Failed to decode JSONL record at line %d: %s", idx, err)
            continue

        if not isinstance(record, dict):
            continue

        # Extract normalized fields
        raw_url = record.get("url") or record.get("input")
        if not raw_url:
            continue

        parsed = urlparse(raw_url)
        host = record.get("host") or parsed.hostname or ""
        scheme = record.get("scheme") or parsed.scheme or "http"
        port = record.get("port")
        if port is None:
            port = parsed.port or (443 if scheme == "https" else 80)
        else:
            try:
                port = int(port)
            except ValueError:
                port = 443 if scheme == "https" else 80

        # Scope validation on redirect destinations if present
        final_url = record.get("final_url")
        if final_url and authorized_domain:
            final_parsed = urlparse(final_url)
            final_host = final_parsed.hostname or ""
            if not is_in_scope(final_host, authorized_domain):
                # Detected out-of-scope redirect - nullify final_url to prevent unauthorized domain expansion
                logger.warning(
                    "Out-of-scope redirect detected: %s -> %s (outside %s). Stripped.",
                    raw_url, final_url, authorized_domain
                )
                final_url = None

        # Clean technologies list
        tech_raw = record.get("tech") or record.get("technologies") or []
        technologies = []
        if isinstance(tech_raw, list):
            for t in tech_raw:
                if isinstance(t, str) and t.strip():
                    technologies.append(t.strip())
        elif isinstance(tech_raw, str) and tech_raw.strip():
            technologies = [t.strip() for t in tech_raw.split(",") if t.strip()]

        status_code = record.get("status_code") or record.get("status-code")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except ValueError:
                status_code = None

        content_length = record.get("content_length") or record.get("content-length")
        if content_length is not None:
            try:
                content_length = int(content_length)
            except ValueError:
                content_length = None

        resp_time = record.get("response_time") or record.get("time")
        response_time_ms = None
        if resp_time is not None:
            try:
                if isinstance(resp_time, str) and resp_time.endswith("ms"):
                    response_time_ms = float(resp_time[:-2])
                elif isinstance(resp_time, str) and resp_time.endswith("s"):
                    response_time_ms = float(resp_time[:-1]) * 1000.0
                else:
                    response_time_ms = float(resp_time)
            except ValueError:
                pass

        obs = HttpServiceObservation(
            url=raw_url,
            host=host,
            port=port,
            scheme=scheme,
            status_code=status_code,
            title=record.get("title"),
            webserver=record.get("webserver") or record.get("server"),
            content_type=record.get("content_type") or record.get("content-type"),
            content_length=content_length,
            technologies=technologies,
            final_url=final_url,
            ip=record.get("ip") or (record.get("a") and record["a"][0] if isinstance(record.get("a"), list) else None),
            cname=record.get("cname") and record["cname"][0] if isinstance(record.get("cname"), list) else record.get("cname"),
            response_time_ms=response_time_ms,
            observed_at=datetime.now(timezone.utc),
        )
        observations.append(obs)

    return observations
