---
name: reverse-skill
description: Cybersecurity, vulnerability analysis, and ASM intelligence router. Integrates native pure-Python reconnaissance, NVD 2.0 CVE correlation, Metasploit weaponization tags, Dijkstra attack graphing, and autonomous defense hotfixing.
---

# Cybersecurity & ASM Intelligence Router

This skill routes cybersecurity, vulnerability analysis, and attack surface defense tasks to DRISHTI's native asynchronous services and global security skills.

## Core Capabilities & Services

| Capability | Implementing Engine | Description |
| :--- | :--- | :--- |
| **CVE Correlation** | `backend/services/vulnerability_service.py` | Official NVD 2.0 API ingestion, CPE 2.3 matching, and EPSS scoring |
| **Metasploit Intel** | `backend/services/vulnerability_service.py` | Known exploit module tagging and CISA KEV weaponization alerts |
| **Attack Graph** | `backend/services/risk_engine.py` | NetworkX Dijkstra pathfinding with 0.40x lateral friction on weaponized nodes |
| **Autonomous Defense**| `backend/services/remediation_engine.py` | 1-Click Cloudflare WAF, ModSecurity, Linux iptables, and patch diff generation |
| **Diagnostic Probe** | `backend/services/remediation_engine.py` | Non-intrusive micro-probes verifying HTTP 403 Forbidden edge blocking |
| **Security Review** | `~/.gemini/config/skills/security-review` | Code-level security audit and vulnerability elimination |

## Scope & Authorization Gate (RFC 8655)

All active scanning and diagnostic probes strictly enforce legal authorization boundaries:
1. Target must be registered in the authorized scope (`GET /api/authorizations`).
2. Tier 2 active scanning requires a cryptographically verified DNS challenge (`_drishti-challenge.<target>` TXT record).
3. Private IP space (RFC 1918) and cloud metadata services (`169.254.169.254`) are strictly blocked by hardware-level anti-SSRF guards.

## Primary Usage in DRISHTI

- Vulnerability triage and weaponization assessment
- Attack graph simulation and Dijkstra vector analysis
- 1-Click defense rule generation and micro-probe validation
- Static and dynamic application security testing (SAST/DAST)
- Cryptographic audit trail generation for SOC compliance
