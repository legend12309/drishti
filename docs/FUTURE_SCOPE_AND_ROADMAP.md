# DRISHTI // ARCHITECTURAL EVOLUTION & FUTURE SCOPE ROADMAP
**Document Version:** 1.0.0  
**Classification:** Technical Architecture & Product Governance  
**Date:** November 2026  
**Status:** Active Canonical Specification  

---

## 1. Executive Statement & Design Philosophy

DRISHTI is built on a foundational product principle: **Uncompromising Core Focus (The "Ponytail" / YAGNI Principle)**. 

A high-performance cybersecurity asset must never be burdened by decorative bloat, developer scaffolding, premature enterprise complexity, or secondary data viewers that distract security operators from their primary mission:
> **Rapid, autonomous, 100% local, air-gapped attack surface discovery, topological vulnerability correlation, Dijkstra attack path graph traversal, and automated defensive hardening.**

To achieve peak operational speed, zero cognitive friction, and rock-solid reliability on commodity hardware, the DRISHTI architecture has been rigorously streamlined into **Seven Core Tactical Pillars**. Non-core features, machine-to-machine exchange viewers, and developer debug controls have been intentionally deferred to the Enterprise Roadmap with rigorous technical justifications outlined below.

---

## 2. The Seven Canonical Core Pillars of DRISHTI (v1.0.0)

Every operational engine in DRISHTI represents an essential, non-redundant phase in the defensive cyber intelligence lifecycle:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               DRISHTI OPERATIONAL CORE                                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
     │
     ├── [01 // COCKPIT]   : Unified Attack Surface Posture, KPI Dials & Scan Launcher
     │
     ├── [02 // RECON]     : Zero-Touch Passive OSINT, DNS Enumeration & Service Discovery
     │
     ├── [03 // INTEL]     : Vulnerability Intelligence, Metasploit 10/10 & AI Threat Copilot
     │
     ├── [04 // GRAPH]     : 6-Stage Topological Attack Graph & Dijkstra Pathfinding Engine
     │
     ├── [05 // GUARD]     : Automated Defense Compiler (Nginx, WAF, IPTables) & Verification
     │
     ├── [06 // REPORTS]   : Executive Threat Briefings, Plaintext Dossiers & STIX 2.1 Export
     │
     └── [07 // CONFIG]    : Air-Gap Zero-Egress Boundary, Local AI Heuristics & API Secrets
```

### Pillar Detail:
1. **`01_ COCKPIT` (Master Attack Surface Command):** Real-time situational awareness, composite perimeter risk scores, active scan orchestrator, and multi-engine telemetry logs.
2. **`02_ RECON` (Passive & Active Reconnaissance):** Certificate Transparency (crt.sh) logs, DoH DNS mapping, non-destructive port scanning, service banner fingerprinting, and RFC 8655 consent boundaries.
3. **`03_ INTEL` (Tactical Cyber Intelligence & Threat Orchestration):** Automated NVD CVE/CWE matching, real-world EPSS probability calculation, curated Rapid7 Metasploit weaponization matrix, and the Neural AI Copilot providing contextual remediation advice.
4. **`04_ GRAPH` (Topological Attack Graph & Dijkstra Pathfinder):** Interactive 6-stage canvas visualizing the complete adversary traversal chain (Stage 01 OSINT -> Stage 02 Apex -> Stage 03 Listener -> Stage 04 Vulnerability -> Stage 05 Lateral Pivot -> Stage 06 Crown Jewel Datastore) with real-time Dijkstra shortest-path calculations.
5. **`05_ GUARD` (Active Defensive Hardening & WAF Guard):** Automated generation of production-ready Nginx ModSecurity v3 rules, Apache `.htaccess` directives, Cloudflare WAF expressions, and Linux kernel iptables packet filters, coupled with live verification micro-probes.
6. **`06_ REPORTS` (Tactical Dossier & Standardized Intelligence Export):** Generation of comprehensive HTML dossiers, printable executive briefings, raw monospace ASCII reports, and 1-click OASIS STIX 2.1 threat intelligence bundle downloads.
7. **`07_ CONFIG` (Engine Configuration & Security Boundaries):** Air-gapped zero-egress enforcement, deterministic local heuristic model fallback management, and encrypted API key storage.

---

## 3. Itemized Audit of Streamlined & Deferred Features

The following features were audited, removed from the active operational flow, and preserved in this roadmap for future enterprise releases.

### 3.1. Standalone Raw STIX 2.1 JSON Viewer (Deferred to Enterprise SIEM Broker v2.0)

- **Previous State:** Existed as a dedicated top-level primary navigation tab (`06 // STIX`) featuring a raw JSON viewer, indicator tables, and SDO counts.
- **Why It Was Streamlined from Core:**
  1. *Machine-to-Machine vs. Human Workflow:* OASIS STIX 2.1 is an interchange format designed for automated machine-to-machine ingestion by external SIEMs (Splunk, MISP, OpenCTI, QRadar). It is not an active analysis canvas for human security operators.
  2. *Cognitive Overhead:* Displaying hundreds of lines of raw JSON in a primary navigation slot created visual noise and broke the natural flow between defensive remediation (`GUARD`) and executive documentation (`REPORTS`).
- **How It Is Handled in v1.0.0 Core:**
  - Fully retained as an export function inside **`06 // REPORTS`** via the **`[ 📥 STIX 2.1 JSON ]`** action button.
  - Programmatic REST API endpoint (`GET /api/stix/bundle?target=...`) remains 100% active and compliant.
- **Future Enterprise Scope (v2.0):**
  - **TAXII 2.1 Real-Time Server:** Live bidirectional publish/subscribe threat feeds allowing enterprise SIEM clusters to subscribe to DRISHTI's attack surface indicators automatically.
  - **Threat Intelligence Platform (TIP) Connectors:** Direct API push into MISP, AlienVault OTX, and OpenCTI instances.

---

### 3.2. Standalone Cryptographic Audit Trail Screen (Deferred to Enterprise Compliance Suite v2.0)

- **Previous State:** Existed as a standalone primary navigation tab (`08 // AUDIT`) displaying internal SQLite WAL transaction logs (`AUTH-1`, SHA-256 hash chains).
- **Why It Was Streamlined from Core:**
  1. *Plumbing vs. Product:* Transaction journaling and SHA-256 hash chaining are fundamental backend integrity mechanisms, not an active attack surface discovery workflow.
  2. *Target Audience:* Security analysts evaluating perimeter vulnerabilities do not need an entire primary screen dedicated to internal framework authorization events.
- **How It Is Handled in v1.0.0 Core:**
  - Fully verified programmatically by the 43-vector automated Red Team audit suite (`tests/red_team_full_audit.py`).
  - Underlying database tables and WAL journal mode remain active and verified on startup.
- **Future Enterprise Scope (v2.0):**
  - **Hardware Security Module (HSM) Signing:** Integrating physical YubiKey or TPM 2.0 cryptographic hardware chips for hardware-attested audit signing.
  - **SOC 2 Type II & ISO 27001 Audit Vault:** Exportable compliance ledgers formatted for third-party regulatory auditors.

---

### 3.3. Standalone Mock Operator Clearance & Profile Screen (Deferred to Enterprise RBAC v2.0)

- **Previous State:** Existed as a full-screen clearance dossier (`10 // PROFILE`) displaying mock "Level 5 Top Secret // Alex Morgan" clearance badges.
- **Why It Was Streamlined from Core:**
  1. *Single-Operator Reality:* DRISHTI is engineered as a zero-dependency, single-operator desktop tool that runs natively without requiring external enterprise directory services.
  2. *Aesthetic Distraction:* A mock clearance screen adds decorative complexity without providing functional multi-user access control.
- **How It Is Handled in v1.0.0 Core:**
  - Streamlined into a minimalist, high-contrast operator badge (`OP: AM // LVL 5`) on the top command HUD.
- **Future Enterprise Scope (v2.0):**
  - **Enterprise Identity Federation:** Native SAML 2.0, Okta, and Azure AD (Entra ID) single sign-on (SSO).
  - **Granular Role-Based Access Control (RBAC):** Multi-tenant organization boundaries, assigning distinct roles (e.g. Read-Only Auditor, Threat Hunter, Red Team Operator).

---

### 3.4. In-Header Developer `[ TEST PIPELINE ]` Button (Removed from Production UI)

- **Previous State:** A permanent button pinned in the top executive command bar executing `/api/health/pipeline-test`.
- **Why It Was Removed from Core UI:**
  - A prominent diagnostic button running test pipelines looks like unfinished developer scaffolding in an executive production interface.
- **How It Is Handled in v1.0.0 Core:**
  - Automated health monitoring is natively indicated by the **`[ LIVE HUD ]`** status indicator and the non-blocking background health daemon.
  - Diagnostic validation is executed via standard engineering test suites (`pytest` and `red_team_full_audit.py`).
- **Future Enterprise Scope (v2.0):**
  - **Synthetic Canary Monitoring:** Autonomous scheduled boundary health checks that notify operators via Slack, Discord, or PagerDuty webhooks upon infrastructure drift.

---

### 3.5. External Cloud Backend Hosting (Deferred to Cloud SaaS Architecture v2.0)

- **Previous State:** Evaluated for cloud hosting platforms (e.g., Vercel, Render, AWS ECS).
- **Why It Was Deferred in Favor of Local Standalone:**
  1. *Zero Cloud Fees:* Running 100% locally eliminates recurring cloud server, database, and ingress/egress bandwidth costs.
  2. *Zero-Egress Security & Privacy:* Security operators often assess private infrastructure, intellectual property, and proprietary networks where sending scan data to third-party cloud servers violates confidentiality agreements.
  3. *Total Air-Gap Capability:* DRISHTI runs in physically isolated, air-gapped enclaves without requiring internet access or cloud API keys.
- **How It Is Handled in v1.0.0 Core:**
  - Self-contained Windows-x64 standalone package (`DRISHTI-v1.0.0-Windows-x64.zip`) and cross-platform source distribution.
- **Future Enterprise Scope (v2.0):**
  - **Kubernetes Helm Chart & Distributed Worker Nodes:** For large organizations that require multi-region distributed scanner nodes managed by a central private cloud control plane.

---

## 4. Release Trajectory & Milestones

| Version | Focus | Scope & Deliverables | Status |
|:---|:---|:---|:---|
| **v1.0.0** | **Autonomous Local Core** | 7-Engine Core Cockpit, 100% air-gap synthetic AI reasoning, NVD/EPSS correlation, Dijkstra attack paths, Rapid7 Metasploit arsenal, 1-click Windows portable distribution. | **COMPLETE (CURRENT)** |
| **v1.5.0** | **Tactical Arsenal Upgrade** | Metasploit RC2 automation compiler, local embedding vector search for CVEs, customizable WAF export templates. | **PLANNED** |
| **v2.0.0** | **Enterprise Security Suite** | Live TAXII 2.1 feed broker, SAML/Okta SSO, multi-user RBAC, distributed cloud worker nodes, and HSM-backed audit trails. | **FUTURE ROADMAP** |

---

## 5. Summary of Core Invariants

Regardless of future feature additions, DRISHTI will always maintain the following core invariants:
1. **Always Fully Functional Offline:** The core vulnerability matching, attack graph pathfinding, and threat intelligence advisory will never require a mandatory internet connection or paid third-party API key.
2. **Deterministic & Audit-Verified:** All risk scores, CVSS rankings, and graph resistance costs are mathematically derived and verified by automated regression tests.
3. **Zero Cognitive Friction:** The user experience will remain laser-focused on actionable cybersecurity defense without decorative bloat.
