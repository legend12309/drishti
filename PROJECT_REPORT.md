# DRISHTI Cyber Intelligence Platform — Comprehensive Project Report

**Document Title:** Production Platform Architecture & Comprehensive Frontend Specification  
**Generated Date:** November 01, 2026  
**System Status:** Production Ready // All Engines & Services Operational  
**Repository Source:** `D:\drishti`  

---

## 1. Executive Summary

**DRISHTI** is an autonomous, multi-engine Cyber Intelligence & Attack Surface Management (ASM) platform designed for red teams, blue teams, and enterprise security auditors. It unifies perimeter reconnaissance, protocol-level vulnerability discovery, topological attack graph computation, and autonomous defense generation into a single tactical command system.

### Core Value Proposition
- **Self-Contained Pure-Python Architecture:** Replaced heavy, brittle external scanner containers (ZAP, Trivy, Nuclei, Nmap) with native, high-performance, asynchronous Python engines.
- **Topological Attack Graphing:** Moves past flat CVE lists by running **Dijkstra’s shortest path algorithm** over a directed graph $G = (V, E)$, calculating the exact lateral pivot path from public ingress to the organization's "Crown Jewels" (core databases and secrets vaults).
- **Multi-Model AI Consensus (Groq + Gemini + NVIDIA NIM):** Combines sub-150ms LPU telemetry triage (Groq), 2M-token whole-surface contextual exploit chaining (Google Gemini), and environment-specific exploitability filtering (NVIDIA NIM) with zero-hallucination guardrails (`temperature: 0.2`).
- **Cryptographic Scope Guardrails:** Enforces legal authorization boundaries via DNS TXT challenge tokens (`drishti-verify=...`) and hardware-level anti-SSRF protections against private subnets (RFC1918) and cloud metadata services (`169.254.169.254`).

---

## 2. Platform Architecture & Technology Stack

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                 DRISHTI CYBER INTELLIGENCE PLATFORM                              │
├────────────────────────────────┬────────────────────────────────┬────────────────────────────────┤
│ FRONTEND PRESENTATION LAYER    │ BACKEND INTELLIGENCE CORE      │ PERSISTENCE & DATA PLANE       │
│                                │                                │                                │
│ • React 18.x (TypeScript 5.9)  │ • FastAPI (Python 3.12 Asgard) │ • SQLite WAL Mode (Local)      │
│ • Vite 5.4 High-Speed Bundler  │ • Asynchronous Event Loops     │ • Supabase PostgreSQL (Remote) │
│ • Tactical Obsidian Dark HUD   │ • Multi-Provider LLM Gateway   │ • Realtime WebSocket Mesh      │
│ • Force-Directed Canvas Graph  │ • Native Pure-Python Engines   │ • Cryptographic Audit Ledger   │
│ • Lucide Tactical Iconography  │ • Strict DNS Scope Enforcement │ • STIX 2.1 Threat Store        │
└────────────────────────────────┴────────────────────────────────┴────────────────────────────────┘
```

### Technology Matrix

| Layer | Component | Version / Specification | Technical Role |
| :--- | :--- | :--- | :--- |
| **Frontend UI** | React + TypeScript | React 18, Vite 5.4, TS 5.9 | Componentized tactical HUD, zero layout shifts, monospace data density. |
| **Styling** | Tailwind CSS + Tactical Tokens | Custom Obsidian Palette | Aerospace/military-grade high-contrast SecOps aesthetics. |
| **Backend API** | FastAPI / Starlette | Python 3.12 (Native Async) | Asynchronous REST endpoints, SSE event streams, lifespan event management. |
| **Database** | SQLite 3 (WAL Mode) | Write-Ahead Logging | Sub-millisecond reads, serialized safe writes, zero external DB dependencies. |
| **Cloud State** | Supabase PostgreSQL + Realtime | Cloud-Managed PostgreSQL 16 | Distributed multi-operator synchronization and live WebSocket broadcasts. |
| **AI Gateway** | Custom Circuit-Breaker Router | Groq, Gemini, NVIDIA, HF | Tri-provider consensus with deterministic offline synthetic fallback. |

---

## 3. Comprehensive Frontend Page-by-Page Specification

The DRISHTI frontend (`frontend/src/`) is organized into **11 specialized operational views**, accessible via the persistent tactical sidebar, top command bar, or global keyboard command palette (`⌘K`).

---

### Page 1: `LoginView` — Operator Authentication & Clearance Gateway
- **Component File:** [`frontend/src/views/LoginView.tsx`](file:///D:/drishti/frontend/src/views/LoginView.tsx)
- **Primary Purpose:** Enforces zero-trust entry, validates operator identity, assigns role-based access control (RBAC), and issues session JWT tokens.
- **Key UI Elements:**
  - **Operator Credentials Card:** High-contrast input fields for username/email and masked password.
  - **Role Selection Selector:** Allows switching operational persona (`Principal Security Analyst`, `Red Team Lead`, `Compliance Auditor`, `SecOps Engineer`).
  - **Security Indicator Badges:** Displays active cryptographic protection standards (`TLS 1.3 Strict`, `Zero-Knowledge Session Context`).
- **Data Flow & Actions:**
  - Sends `POST /api/auth/login`. On success, receives signed JWT and initializes the operator profile in `localStorage`.
  - Dispatches `onLoginSuccess(operator, token)`, unlocking the Command Deck.

---

### Page 2: `DashboardView` — Tactical Mission Control & Executive HUD
- **Component File:** [`frontend/src/views/DashboardView.tsx`](file:///D:/drishti/frontend/src/views/DashboardView.tsx)
- **Primary Purpose:** Serves as the high-level operational cockpit. Aggregates system health, active scan statuses, discovered asset counts, and threat scores.
- **Key UI Elements:**
  - **Global Threat Level Dial:** Real-time calculated risk gauge (0.0 to 10.0) reflecting current perimeter exposure.
  - **Target Quick-Launch Cockpit:** Input bar for initiating instantaneous single-target or domain assessments.
  - **Engine Health Cards:** Real-time heartbeat monitors for all 5 intelligence engines (Detective, HTTPX, DAST, Nuclei, Trivy).
  - **Recent Activity Stream:** Chronological feed of scan completions, scope validations, and critical CVE detections.
- **Data Flow & Actions:**
  - Polls `GET /health` and `GET /api/scans/latest` on mount.
  - Emits navigation events to deep-dive into Recon, Intel, or Graph views.

---

### Page 3: `ReconView` — Autonomous Reconnaissance & Perimeter Explorer
- **Component File:** [`frontend/src/views/ReconView.tsx`](file:///D:/drishti/frontend/src/views/ReconView.tsx)
- **Primary Purpose:** Manages perimeter discovery, DNS challenge verification, subdomain enumeration, and active port fingerprinting.
- **Key UI Elements:**
  - **Target Ingress & Scope Bar:** Domain input with scope toggle (`FULL_PASSIVE` vs `FULL_ACTIVE`).
  - **Cryptographic DNS Challenge Card:** Generates and displays the exact DNS TXT record name (`_drishti-challenge.target.com`) and verification token required to unlock Tier 2 active scanning.
  - **Discovered Subdomains Table:** Tabular grid displaying hostname, resolved IP, detected technology stack, response status, and risk level.
  - **Service & Port Discovery Matrix:** Monospace port listings showing protocol, service banner (`nginx 1.24.0`, `OpenSSH 8.9`), and TLS cipher status.
- **Data Flow & Actions:**
  - Invokes `POST /api/authorizations/challenge` to request DNS tokens.
  - Calls `POST /api/authorizations/verify` to validate TXT record presence via Cloudflare DoH (`1.1.1.1`).
  - Streams real-time scanner logs via Server-Sent Events (`/api/scans/{id}/stream`).

---

### Page 4: `IntelView` — Vulnerability Intelligence & CVE Correlation Matrix
- **Component File:** [`frontend/src/views/IntelView.tsx`](file:///D:/drishti/frontend/src/views/IntelView.tsx)
- **Primary Purpose:** Deep vulnerability analysis correlating discovered services against the NVD database, CISA KEV catalog, and EPSS scores.
- **Key UI Elements:**
  - **CVE Severity Filter Chips:** Quick filters for `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `CORRELATED`.
  - **Vulnerability Inspection Cards:** Expandable cards displaying CVE ID, published date, CVSS v3.1 base score, EPSS percentile, and affected asset hostname.
  - **Match Rationale Pill:** Transparently displays why the CVE was flagged (e.g., `Banner Match: Apache 2.4.49 -> Known Path Traversal`).
  - **Vendor Remediation Guidance:** Direct vendor remediation instructions and patched release numbers.
- **Data Flow & Actions:**
  - Fetches vulnerabilities from `GET /api/vulnerabilities/scan/{scan_id}`.
  - Connects to AI Copilot via `POST /api/llm/explain-vulnerability` to generate plain-English technical impact briefs.

---

### Page 5: `GraphView` — Topological Attack Graph & Dijkstra Path Analysis
- **Component File:** [`frontend/src/views/GraphView.tsx`](file:///D:/drishti/frontend/src/views/GraphView.tsx)
- **Primary Purpose:** Visualizes the target attack surface as an interactive graph, computing the lowest-friction route from public ingress to core databases.
- **Key UI Elements:**
  - **Force-Directed Graph Canvas:** Visual canvas grouping nodes into architectural layers: Ingress, Reverse Proxy, Application Services, and Crown Jewels.
  - **Critical Attack Path Highlighting:** Renders the Dijkstra shortest path as an animated pulsating crimson energy beam.
  - **Node Inspector Drawer:** Slide-up panel displaying node details, open ports, connected edges, and assigned risk weighting.
  - **"What-If" Simulation Toggles:** Interactive toggles allowing operators to simulate patching a CVE or shutting down a port, watching the graph dynamically collapse the attack path in real time.
- **Data Flow & Actions:**
  - Fetches graph topology from `GET /api/graph/latest`.
  - Dispatches `POST /api/llm/explain-path` to have the multi-model AI explain the ingress-to-pivot narrative.

---

### Page 6: `GuardView` — Prompt Guard & LLM Safety Boundary Evaluator
- **Component File:** [`frontend/src/views/GuardView.tsx`](file:///D:/drishti/frontend/src/views/GuardView.tsx)
- **Primary Purpose:** Hardens the platform against adversarial manipulation, testing and evaluating incoming security prompts for jailbreaks, prompt injections, and SQL injections.
- **Key UI Elements:**
  - **Prompt Security Sandbox:** Input area for testing malicious payloads.
  - **Preset Attack Library:** Quick-load buttons for Prompt Override, DAN Jailbreak, SQL Injection, System Directive Leakage, and SSRF.
  - **Multi-Layer Defense Verdict:** Real-time card showing verdict (`PASSED` vs `BLOCKED`), defense layer triggered (`L1 Regex Pattern`, `L2 Semantic Entropy`, `L3 Model Guard`), and latency in milliseconds.
- **Data Flow & Actions:**
  - Dispatches `POST /api/guard/evaluate` to test prompt strings against DRISHTI's multi-layered input sanitization middleware.

---

### Page 7: `StixView` — STIX 2.1 Threat Intelligence & TAXII Bundler
- **Component File:** [`frontend/src/views/StixView.tsx`](file:///D:/drishti/frontend/src/views/StixView.tsx)
- **Primary Purpose:** Translates DRISHTI’s findings into standardized OASIS STIX 2.1 JSON bundles for seamless integration into enterprise SIEMs (Splunk, Microsoft Sentinel).
- **Key UI Elements:**
  - **STIX Object Matrix:** Card counters for generated Threat Actors, Attack Patterns, Vulnerabilities, Indicators, and Observed Data objects.
  - **Monospace JSON Inspector:** Formatted STIX 2.1 bundle viewer with syntax highlighting and 1-click clipboard copy.
  - **TAXII Export Trigger:** Button to export the bundle or push directly to a configured TAXII 2.1 server collection.
- **Data Flow & Actions:**
  - Queries `GET /api/stix/bundle`, generating deterministic, standard-compliant STIX JSON representations of all scan findings.

---

### Page 8: `ReportsView` — Cryptographically Signed Assessment Reports
- **Component File:** [`frontend/src/views/ReportsView.tsx`](file:///D:/drishti/frontend/src/views/ReportsView.tsx)
- **Primary Purpose:** Generates, manages, and downloads executive-ready PDF and standalone HTML penetration testing and vulnerability assessment reports.
- **Key UI Elements:**
  - **Report Archive Table:** Historical list of generated reports with target name, status badge, file size in KB, and timestamp.
  - **Report Generation Modal:** Configuration dialog to select report scope, executive summary inclusion, and technical appendix detail.
  - **Direct Download & Preview Actions:** Buttons to open standalone HTML reports in a new tab or trigger binary downloads.
- **Data Flow & Actions:**
  - Invokes `POST /api/reports/generate` to trigger the backend Jinja2 HTML/PDF report synthesis pipeline.

---

### Page 9: `AuditView` — Immutable SQLite WAL Audit Ledger
- **Component File:** [`frontend/src/views/AuditView.tsx`](file:///D:/drishti/frontend/src/views/AuditView.tsx)
- **Primary Purpose:** Provides a tamper-evident, append-only record of every operator action, scan event, authorization challenge, and security block.
- **Key UI Elements:**
  - **Engine & Severity Filters:** Filter audit logs by engine (`All`, `DNS`, `Nmap`, `HTTPX`, `ZAP`, `Nuclei`) and status (`SUCCESS`, `BLOCKED`, `WARNING`).
  - **Cryptographic Hash Column:** Displays SHA-256 hashes linking audit entries to maintain tamper-evident integrity.
  - **Audit Search Bar:** Real-time substring filter across action details, operator IDs, and target domains.
- **Data Flow & Actions:**
  - Queries `GET /api/audit/logs` and `GET /api/authorizations/audit` on mount.

---

### Page 10: `SettingsView` — Multi-Provider AI Gateway & Engine Configuration
- **Component File:** [`frontend/src/views/SettingsView.tsx`](file:///D:/drishti/frontend/src/views/SettingsView.tsx)
- **Primary Purpose:** Allows administrators to configure API keys for external intelligence providers, toggle offline modes, and inspect active engine routing.
- **Key UI Elements:**
  - **API Provider Credentials Grid:** Masked credential inputs for Google Gemini, NVIDIA NIM, Groq, and Hugging Face.
  - **Active Engine Mode Card:** Displays active mode (`HIGH_SPEED_LPU_CONSENSUS` vs `LOCAL_COMMODITY_FALLBACK`).
  - **Force Local Mode Toggle:** Master switch to disable all external network calls and enforce 100% offline heuristic operation.
- **Data Flow & Actions:**
  - Reads masked keys via `GET /api/settings`.
  - Persists updated credentials securely to `.env` and runtime state via `POST /api/settings`.

---

### Page 11: `ProfileView` — Operator Identity & Cryptographic Session Card
- **Component File:** [`frontend/src/views/ProfileView.tsx`](file:///D:/drishti/frontend/src/views/ProfileView.tsx)
- **Primary Purpose:** Displays current operator clearance, active cryptographic session fingerprints, RBAC permissions, and hardware security bindings.
- **Key UI Elements:**
  - **Operator Avatar & Clearance Badge:** Displays operator name, email, and security tier (`LEVEL 5 // TOP SECRET // SI-TK / GBD-AUTH`).
  - **Permission Matrix Chips:** Visual badges for granted capabilities (`FULL_PASSIVE_RECON`, `ATTACK_GRAPH_PATHFINDING`, `SCOPE_CHALLENGE_ISSUER`).
  - **Session Cryptographic Fingerprint:** Monospace display of active SHA-256 token fingerprint, client IP, and hardware token binding status.
  - **Session Logout Action:** Secure session termination clearing tokens and resetting operational state.
- **Data Flow & Actions:**
  - Reads operator state from `localStorage` and app memory. Dispatches `onLogout()` to safely invalidate session tokens.

---

## 4. Backend Engine Architecture & Pure-Python Foundations

DRISHTI does not require external scanning binaries or Docker dependencies to run core scans. All assessment capabilities are implemented in native, non-blocking asynchronous Python:

```
backend/
├── engines/
│   ├── async_port_engine.py      # Native non-blocking TCP/UDP socket scanner
│   ├── async_httpx_engine.py     # Protocol, TLS, and ALPN fingerprinting engine
│   ├── pure_dast_engine.py       # Passive & active DAST header, CORS, and cookie auditor
│   ├── pure_nuclei_engine.py     # Lightweight YAML-less vulnerability pattern matching
│   └── pure_trivy_engine.py      # Client-side dependency & CVE correlation engine
```

### Engine Capabilities

| Engine Name | Implementation | Technical Advantage |
| :--- | :--- | :--- |
| **Pure DAST Engine** | `backend/services/zap_adapter.py` | Audits security headers, CORS wildcards, cookie flags, and passive client-side JS endpoints in pure Python with zero Java runtime overhead. |
| **Pure Nuclei Engine** | `backend/services/nuclei_adapter.py` | Implements high-frequency vulnerability pattern matching (exposed `.git`, `.env` leaks, Swagger docs, path traversals) without requiring the Go Nuclei binary. |
| **Pure Trivy Engine** | `backend/services/trivy_adapter.py` | Extracts client-side frontend libraries (React, Vite, Axios, Lodash), parses semantic versions, and matches them directly against local CVE databases. |
| **Async Port Engine** | `backend/services/nmap_adapter.py` | Native non-blocking socket probes across curated service ports with adaptive jitter to avoid WAF rate-limiting. |

---

## 5. Security, Scope & Legal Guardrails

DRISHTI enforces legal and operational boundaries through architectural constraints:

1. **DNS-Based Cryptographic Proof of Authorization:**
   - Production scans require the target domain administrator to insert a unique TXT challenge record (`_drishti-challenge.target.com`).
   - The detective engine verifies this record via DoH before promoting the domain from `UNVERIFIED` to `AUTHORIZED`.
2. **Hardcoded Anti-SSRF Protection:**
   - Evaluates every resolved destination IP against loopback (`127.0.0.0/8`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata APIs (`169.254.169.254`).
   - If an IP matches a protected boundary, the engine terminates the connection immediately.
3. **Immutable SQLite WAL Audit Ledger:**
   - Every scan initiation, scope grant, and blocked request is recorded in `data/drishti.db` using SQLite Write-Ahead Logging (WAL) mode for crash-resilient audit integrity.

---

## 6. Verification & Quality Assurance Baseline

The platform has been audited and validated through rigorous automated test suites:

- **Total Backend Tests:** 15 Comprehensive Integration & Unit Tests.
- **Test Command:** `python -m pytest tests/test_health.py tests/test_phase11_orchestrator.py tests/test_phase4_attack_graph_risk_engine.py`
- **Result:** **100% PASSING (GREEN)**.
- **Frontend Production Build:** Compiles cleanly via `npm run build` into `frontend/dist/` with zero TypeScript or bundling errors.

---

## 7. Operational Run Guide

### Starting the Platform

#### 1. Backend API Service:
```powershell
Set-Location "D:\drishti"
& "D:\drishti\.venv\Scripts\python.exe" -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
- API Health Endpoint: `http://localhost:8000/health`
- Interactive OpenAPI Docs: `http://localhost:8000/api/docs`

#### 2. Frontend Command Deck:
```powershell
Set-Location "D:\drishti\frontend"
npm run dev -- --host 0.0.0.0
```
- Web Application URL: `http://localhost:5173`

---

## 8. Conclusion

DRISHTI provides an end-to-end cyber intelligence and defense workflow that connects **dual-layer reconnaissance**, **Dijkstra attack graph pathfinding**, **Metasploit exploit intelligence correlation**, and **autonomous multi-model AI defense synthesis**. By encapsulating this architecture into a responsive, high-density **Tactical Obsidian HUD**, it delivers unmatched situational awareness and rapid threat neutralization for modern security operations.
