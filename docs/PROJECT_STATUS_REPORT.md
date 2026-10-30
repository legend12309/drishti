# DRISHTI — Project Status Report

**Cyber Command & Threat Intelligence Platform**

| | |
|---|---|
| **Document type** | Consolidated project status report |
| **Prepared for** | Project guide / evaluator |
| **Prepared on** | 2026-10-28 |
| **Evidence window** | Live run of 2026-10-27 |
| **Version** | `v1.0.0-rc1` |
| **Overall status** | **Functional prototype — not production-ready** |
| **Test result** | **121 passed / 1 failed** (122 total) |

---

## 1. Executive summary

DRISHTI is a full-stack cyber-intelligence and automated reconnaissance platform. The application builds, starts, authenticates, authorizes targets, orchestrates scans, streams progress, persists results and exposes findings through a React frontend and a FastAPI backend.

The platform is **operational as a system** but **not yet reliable as a scanner product**. A complete end-to-end run with all five scanners produced:

| Result | Count |
|---|---|
| Scanners that delivered usable findings | **1 of 5** (httpx) |
| Scanners that failed | **3 of 5** (Nmap, Trivy, Nuclei) |
| Scanners that reported success without scanning | **1 of 5** (ZAP) |

Three of those are defects in *our* code, not in the scanners themselves. All have been root-caused with file-level evidence and are scheduled for repair.

**The strong parts** — authorization enforcement, orchestration, persistence, SSE streaming, partial-success handling and the frontend build — work correctly and are verified.

---

## 2. Aim

To build a unified security assessment platform that:

1. **Authorizes** a target through cryptographic proof of ownership (DNS TXT challenge) before any active scanning.
2. **Discovers** an organisation's external attack surface (subdomains, hosts, services, technologies).
3. **Scans** that surface with industry-standard tools (Nmap, ZAP, httpx, Nuclei, Trivy).
4. **Correlates** raw observations into normalized, risk-scored findings with CVE/EPSS enrichment.
5. **Explains** the results through an AI layer and an attack-path graph.
6. **Exports** findings in standard formats (STIX 2.1, reports).

---

## 3. Problem statement

Manual external attack-surface assessment is slow, inconsistent and legally hazardous:

| Problem | Consequence |
|---|---|
| Reconnaissance is performed ad-hoc with disconnected tools | Incomplete coverage; results in spreadsheets |
| No proof of authorization before scanning | Legal and ethical risk; accidental scanning of third parties |
| Raw scanner output is unstructured and overwhelming | Analysts cannot prioritise; findings are missed |
| Vulnerability data is not correlated with asset context | Noise instead of actionable risk |
| No audit trail of who scanned what, when and why | Non-reproducible, non-compliant assessments |

DRISHTI addresses these with an authorization-first, orchestrated, evidence-preserving pipeline.

---

## 4. Proposed solution

A single platform where the operator:

1. **Registers a target** and receives a DNS TXT challenge.
2. **Publishes the TXT record**, which the backend verifies before any network activity.
3. **Launches a Unified Recon workflow**, selecting the scanners to run.
4. **Watches live progress** over SSE while stages execute sequentially.
5. **Receives normalized findings** correlated into a risk model, with scanner provenance.
6. **Explores the attack graph** and asks the AI layer for explanation and remediation.
7. **Exports** the assessment.

Security controls built into the design:

- Authorization is re-validated **immediately before** network I/O, not just at request time.
- Scope boundaries are enforced per target.
- Scanner subprocesses use argument arrays (`shell=False`), never string concatenation.
- XML parsing is hardened against XXE and entity expansion.
- Credentials remain server-side; the frontend never receives API keys.
- Every action is written to an audit log.

---

## 5. System architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  React 18 + Vite + TypeScript  (single-page application)             │
│  Dashboard · Recon · Intel · Guard · Graph · STIX · Audit · Settings │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ REST + Server-Sent Events
┌───────────────────────────────▼──────────────────────────────────────┐
│  FastAPI backend  (62 routes across 10 API modules)                  │
│                                                                      │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────────────────────┐   │
│  │ Auth /     │  │ Scan         │  │ Scan Orchestrator           │   │
│  │ Authoriza- │─▶│ Lifecycle    │─▶│  stage sequencing,          │   │
│  │ tion       │  │ + SSE        │  │  availability, partial      │   │
│  │ (DNS TXT)  │  │              │  │  completion, cancellation   │   │
│  └────────────┘  └──────────────┘  └──────────────┬──────────────┘   │
│                                                   │                  │
│  ┌────────────────────────────────────────────────▼───────────────┐  │
│  │ Scanner adapters (33 service modules)                          │  │
│  │ Nmap · ZAP · httpx · Nuclei · Trivy · Detective engine         │  │
│  └────────────────────────────────────────────────┬───────────────┘  │
│                                                   │                  │
│  ┌───────────────┐  ┌──────────────┐  ┌───────────▼──────────────┐   │
│  │ Risk engine   │  │ AI router    │  │ Persistence layer        │   │
│  │ (deterministic│  │ Gemini →     │  │ PostgreSQL (asyncpg pool)│   │
│  │  CVE / EPSS)  │  │ Groq → NVIDIA│  │ migrations, RLS          │   │
│  │               │  │ → HuggingFace│  │                          │   │
│  └───────────────┘  └──────────────┘  └──────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│  Execution environment (Docker Compose)                              │
│  drishti_platform (API + binaries) · drishti_zap (daemon) ·          │
│  drishti_postgres (PostgreSQL 16.15)                                 │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 6. Technology stack

### Frontend
| Component | Version | Role |
|---|---|---|
| React | 18.3.1 | UI framework |
| TypeScript | 5.6.3 | Type safety |
| Vite | 5.4.9 | Build tool / dev server |
| Tailwind CSS (CDN) | — | Styling |
| lucide-react | 0.453.0 | Icons |

### Backend
| Component | Version | Role |
|---|---|---|
| Python | 3.12.14 | Runtime |
| FastAPI | ≥0.115 | API framework |
| Uvicorn | ≥0.32 | ASGI server |
| Pydantic | ≥2.9 | Schema validation |
| asyncpg | ≥0.29 | PostgreSQL driver |
| NetworkX | ≥3.4 | Attack-graph modelling |
| dnspython | ≥2.7 | DNS resolution |
| httpx | ≥0.27 | HTTP client |
| PyJWT | ≥2.9 | Token handling |
| psutil | ≥6.1 | System telemetry |

### Data & intelligence
| Component | Role |
|---|---|
| PostgreSQL 16.15 | Primary datastore (Supabase-compatible) |
| ChromaDB + all-MiniLM-L6-v2 | Vector intelligence store |
| Deterministic risk engine | CVE / EPSS correlation |
| STIX 2.1 | Threat-report export |

### AI providers (existing, unchanged)
Gemini → Groq → NVIDIA NIM → Hugging Face, with a deterministic offline fallback. Keys stay server-side.

### Security scanners
| Scanner | Version | Mode |
|---|---|---|
| Nmap | 7.95 | Local subprocess |
| OWASP ZAP | 2.17.0 | Daemon container + REST API |
| ProjectDiscovery httpx | v1.6.0 | Local subprocess (CLI, not the Python library) |
| Nuclei | v3.3.2 | Local subprocess |
| Trivy | 0.76.1 | Local subprocess |

---

## 7. Feature inventory

| Area | Feature | Status |
|---|---|---|
| Authorization | DNS TXT challenge create / verify / lifecycle | **Working** |
| Authorization | Scope enforcement and boundary checks | **Working** |
| Authorization | Pre-scan re-validation from database | **Working** (but see I-18) |
| Recon | Passive DNS, CT logs, RDAP, active DNS | **Working** |
| Recon | Subdomain enumeration and asset inventory | **Working** |
| Scanning | Unified multi-scanner orchestration | **Working** |
| Scanning | Partial-success handling | **Working** |
| Scanning | Cancellation and recovery | **Working** |
| Scanning | Nmap integration | **Broken** (parser rejects valid XML) |
| Scanning | ZAP integration | **Broken** (reports success without scanning) |
| Scanning | httpx integration | **Working** (3 findings in live run) |
| Scanning | Nuclei integration | **Partial** (timeout budget too small) |
| Scanning | Trivy integration | **Broken** (hostname treated as path) |
| Results | Normalized finding schema | **Working** |
| Results | CVE / EPSS enrichment | **Working** |
| Results | Attack-path graph | **Working** |
| Results | STIX 2.1 export | **Working** |
| Interface | SSE live progress | **Working** (state persistence newly fixed) |
| Interface | Scanner status display | **Partial** (no per-scanner health endpoint) |
| Interface | AI explanation / remediation | **Working** (router with fallback) |
| Interface | Audit log | **Working** |
| Ops | Health endpoint (`/api/health`) | **Working** |
| Ops | Docker Compose stack | **Working** |

**Scale:** 33 backend service modules · 10 API modules · 62 routes · 17 test files · 10 frontend views · 6 components.

---

## 8. Verification evidence

### 8.1 Live end-to-end workflow

Target `www.curezy.in`, all five scanners requested, workflow `wf-1793120244-www-curezy-in`.

| Stage | Status | Duration | Findings | Error |
|---|---|---|---|---|
| nmap | **failed** | 1107.11 s | 0 | `XML containing DTD / External Entities is strictly rejected for security.` |
| httpx | completed | 2.89 s | **3** | — |
| zap | completed | 0.74 s | 0 | none — but no scan was performed |
| trivy | **failed** | 0.05 s | 0 | `Target path does not exist: /app/www.curezy.in` |
| nuclei | **failed** | 120.27 s | 0 | `Scan execution exceeded timeout of 120s` |

Final state: `partially_completed`, progress 100.

**What this run proves:** authorization was enforced, the workflow executed, stages were isolated, a failing stage did not erase another stage's findings, and final status was reported accurately.

### 8.2 Test suite

```
1 failed, 121 passed, 1 warning in 357.71s (0:05:57)
```

| Metric | Value |
|---|---|
| Collected | 122 |
| Passed | **121** |
| Failed | **1** |
| Skipped | 0 |
| Warning | `StarletteDeprecationWarning: HTTP_422_UNPROCESSABLE_ENTITY` |

Baseline at start of session: **114 passed / 8 failed**. Net improvement: **+7 tests**.

The single remaining failure is `tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence`. It fails deterministically in isolation (27.8 s) and is caused by defect **I-18**, not by test flakiness.

### 8.3 Frontend build

```
✓ 46 modules transformed
✓ built in 473ms
dist/assets/index-D1dgi4v7.js   281.80 kB │ gzip: 75.77 kB
```

### 8.4 Runtime health

```json
{"status":"operational","platform":"DRISHTI","version":"v1.0.0-rc1",
 "database":{"engine":"postgresql","status":"connected","supabase":false,
             "version":"PostgreSQL 16.15"},
 "engines":{"recon":"ready","intel":"ready","graph":"ready","stix":"ready"}}
```

### 8.5 Binaries present

```
nmap 7.95 · httpx v1.6.0 · nuclei v3.3.2 · trivy 0.76.1 · ZAP 2.17.0
```

---

## 9. Defects found

Full detail with file references: `docs/project-audit/ERROR_REGISTER.md`.

| ID | Defect | Severity | Status |
|----|--------|----------|--------|
| I-06 | Valid Nmap XML rejected — parser scans the whole document for `system`/`public`/`%` | Critical | Open |
| I-07 | Nmap timeout unenforced when a cancel event exists (120 s budget → 1107 s run) | Critical | Open |
| I-08 | Trivy receives a hostname and resolves it as a local filesystem path | Critical | Open |
| I-09 | ZAP returns `COMPLETED` after one `accessUrl` call, without scanning | Critical | Open |
| I-18 | Sandbox authorization is not persisted, so the worker rejects its own scan | Critical | Open |
| I-12 | Workflow findings endpoint missing; SPA fallback returns HTML 200 | High | Open |
| I-10 | Nuclei exceeds 120 s budget; partial output discarded | High | Partial |
| I-11 | Progress is a fixed placeholder (5 % / 10 %), not real work | Medium | Partial |
| I-13 | Recon view lost state on tab switch | High | Fixed, unverified |
| I-14 | UI displayed fabricated stage durations and finding counts | High | Fixed |
| I-15 | Frontend build broken by an incomplete edit | High | Fixed |
| I-01 | ZAP API allow-list rejected container requests | High | Fixed |
| I-02 | `SANDBOX_ALLOWLIST` shadowed DB authorizations in tests | Medium | Fixed |
| I-03 | Passive-recon source assertion too narrow | Low | Fixed |
| I-04 | Orchestrator test poll window too short | Low | Fixed |
| I-05 | Truncated-XML chaos test expected the wrong contract | Low | Fixed |
| I-16 | Supabase connection ceiling blocks integration tests | Medium | Blocked (environment) |
| I-17 | ZAP host-port access from Windows unconfirmed | Low | Unverified |

---

## 10. Current status dashboard

| Dimension | Status | Evidence |
|---|---|---|
| Application starts and serves the UI | **PASS** | `/api/health` → `operational` |
| Database connectivity | **PASS** | PostgreSQL 16.15 connected, pool healthy |
| Authentication / authorization model | **PASS** | DNS TXT lifecycle tests pass |
| Orchestration and stage isolation | **PASS** | Live workflow `partially_completed` |
| Persistence of findings | **PASS** | httpx findings persisted and retrievable |
| SSE progress streaming | **PASS** | Stream endpoint returns workflow state |
| Frontend build | **PASS** | 46 modules, 473 ms |
| Backend test suite | **PASS (with 1 failure)** | 121 / 122 |
| Scanner correctness | **FAIL** | 1 of 5 scanners delivered findings |
| Scanner status honesty | **FAIL** | ZAP reports success without scanning |
| Progress reporting accuracy | **PARTIAL** | Fixed percentages only |
| Production readiness | **FAIL** | See §12 |

---

## 11. Roadmap

### Phase 1 — Restore scanner correctness (blocking)
| # | Task | Effort |
|---|---|---|
| 1 | I-18: persist sandbox authorization so worker revalidation succeeds | M |
| 2 | I-06: narrow Nmap DOCTYPE handling, preserve XXE rejection | S |
| 3 | I-07: enforce Nmap timeout inside the monitor loop | S |
| 4 | I-08: Trivy target typing + `SKIPPED` for website-only scans | M |

### Phase 2 — Make status trustworthy
| # | Task | Effort |
|---|---|---|
| 5 | I-09: ZAP baseline that actually scans (spider + passive + poll) | M |
| 6 | I-12: workflow findings route + JSON 404 for unknown `/api/*` | S |
| 7 | I-10: per-scanner budgets, preserve partial output | S |
| 8 | I-11: real progress or explicit elapsed-time indicator | M |

### Phase 3 — Operational hardening
| # | Task | Effort |
|---|---|---|
| 9 | Local PostgreSQL test profile (removes Supabase ceiling) | S |
| 10 | Per-scanner health endpoint (`/api/scanners/health`) | XS |
| 11 | Browser verification of scan reconnect | S |
| 12 | Deployment documentation and `.env.example` | S |

### Phase 4 — Product completion
| # | Task | Effort |
|---|---|---|
| 13 | PDF report generation | M |
| 14 | AI provider contract tests (timeout, retry, fallback) | S |
| 15 | Container-image and repository Trivy modes | M |

---

## 12. Honest readiness verdict

| Level | Assessment |
|---|---|
| **Demonstrable prototype** | **YES** — the full stack runs, authorizes, orchestrates and displays results |
| **Internally testable** | **YES** — 121/122 tests pass, build is clean |
| **Scanner-accurate** | **NO** — 3 of 5 scanners fail, 1 reports false success |
| **Production-ready** | **NO** — critical correctness and honesty defects remain |

**Statement for the guide:**

> DRISHTI's architecture, authorization model, orchestration, persistence and interface are complete and verified. The remaining work is concentrated in scanner integration correctness: Nmap's XML parser rejects valid output, Trivy is routed an invalid target type, ZAP reports success without scanning, and sandbox authorizations are not persisted so classic scans abort at the authorization step. These are diagnosed to file and line level with reproducible evidence. The system should be presented as a working prototype with a defined remediation plan, not as a finished product.

---

## 13. How to run and demonstrate

```powershell
# Start the stack
docker compose -f D:\drishti\docker-compose.yml up -d

# Verify health
Invoke-RestMethod http://localhost:8000/api/health

# Frontend
#   http://localhost:8000
# API docs
#   http://localhost:8000/api/docs
# ZAP API
#   http://localhost:8080

# Backend tests
cd D:\drishti
.venv\Scripts\python -m pytest tests/ -q

# Frontend build
cd D:\drishti\frontend
npm run build
```

**Suggested demo flow:** open the UI → create and verify a DNS TXT authorization → launch a Unified Recon workflow → show live SSE progress → open findings → show the attack graph and STIX export. Present the scanner matrix alongside it so the guide sees exactly which stages are trustworthy.

---

## 14. Document map

| Document | Contents |
|---|---|
| `docs/PROJECT_STATUS_REPORT.md` | **This document** — consolidated status for the guide |
| `docs/DAILY_ISSUE_REPORT_2026-10-27.md` | Narrative report of the session |
| `docs/project-audit/ERROR_REGISTER.md` | All 18 defects with file-level root causes |
| `docs/project-audit/BUG_FIX_LOG.md` | Every fix with verification evidence |
| `docs/project-audit/IMPLEMENTATION_BASELINE.md` | Environment and configuration snapshot |
| `docs/project-audit/REGRESSION_TEST_RESULTS.md` | Full and focused test runs |
| `docs/project-audit/REMAINING_FEATURES.md` | Prioritised backlog |
| `docs/project-audit/IMPLEMENTATION_PROGRESS.md` | Phase tracker |
| `docs/project-audit/PRODUCTION_READINESS.md` | Readiness checklist |
| `docs/project-audit/TEST_ENVIRONMENT.md` | Database and test configuration |
| `docs/scanner-audit/SCANNER_INTEGRATION_MATRIX.md` | Per-scanner state matrix |
| `docs/UNIFIED_RECON_REPAIR_REPORT.md` | Unified Recon repair report |
| `docs/UNIFIED_RECON_TEST_MATRIX.md` | Unified Recon test matrix |
