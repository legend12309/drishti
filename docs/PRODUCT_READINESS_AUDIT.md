# DRISHTI — PRODUCT READINESS AUDIT & INTEGRATION GAP ANALYSIS
**Audit Completion Date:** 2026-10-21  
**Auditor Roles:** Principal Platform Architect, QA Lead, AppSec Engineer, DevOps Lead  
**Scope:** Full-stack assessment of Frontend, FastAPI Core, Supabase PostgreSQL, Security Scanners, Attack Graph, Risk Engine, and UI/UX Design System  

---

## 1. Executive Summary

DRISHTI has evolved into a sophisticated, multi-layered cyber defense and attack surface management platform. The codebase exhibits rigorous software engineering practices in its core domain services:
- **87 automated tests passing (100% test pass rate)** covering scanner adapters, safe subprocess execution, graph pathfinding, risk calculation, CVSS mapping, and AI safety guard rails.
- **Production Supabase PostgreSQL 17.11 instance verified active and healthy** with connection pooling (~218ms live latency).
- **Frontend compiles cleanly** under TypeScript and Vite with zero bundle build errors.

However, an objective evaluation of **product readiness for production general availability (GA)** reveals concrete operational and architectural integration gaps. The system is currently at **Release Candidate / Staging Readiness (v1.0.0-rc1)**.

### Primary Gap Summary:
1. **Binary Dependency Isolation:** The AutoRecon orchestration engine (Phase 11) is fully coded and tested via mocked subprocesses, but external CLI binaries (`nmap`, `httpx`, `zap`, `nuclei`, `trivy`) are missing from the host runtime environment, requiring a containerized execution worker strategy.
2. **Frontend Mock Fallback Decoupling:** While backend endpoints exist for all phases, certain frontend components fallback to static fixtures when an active scan or workflow ID is absent in local storage, obscuring live database state.
3. **Database RLS Enforcement:** Backend services communicate with Supabase using direct connection strings; row-level security (RLS) policies for true tenant isolation are defined in SQL migrations but need uniform session context propagation across all endpoints.
4. **PDF Report Generation:** STIX 2.1 JSON and CSV export endpoints are fully functional; PDF executive reporting is currently represented as a client-side print layout rather than a server-side headless document generator.

---

## 2. Feature & Implementation Matrix

| Module / Feature | Implemented in Code | Backend Endpoint Verified | DB Model Verified | Frontend Integrated | Real-world Usable | Readiness Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phase 0: Supabase PostgreSQL Persistence** | Yes | Yes (`/health`) | Yes (Schema v1.0) | Yes | Yes | **PRODUCTION READY** |
| **Phase 1: Operator Auth & JWT Management** | Yes | Yes (`/api/auth/*`) | Yes (`users`) | Yes | Partial (Needs refresh loop) | **BETA READY** |
| **Phase 2: Target Scope & RFC 8655 DNS Challenge**| Yes | Yes (`/api/authorizations/*`) | Yes (`targets`) | Yes | Yes (DNS dependent) | **PRODUCTION READY** |
| **Phase 3: Attack Graph & Lateral Pathfinding** | Yes | Yes (`/api/graph/*`) | Yes (`assets`, `edges`) | Yes (Canvas) | Yes | **PRODUCTION READY** |
| **Phase 4: Vulnerability & CVE Intelligence Engine**| Yes | Yes (`/api/findings/*`) | Yes (`findings`) | Yes | Yes | **PRODUCTION READY** |
| **Phase 5: AI Copilot & 3-Layer Guard Engine** | Yes | Yes (`/api/chat/*`) | Yes (`audit_logs`) | Yes (Drawer) | Yes (Offline fallback) | **PRODUCTION READY** |
| **Phase 6: Safe Subprocess Scanner Foundation** | Yes | Yes (Adapters) | N/A (Internal) | N/A | Yes | **PRODUCTION READY** |
| **Phase 7: ProjectDiscovery httpx Adapter** | Yes | Yes (`/api/scans/httpx`) | Yes (`scans`) | Yes | Requires CLI binary | **STAGING READY** |
| **Phase 8: OWASP ZAP API Adapter** | Yes | Yes (`/api/scans/zap`) | Yes (`scans`) | Yes | Requires ZAP Daemon | **STAGING READY** |
| **Phase 9: Aqua Security Trivy Adapter** | Yes | Yes (`/api/scans/trivy`) | Yes (`scans`) | Yes | Requires Trivy binary | **STAGING READY** |
| **Phase 10: ProjectDiscovery Nuclei Adapter** | Yes | Yes (`/api/scans/nuclei`) | Yes (`scans`) | Yes | Requires Nuclei binary| **STAGING READY** |
| **Phase 11: AutoRecon Unified Orchestrator** | Yes | Yes (`/api/scans/orchestrator/*`)| Yes (`workflows`) | Yes | Requires CLI binaries | **STAGING READY** |
| **Reporting: STIX 2.1 & CSV Export** | Yes | Yes (`/api/reports/*`) | Yes | Yes | Yes | **PRODUCTION READY** |
| **Reporting: Executive PDF Generation** | Partial | No (Client layout) | No | UI Only | Incomplete | **ALPHA / MOCK** |
| **UI/UX: Lavender & Red/Dark SaaS Theme** | Yes | N/A | N/A | Yes | Yes | **PRODUCTION READY** |

---

## 3. Route-to-Backend Architecture Mapping

```mermaid
graph TD
    subgraph Frontend Routes
        R_D["/dashboard"] --> F_D["DashboardView"]
        R_T["/targets"] --> F_T["TargetsView"]
        R_S["/scans"] --> F_S["ScansView / AutoRecon"]
        R_V["/vulnerabilities"] --> F_V["VulnerabilitiesView"]
        R_G["/attack-graph"] --> F_G["AttackGraphView"]
        R_R["/reports"] --> F_R["ReportsView"]
        R_SET["/settings"] --> F_SET["SettingsView"]
    end

    subgraph FastAPI Endpoints
        EP_H["GET /health"]
        EP_A["POST /api/auth/login"]
        EP_TG["GET/POST /api/authorizations/challenge"]
        EP_SC["POST /api/scans/orchestrator/workflows"]
        EP_STR["GET /api/scans/orchestrator/workflows/{id}/stream"]
        EP_CAP["GET /api/scans/orchestrator/capabilities"]
        EP_FN["GET /api/findings"]
        EP_GP["GET /api/graph/topology"]
        EP_AI["POST /api/chat/completions"]
        EP_RP["GET /api/reports/stix2, csv"]
    end

    subgraph Data & Execution Tier
        DB[("Supabase PostgreSQL 17.11")]
        SUBPROC["Safe Subprocess Sandbox"]
        AI_ENG["3-Layer AI Guard & LLM"]
    end

    F_D --> EP_H
    F_D --> EP_FN
    F_T --> EP_TG
    F_S --> EP_SC
    F_S --> EP_STR
    F_S --> EP_CAP
    F_V --> EP_FN
    F_G --> EP_GP
    F_R --> EP_RP

    EP_TG --> DB
    EP_SC --> DB
    EP_SC --> SUBPROC
    EP_FN --> DB
    EP_GP --> DB
    EP_AI --> AI_ENG
```

---

## 4. In-Depth Integration Gap Analysis

### 4.1 Scanner Binary Availability vs Containerized Workers
- **Current Architecture:** Backend runs on the developer host machine and attempts to resolve CLI binaries directly from Windows system PATH or hardcoded environment paths (e.g. `nmap.exe`, `httpx.exe`, `nuclei.exe`).
- **Gap:** In standard cloud staging or developer environments, installing 5 disparate security scanners natively on Windows is error-prone.
- **Remediation Recommendation:** Decouple scanner execution into a dedicated asynchronous Celery/Redis worker running inside a specialized Docker container (`sec-scanners-sandbox`), communicating with the FastAPI core via a task queue or webhook.

### 4.2 Frontend Mock Decoupling
- **Current Architecture:** When the frontend is opened without an active scan selected or when API responses are empty, several views fall back to static fixtures to ensure the visual UI renders smoothly.
- **Gap:** Testers may confuse mock demonstration data with live database records.
- **Remediation Recommendation:** Implement an explicit "Demo / Mock Data Toggle" banner in the header when mock fallbacks are active, and ensure live empty states (e.g. "No scans launched yet. Click here to launch your first assessment.") are cleanly presented when connected to an empty database.

### 4.3 Database RLS Context
- **Current Architecture:** Asyncpg connection pool connects using the direct PostgreSQL database connection string, executing parameterized queries securely.
- **Gap:** Multi-tenant RLS policies created in Supabase SQL rely on `auth.uid()` or session claim variables that must be explicitly set on each checked-out connection via `SET LOCAL role` or `SET LOCAL request.jwt.claim`.
- **Remediation Recommendation:** Add an asyncpg connection context manager that injects the validated user ID claim into transaction local storage prior to executing tenant queries.

---

## 5. Release Gate Evaluation

| Release Gate | Criteria | Status | Verdict |
| :--- | :--- | :---: | :---: |
| **Gate A: Automated Tests** | >95% passing unit & integration tests, clean lint | 87/87 passed (100%) | **PASSED** |
| **Gate B: Frontend Build** | Zero compile errors, asset bundle under size limit | Clean Vite build (252 KB gzip) | **PASSED** |
| **Gate C: Database Health** | Live connection, migration parity, active pool | Supabase PostgreSQL 17.11 connected | **PASSED** |
| **Gate D: Scanner Execution** | Live execution of all 5 security scanners | Missing local CLI binaries on Windows | **BLOCKED (Needs Docker Worker)** |
| **Gate E: Security & Guard** | SSRF prevention, RFC 8655 challenge, AI Guard | L1-L3 Guard and SSRF filters verified | **PASSED** |

---

## 6. Prioritized Action Roadmap

```mermaid
flowchart TD
    subgraph Milestone 1: Scanner Containerization (P0)
        M1_1["Build Dockerfile with Nmap, Httpx, Nuclei, Trivy, ZAP"]
        M1_2["Implement Docker execution runner / Celery task worker"]
        M1_3["Verify live AutoRecon stage progression in container"]
    end

    subgraph Milestone 2: UI Real-State Hardening (P1)
        M2_1["Add live vs mock mode visual indicator"]
        M2_2["Refine empty states for fresh tenant databases"]
        M2_3["Implement token auto-refresh loop in axios/fetch client"]
    end

    subgraph Milestone 3: Reporting & Compliance (P2)
        M3_1["Implement headless Chromium / Weasyprint server-side PDF generator"]
        M3_2["Automate scheduled recurring scan orchestrator"]
    end

    M1_1 --> M1_2 --> M1_3
    M1_3 --> M2_1 --> M2_2 --> M2_3
    M2_3 --> M3_1 --> M3_2
```
