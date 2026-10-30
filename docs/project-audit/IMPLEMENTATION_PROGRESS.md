# DRISHTI — Implementation Progress

**Compiled:** 2026-10-28 · **Evidence window:** 2026-10-27
**Status vocabulary:** PASS · PARTIAL · FAIL · MISSING · BLOCKED · NOT VERIFIED

---

## 1. Overall position

| Dimension | Status | Note |
|---|---|---|
| Architecture & scaffolding | **PASS** | React + FastAPI + PostgreSQL + Docker |
| Authorization model | **PASS** | DNS TXT lifecycle verified |
| Orchestration | **PASS** | Live workflow executed and finalised |
| Persistence | **PASS** | Findings written and retrieved |
| Interface | **PARTIAL** | Builds clean; reconnect not browser-verified |
| Scanner correctness | **FAIL** | 1 of 5 scanners delivered findings |
| Test suite | **PASS (1 failure)** | 121 / 122 |
| Production readiness | **FAIL** | Critical defects remain |

---

## 2. Phase tracker

### Phase 1 — Foundation
| Item | Status |
|---|---|
| FastAPI application, routing, middleware | **PASS** |
| PostgreSQL pool and SQL adaptation layer | **PASS** |
| Migrations and schema | **PASS** |
| Health endpoint with DB telemetry | **PASS** |
| Docker Compose topology (app, ZAP, Postgres) | **PASS** |

### Phase 2 — Authorization
| Item | Status |
|---|---|
| DNS TXT challenge creation | **PASS** |
| Challenge verification lifecycle | **PASS** |
| Scope boundary enforcement | **PASS** |
| Pre-scan revalidation from DB | **PASS** (control works — but see I-18) |
| Sandbox authorization persistence | **FAIL** (I-18) |
| Audit logging of authorization events | **PASS** |

### Phase 3 — Reconnaissance
| Item | Status |
|---|---|
| Passive DNS, CT logs, RDAP | **PASS** |
| Active DNS enumeration | **PASS** |
| Asset inventory and subdomain discovery | **PASS** |
| Observation provenance | **PASS** |
| Detection and correlation | **PASS** |

### Phase 4 — Scanning
| Item | Status |
|---|---|
| Scanner registry and capability model | **PASS** |
| Stage sequencing and dependency gating | **PASS** |
| Cancellation and recovery | **PASS** |
| Partial-success policy | **PASS** |
| Nmap adapter | **FAIL** (I-06, I-07) |
| httpx adapter | **PASS** |
| ZAP adapter | **FAIL** (I-09) |
| Trivy adapter | **FAIL** (I-08) |
| Nuclei adapter | **PARTIAL** (I-10) |

### Phase 5 — Results & intelligence
| Item | Status |
|---|---|
| Normalized finding schema | **PASS** |
| CVE / EPSS enrichment | **PASS** |
| Deterministic risk scoring | **PASS** |
| Attack-path graph (NetworkX) | **PASS** |
| Vector intelligence (ChromaDB) | **PASS** |
| STIX 2.1 export | **PASS** |
| AI explanation and remediation | **PASS** (offline fallback verified) |

### Phase 6 — Interface
| Item | Status |
|---|---|
| Dashboard, Recon, Intel, Guard, Graph, STIX, Audit, Settings views | **PASS** |
| SSE live progress | **PASS** |
| State persistence across tab switches | **PARTIAL** (fixed, unverified) |
| Fabricated data removed from Recon | **PASS** |
| Production build | **PASS** |
| Per-scanner status display | **MISSING** |

### Phase 7 — Operations
| Item | Status |
|---|---|
| Container health | **PASS** |
| Scanner binaries present | **PASS** |
| ZAP API connectivity (container→container) | **PASS** |
| ZAP host access | **NOT VERIFIED** |
| Local test database profile | **MISSING** |
| Version control | **MISSING** |
| Deployment documentation | **MISSING** |

---

## 3. Session delta (2026-10-27)

| Change | Effect |
|---|---|
| ZAP `config.xml` allow-list | ZAP API reachable from the platform container |
| `clear_sandbox_allowlist` fixture | 3 authorization tests recovered |
| Passive-recon source assertion widened | 1 test recovered |
| Orchestrator poll window 3 s → 6 s | 1 test recovered |
| Chaos test aligned with parser contract | 1 test recovered |
| Recon state persistence + SSE reattach | Tab switching no longer abandons the view |
| Fabricated stage data removed | No invented scan evidence in the UI |
| Broken build repaired | `tsc -b && vite build` passes |

**Test delta:** 114 passed / 8 failed → **121 passed / 1 failed**.

---

## 4. Open work at a glance

| Count | Category |
|---|---|
| 6 | Open failures (I-06, I-07, I-08, I-09, I-12, I-18) |
| 2 | Partial (I-10, I-11) |
| 1 | Blocked (I-16) |
| 1 | Unverified (I-17) |
| 7 | Fixed |

---

## 5. Next milestone

**Milestone: "Trustworthy scanner results"**

Exit criteria — all must hold:

1. A sandbox scan reaches `completed` and persists findings (I-18 fixed).
2. Nmap parses real `nmap -A` XML while still rejecting XXE (I-06 fixed).
3. A stalled Nmap terminates at its configured deadline (I-07 fixed).
4. Trivy is `SKIPPED` for website targets and never receives a hostname as a path (I-08 fixed).
5. ZAP reports `COMPLETED` only after a real scan (I-09 fixed).
6. The full suite passes against a local PostgreSQL instance (I-16 resolved).
7. A live run with all five scanners yields findings from more than one scanner.

Until criterion 7 holds, scanner coverage must not be described as complete.
