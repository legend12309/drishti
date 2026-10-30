# DRISHTI — Production Readiness

**Compiled:** 2026-10-28 · **Evidence window:** 2026-10-27
**Overall verdict:** **NOT PRODUCTION-READY**

---

## 1. Readiness scorecard

| Area | Status | Rationale |
|---|---|---|
| Application startup | **PASS** | `/api/health` → `operational` |
| Database connectivity | **PASS** | PostgreSQL 16.15, pool healthy |
| Authorization enforcement | **PASS** | DNS TXT lifecycle verified |
| Sandbox authorization flow | **FAIL** | I-18 — scans abort at revalidation |
| Orchestration | **PASS** | Live workflow executed end-to-end |
| Partial-success handling | **PASS** | Failed stage did not erase findings |
| Cancellation / recovery | **PASS** | Verified by tests |
| Persistence | **PASS** | Findings written and retrieved |
| SSE streaming | **PASS** | Workflow state streamed |
| Frontend build | **PASS** | 46 modules, 473 ms |
| Backend tests | **PASS (1 failure)** | 121 / 122 |
| Nmap | **FAIL** | Parser rejects valid XML; timeout unenforced |
| ZAP | **FAIL** | Reports success without scanning |
| httpx | **PASS** | 3 findings in the live run |
| Trivy | **FAIL** | Hostname routed as filesystem path |
| Nuclei | **PARTIAL** | Times out; partial output lost |
| Status honesty | **FAIL** | ZAP and progress reporting misrepresent reality |
| API correctness | **FAIL** | Missing route returns HTML 200 |
| Observability | **PARTIAL** | Aggregate health only; no per-scanner endpoint |
| Test environment | **BLOCKED** | Supabase connection ceiling |
| Change traceability | **MISSING** | No version control |
| Deployment documentation | **MISSING** | No runbook |
| Secrets handling | **PASS** | Keys server-side; none exposed in responses |

---

## 2. Blocking defects

| ID | Defect | Why it blocks |
|---|---|---|
| I-18 | Sandbox authorization not persisted | Classic scans cannot complete |
| I-06 | Valid Nmap XML rejected | Nmap yields zero findings |
| I-07 | Nmap timeout unenforced | A worker can be occupied indefinitely |
| I-08 | Trivy hostname→path | Trivy always fails on web targets |
| I-09 | ZAP false success | Results cannot be trusted |
| I-12 | Missing findings route returns HTML 200 | Silent API failure |

---

## 3. Security posture

### Controls verified
| Control | Status |
|---|---|
| DNS TXT authorization required before active scanning | **PASS** |
| Authorization re-validated immediately before network I/O | **PASS** |
| Scope boundary enforcement | **PASS** |
| Subprocess execution via argument arrays (`shell=False`) | **PASS** |
| XXE / entity expansion rejected | **PASS** |
| XML size ceiling (10 MB) | **PASS** |
| Credentials never returned to the frontend | **PASS** |
| Audit logging of authorization and scan events | **PASS** |

### Gaps
| Gap | Risk |
|---|---|
| Sandbox authorizations bypass the DB path | Inconsistent authorization provenance (I-18) |
| `.env` holds live provider keys | Rotation and secret-management discipline required |
| No `.env.example` | Risk of committing real secrets by accident |
| No version control | No review trail; no rollback |
| ZAP API key stored in a mounted config file | Acceptable for dev; use a secret store in production |

---

## 4. Operational gaps

| Gap | Impact | Remedy |
|---|---|---|
| Remote Supabase in tests | Intermittent connection failures | Local PostgreSQL profile |
| No per-scanner health endpoint | Cannot diagnose a scanner from the UI | Add `/api/scanners/health` |
| Container serves pre-fix bundle | Frontend fixes not live | Rebuild and restart |
| ZAP host port unverified | Demo uncertainty | Verify `localhost:8080` |
| No git repository | No audit trail | Initialise git |
| No deployment runbook | Onboarding risk | Write `docs/DEPLOYMENT.md` |

---

## 5. Go / no-go criteria

A production release requires **all** of the following:

| # | Criterion | Current |
|---|---|---|
| 1 | All P0 defects closed | **NO** (4 open) |
| 2 | A live run yields findings from ≥ 3 scanners | **NO** (1 of 5) |
| 3 | Scanner status never reports success without work | **NO** (ZAP) |
| 4 | Full suite passes against a deterministic database | **NO** (1 failure, remote DB) |
| 5 | API returns JSON errors, never HTML, for `/api/*` | **NO** |
| 6 | Version control and review process in place | **NO** |
| 7 | Deployment documentation complete | **NO** |
| 8 | Secrets managed outside the repository | **PARTIAL** |

**Decision: NO-GO for production. GO for guided demonstration as a working prototype.**

---

## 6. Demonstration guidance

If presenting to a guide, frame the work honestly:

**Show as working:**
- Authorization-first design and DNS TXT verification
- Unified Recon orchestration with live SSE progress
- Finding persistence, risk scoring, attack graph, STIX export
- 121/122 tests passing and a clean frontend build

**Show as known-broken, with the diagnosis:**
- Nmap parser rejects valid XML (file and line identified)
- Trivy receives an invalid target type (file and line identified)
- ZAP reports success without scanning (file and line identified)
- Sandbox scans abort at authorization (reproduced with a database query)

**Never claim:** "all five scanners are operational." The evidence contradicts it.

---

## 7. Recommended next actions (in order)

1. Obtain sign-off on the I-18 authorization fix, then implement it.
2. Fix I-06 and I-07 together — both are in the Nmap path.
3. Fix I-08 with explicit Trivy target typing.
4. Fix I-09 so ZAP performs a real baseline.
5. Add the workflow findings route and JSON 404 handling (I-12).
6. Stand up the local PostgreSQL test profile.
7. Rebuild and restart the stack, then re-run the full suite and a live five-scanner workflow.
8. Re-issue this readiness assessment based on that evidence.
