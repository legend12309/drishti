# DRISHTI — Audit Documentation Index

**Compiled:** 2026-10-28
**Evidence window:** 2026-10-27
**Overall status:** Functional prototype · **not production-ready**

This folder contains the complete, evidence-backed record of the platform's current state. Every claim traces to a file path, a reproduced behaviour, or a test result.

---

## Start here

| Order | Document | Read it for |
|---|---|---|
| 1 | [`../PROJECT_STATUS_REPORT.md`](../PROJECT_STATUS_REPORT.md) | **The guide-facing consolidated report** — aim, problem, solution, stack, status |
| 2 | [`ERROR_REGISTER.md`](ERROR_REGISTER.md) | Every defect (I-01 … I-18) with root cause and file reference |
| 3 | [`REGRESSION_TEST_RESULTS.md`](REGRESSION_TEST_RESULTS.md) | 121/122 tests, the single failure, and what tests do *not* prove |
| 4 | [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Go/no-go assessment |

---

## Full inventory

| Document | Purpose | Status |
|---|---|---|
| [`ERROR_REGISTER.md`](ERROR_REGISTER.md) | Master list of all 18 defects and blockers | Current |
| [`BUG_FIX_LOG.md`](BUG_FIX_LOG.md) | Every fix with verification evidence | Current |
| [`IMPLEMENTATION_BASELINE.md`](IMPLEMENTATION_BASELINE.md) | Environment, versions, configuration snapshot | Current |
| [`REGRESSION_TEST_RESULTS.md`](REGRESSION_TEST_RESULTS.md) | Full and focused test runs | Current |
| [`REMAINING_FEATURES.md`](REMAINING_FEATURES.md) | Prioritised backlog (P0–P3) | Current |
| [`IMPLEMENTATION_PROGRESS.md`](IMPLEMENTATION_PROGRESS.md) | Phase-by-phase tracker | Current |
| [`PRODUCTION_READINESS.md`](PRODUCTION_READINESS.md) | Readiness scorecard and go/no-go | Current |
| [`TEST_ENVIRONMENT.md`](TEST_ENVIRONMENT.md) | Database configuration, Supabase limitation, local PG profile | Current |

## Related documents outside this folder

| Document | Purpose |
|---|---|
| [`../DAILY_ISSUE_REPORT_2026-10-27.md`](../DAILY_ISSUE_REPORT_2026-10-27.md) | Narrative session report |
| [`../scanner-audit/SCANNER_INTEGRATION_MATRIX.md`](../scanner-audit/SCANNER_INTEGRATION_MATRIX.md) | Per-scanner state matrix |
| [`../UNIFIED_RECON_REPAIR_REPORT.md`](../UNIFIED_RECON_REPAIR_REPORT.md) | Unified Recon root-cause report |
| [`../UNIFIED_RECON_TEST_MATRIX.md`](../UNIFIED_RECON_TEST_MATRIX.md) | 43-row test matrix with verdicts |

---

## Headline numbers

| Metric | Value |
|---|---|
| Backend tests | **121 passed / 1 failed** (122 total, 5 m 57 s) |
| Frontend build | **PASS** — 46 modules, 473 ms |
| Live five-scanner run | **1 of 5 scanners delivered findings** |
| Open critical defects | **6** |
| Fixed this session | **7** |
| Blocked | **1** (Supabase connection ceiling) |
| Unverified | **1** (ZAP host access) |

---

## Defect quick reference

| ID | Defect | Status |
|---|---|---|
| I-01 | ZAP API allow-list rejected container requests | Fixed |
| I-02 | `SANDBOX_ALLOWLIST` shadowed DB authorizations in tests | Fixed |
| I-03 | Passive-recon source assertion too narrow | Fixed |
| I-04 | Orchestrator poll window too short | Fixed |
| I-05 | Truncated-XML test expected the wrong contract | Fixed |
| I-06 | Valid Nmap XML rejected | **Open** |
| I-07 | Nmap timeout unenforced | **Open** |
| I-08 | Trivy hostname treated as filesystem path | **Open** |
| I-09 | ZAP reports `COMPLETED` without scanning | **Open** |
| I-10 | Nuclei exceeds budget; partial output lost | Partial |
| I-11 | Progress is a fixed placeholder | Partial |
| I-12 | Workflow findings endpoint missing (HTML 200) | **Open** |
| I-13 | Recon view lost state on tab switch | Fixed, unverified |
| I-14 | UI displayed fabricated stage data | Fixed |
| I-15 | Frontend build broken | Fixed |
| I-16 | Supabase connection ceiling | Blocked |
| I-17 | ZAP host access unconfirmed | Unverified |
| I-18 | Sandbox authorization not persisted | **Open** |

---

## Conventions

- **PASS** — demonstrated by runtime evidence or a passing test.
- **PARTIAL** — works with a known limitation.
- **FAIL** — does not meet the requirement.
- **BLOCKED** — cannot be verified until an external condition changes.
- **NOT VERIFIED** — no evidence either way; never assumed to work.

A green test suite is **not** treated as proof that a scanner works. Scanner readiness is judged from the live workflow.
