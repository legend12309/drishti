# DRISHTI — Remaining Features & Backlog

**Compiled:** 2026-10-28
**Basis:** defects catalogued in `ERROR_REGISTER.md` plus gaps found during the 2026-10-27 audit.
**Rule:** only work that is not already implemented appears here. Completed items live in `BUG_FIX_LOG.md`.

---

## Priority legend

| Priority | Meaning |
|---|---|
| **P0** | Blocks trustworthy scanning; fix before any demo claiming scanner coverage |
| **P1** | Makes status honest and the API correct |
| **P2** | Operational hardening and developer experience |
| **P3** | Product completeness |

---

## P0 — Scanner correctness (blocking)

### 1. Persist sandbox authorizations (I-18)
- **Problem:** `create_scan()` stores a synthetic `auth-sandbox-…` id; the worker's DB revalidation cannot find it and aborts the scan at 5 %.
- **Approach:** upsert the sandbox authorization as a real row when it is resolved, preserving the worker's "revalidate from DB before network I/O" control.
- **Must not:** remove worker revalidation; trust a client-supplied id; weaken scope checks.
- **Acceptance:** a sandbox scan reaches `completed`; `test_scan_lifecycle_and_findings_persistence` passes; audit log shows a real authorization id.
- **Effort:** M · **Needs sign-off:** yes (authorization semantics)

### 2. Nmap XML DOCTYPE handling (I-06)
- **Problem:** the parser rejects any document containing `system`, `public` or `%` once a DOCTYPE is present, so real `nmap -A` output fails.
- **Approach:** neutralise only the exact literal `<!DOCTYPE nmaprun>`; reject every other DOCTYPE and all `<!ENTITY` declarations; keep external DTD resolution and entity expansion disabled.
- **Acceptance:** valid Nmap XML parses; XXE, entity expansion, malformed, empty, truncated and oversized inputs are rejected or handled gracefully; regression fixtures added.
- **Effort:** S

### 3. Enforce the Nmap timeout (I-07)
- **Problem:** with a cancel event present — always, in orchestration — the monitoring loop has no deadline, so a 120 s budget produced a 1107 s run.
- **Approach:** apply a single deadline inside the loop, matching the pattern already used in `nuclei_adapter.py`.
- **Acceptance:** a stalled process terminates at the configured deadline with `TIMED_OUT`; cancellation still works; no orphaned subprocess.
- **Effort:** S

### 4. Trivy target typing (I-08)
- **Problem:** a hostname is resolved as a filesystem path (`/app/www.curezy.in`).
- **Approach:** introduce explicit target types (`filesystem`, `image`, `repository`, `website`); gate eligibility in the orchestrator; mark `SKIPPED` with a reason for website-only workflows.
- **Acceptance:** a hostname never becomes a path; skipped stages do not fail the workflow; filesystem, image and repository inputs validated by tests.
- **Effort:** M

---

## P1 — Honest status and correct API

### 5. ZAP must actually scan (I-09)
- **Problem:** one `accessUrl` call followed by an alert query returns `COMPLETED`.
- **Approach:** spider + passive scan + poll `scan/view/status` until completion; or introduce an explicit `NOT_SCANNED` state with the reason surfaced.
- **Acceptance:** `COMPLETED` implies a scan occurred; zero-findings is distinguishable from not-scanned.
- **Effort:** M

### 6. Workflow findings endpoint + JSON 404 (I-12)
- **Problem:** the route does not exist and the SPA fallback returns HTML with status 200.
- **Approach:** add `GET /api/scans/orchestrator/workflows/{id}/findings`; return JSON 404 for unmatched `/api/*`.
- **Acceptance:** findings return as JSON; unknown API paths return 404 JSON, never HTML.
- **Effort:** S

### 7. Per-scanner health endpoint
- **Problem:** `/api/health` reports four logical engines but no individual scanner state.
- **Approach:** expose `GET /api/scanners/health` from the existing registry capabilities.
- **Acceptance:** returns `available`, `version`, `error_message` per scanner without leaking secrets.
- **Effort:** XS

### 8. Nuclei budget and partial output (I-10)
- **Problem:** a 120 s budget is too small and output produced before the deadline is discarded.
- **Approach:** configurable per-scanner budgets; preserve partial results and mark them partial.
- **Acceptance:** long runs terminate cleanly and retain findings collected before the deadline.
- **Effort:** S

### 9. Real progress reporting (I-11)
- **Problem:** stage progress is pinned at 10 % and overall progress advances only at stage boundaries.
- **Approach:** emit genuine per-scanner progress, or replace the percentage with elapsed time and the current step while running.
- **Acceptance:** no frozen 5 % / 10 % during long stages.
- **Effort:** M

---

## P2 — Operational hardening

### 10. Local PostgreSQL test profile (I-16)
- **Approach:** `tests/conftest.py` with a session-scoped pool; documented `DATABASE_URL` override.
- **Acceptance:** full suite green without Supabase; no `TooManyConnectionsError`.
- **Effort:** S · See `TEST_ENVIRONMENT.md`

### 11. Browser verification of scan reconnect (I-13)
- **Approach:** rebuild the frontend image, restart the container, switch tabs during an active scan.
- **Acceptance:** returning to Recon resumes progress and stage state.
- **Effort:** S

### 12. Remove legacy `zap.conf`
- **Approach:** delete it or document it as unused; only `zap-config.xml` is read.
- **Acceptance:** no ambiguity about which ZAP config is authoritative.
- **Effort:** XS

### 13. Confirm host access to ZAP (I-17)
- **Approach:** verify `http://localhost:8080` from the Windows host.
- **Acceptance:** documented working URL for demos.
- **Effort:** XS

### 14. Version control
- **Problem:** the repository is not a git repository; there is no change history.
- **Approach:** initialise git, add `.gitignore` (`.env`, `.venv`, `node_modules`, `dist`).
- **Acceptance:** every change reviewable as a diff.
- **Effort:** S

### 15. `.env.example`
- **Approach:** publish variable names with non-secret placeholders only.
- **Acceptance:** a new developer can start the stack without access to real credentials.
- **Effort:** XS

### 16. Deployment documentation
- **Approach:** document Compose topology, ports, volumes, ZAP config, scanner prerequisites and capabilities (`NET_RAW` for Nmap).
- **Effort:** S

---

## P3 — Product completeness

### 17. PDF report generation
- **Approach:** `/api/reports/{scan_id}/pdf` with an executive summary.
- **Effort:** M

### 18. AI provider contract tests
- **Approach:** timeout, retry and fallback coverage for all four providers.
- **Acceptance:** router falls back deterministically and never leaks keys.
- **Effort:** S

### 19. Trivy image and repository modes
- **Approach:** exercise `TRIVY_IMAGE` and repository scanning end-to-end.
- **Acceptance:** each mode verified independently — filesystem success does not imply image success.
- **Effort:** M

### 20. Progress/status contract test
- **Approach:** assert backend status, DB row, SSE payload and frontend display agree.
- **Effort:** S

---

## Explicitly out of scope

- Migrating away from PostgreSQL/Supabase.
- Replacing FastAPI or React.
- Adding new AI providers.
- Real scans against third-party targets during testing.
- Weakening DNS TXT authorization.
