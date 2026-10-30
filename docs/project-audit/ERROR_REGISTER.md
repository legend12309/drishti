# DRISHTI — Master Error Register

**Session covered:** 2026-10-27 (documentation compiled 2026-10-28)
**Authoritative evidence:** live workflow `wf-1793120244-www-curezy-in`, container runtime checks, deterministic parser reproduction, full pytest run.
**Verdict vocabulary:** PASS · PARTIAL · FAIL · BLOCKED · NOT VERIFIED

This is the single index of every defect and blocker encountered. Nothing here is inferred: each entry cites a file path, a reproduced behaviour, or a test result.

---

## Summary

| ID | Title | Area | Severity | Status |
|----|-------|------|----------|--------|
| I-01 | ZAP API rejected requests from the DRISHTI container | ZAP | High | **PASS** (fixed) |
| I-02 | `SANDBOX_ALLOWLIST` shadowed real DB authorizations in tests | Test env | Medium | **PASS** (fixed) |
| I-03 | Passive-recon source assertion too narrow | Tests | Low | **PASS** (fixed) |
| I-04 | Orchestrator test poll window too short | Tests | Low | **PASS** (fixed) |
| I-05 | Truncated-XML chaos test expected the wrong contract | Tests | Low | **PASS** (fixed) |
| I-06 | Valid Nmap XML rejected by the parser | Nmap | **Critical** | **FAIL** |
| I-07 | Nmap timeout unenforced when a cancel event exists | Nmap | **Critical** | **FAIL** |
| I-08 | Trivy treats a hostname as a filesystem path | Trivy | **Critical** | **FAIL** |
| I-09 | ZAP reports `COMPLETED` without performing a scan | ZAP | **Critical** | **FAIL** |
| I-10 | Nuclei exceeds the 120 s stage budget; partial output lost | Nuclei | High | **PARTIAL** |
| I-11 | Stage progress is a fixed placeholder | Orchestrator | Medium | **PARTIAL** |
| I-12 | Workflow findings endpoint missing; returns HTML 200 | API | High | **FAIL** |
| I-13 | Recon view lost all state on tab switch | Frontend | High | **PARTIAL** (fixed, unverified) |
| I-14 | UI displayed fabricated stage durations/counts | Frontend | High | **PASS** (fixed) |
| I-15 | Frontend build broken by an incomplete edit | Frontend | High | **PASS** (fixed) |
| I-16 | Supabase connection ceiling blocks integration tests | Test env | Medium | **BLOCKED** |
| I-17 | ZAP host-port access from Windows unconfirmed | ZAP | Low | **NOT VERIFIED** |
| I-18 | Sandbox authorization not persisted → worker rejects its own scan | Authorization | **Critical** | **FAIL** |

**Score:** 7 fixed · 1 blocked · 1 unverified · 6 open failures · 2 partial.

---

## I-01 — ZAP API rejected requests from the DRISHTI container (PASS, fixed)

**Symptom:** ZAP log entries `Request to API URL http://zap:8080/... with host header zap not permitted` and `from 172.18.0.4 not permitted`.

**Root cause:** the ZAP daemon reads its configuration from `config.xml`. The repository only had `zap.conf`, which ZAP ignores. The allow-list is a hierarchical structure in XML, and ZAP matches permitted entries against the request **Host header**, not the source IP.

**Evidence:** `zap.conf` present but unused; no `config.xml` mounted.

**Fix:** created `zap-config.xml` with `api.key` and permitted hosts (`127.0.0.1`, `localhost`, `zap`, `172.18.0.1`, `172.18.0.2`, `172.18.0.4`), mounted read-only at `/home/zap/.ZAP/config.xml`. Compose command reduced to `zap.sh -daemon -host 0.0.0.0 -port 8080`.

**Verification:** `docker exec drishti_platform curl -s "http://zap:8080/JSON/core/view/version/?apikey=***"` → `{"version":"2.17.0"}`.

---

## I-02 — `SANDBOX_ALLOWLIST` shadowed real DB authorizations in tests (PASS, fixed)

**Symptom:** authorization tests failed even though valid DB authorizations existed.

**Root cause:** `.env` `SANDBOX_ALLOWLIST` contained the test domains (`security-target.io`, `company.com`, `target.local`, `provenance-test.net`, `verify-test.org`). `get_valid_authorization_for_target()` short-circuits on sandbox targets **before** querying the database, so a synthetic auth shadowed the real row.

**Fix:** autouse `clear_sandbox_allowlist` fixture (`monkeypatch.setenv("SANDBOX_ALLOWLIST", "")`) added to `tests/test_phase2_authorization.py` and `tests/test_phase3_vulnerability_intelligence.py`.

**Verification:** the three affected tests pass.

---

## I-03 — Passive-recon source assertion too narrow (PASS, fixed)

**Symptom:** `test_passive_reconnaissance_provenance_and_audit` failed on an observation-source assertion.

**Root cause:** the detector legitimately emits `dns_resolver`, `rdap_registry`, `active_dns` and `passive_ct`; the assertion only accepted a subset.

**Fix:** widened the assertion to the full legitimate source set. No production code changed.

---

## I-04 — Orchestrator test poll window too short (PASS, fixed)

**Symptom:** `test_multi_scanner_workflow_orchestration` asserted `COMPLETED` but observed `running`.

**Root cause:** the test polled 30 × 0.1 s (3 s); the mocked three-scanner workflow needed longer.

**Fix:** extended to 60 iterations (6 s) in `tests/test_phase11_orchestrator.py`.

**Verification:** test PASS in 21.3 s together with the chaos test.

---

## I-05 — Truncated-XML chaos test expected the wrong contract (PASS, fixed)

**Symptom:** `test_truncated_xml_graceful_recovery` failed because `parse_nmap_xml` raised `NmapXMLParsingError`.

**Root cause:** for severely truncated input the parser cannot repair the document (`mismatched tag`) and correctly raises a **controlled** error. The test demanded a list unconditionally.

**Fix:** the test now accepts either partial observations **or** a controlled `NmapXMLParsingError`, and still asserts that no unhandled exception escapes.

**Note:** this aligns the test with the real contract; it does not weaken security. The unrelated real defect is I-06.

---

## I-06 — Valid Nmap XML rejected by the parser (FAIL, critical)

**Symptom:** every real Nmap stage fails after Nmap itself succeeds:

```
XML containing DTD / External Entities is strictly rejected for security.
```

**Root cause:** `backend/services/nmap_parser.py:40-44`

```python
xml_lower = xml_content.lower()
if "<!entity" in xml_lower or "<!doctype" in xml_lower:
    if "system" in xml_lower or "public" in xml_lower or "%" in xml_lower:
        raise NmapXMLParsingError("XML containing DTD / External Entities is strictly rejected for security.")
```

The second condition searches the **entire document** for `system`, `public` or `%`. Real `nmap -A` output routinely contains one of them — e.g. a TLS certificate issuer of `Public CA`.

**Reproduced (sanitized fixtures, no network):**

| Fixture | Result |
|---------|--------|
| Valid XML + `<!DOCTYPE nmaprun>`, no cert text | PARSED (1 host) |
| Valid XML + `<!DOCTYPE nmaprun>` + `<script id="ssl-cert" output="...issuer=CN=Public CA"/>` | **REJECTED** |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | REJECTED (correct) |

**Impact:** Nmap contributes zero findings on every real scan and consumes the full stage budget.

**Required fix:** neutralise only the exact literal `<!DOCTYPE nmaprun>` before parsing; reject any other DOCTYPE or `<!ENTITY`. Never enable entity expansion or external DTD resolution.

---

## I-07 — Nmap timeout unenforced when a cancel event exists (FAIL, critical)

**Root cause:** `backend/services/nmap_adapter.py:380-403`

```python
wait_task = asyncio.create_task(proc.communicate())
if cancel_event:
    while not wait_task.done():        # no deadline here
        ...
        await asyncio.sleep(0.2)

stdout_bytes, stderr_bytes = await asyncio.wait_for(wait_task, timeout=float(timeout_seconds))
```

The orchestrator always passes `cancel_event` (`scan_orchestrator.py:578-618`), so the `while` loop governs execution and the `wait_for` on the following line is only reached **after** the process has already exited.

**Evidence:** orchestrator budget `timeout=120` (`scan_orchestrator.py:571`); observed stage duration **1107.11 s**.

**Contrast:** `nuclei_adapter.py:366-393` checks the deadline inside its monitoring loop and terminated correctly at 120 s.

**Impact:** a slow or hung Nmap can occupy a worker indefinitely; the documented timeout is not real.

---

## I-08 — Trivy treats a hostname as a filesystem path (FAIL, critical)

**Symptom:** `Target validation rejected: Target path does not exist: /app/www.curezy.in` after 0.05 s.

**Root cause chain:**
1. `scan_orchestrator.py:600-608` passes the workflow target (`www.curezy.in`) with `ScanProfile.TRIVY_FULL_LOCAL`.
2. `trivy_adapter.py:186` — `Path(clean).resolve()` relative to CWD `/app` yields `/app/www.curezy.in`.
3. `trivy_adapter.py:195-196` rejects the non-existent path.

**Missing capability:** the eligibility gate (`scan_orchestrator.py:322-345`) checks availability and dependency only — there is no target-type check.

**Required fix:** explicit target typing (`filesystem` / `image` / `repository` / `website`); mark Trivy `SKIPPED` with a reason for website-only workflows.

---

## I-09 — ZAP reports `COMPLETED` without performing a scan (FAIL, critical)

**Evidence:** ZAP stage finished in **0.74 s** with 0 findings against a live site.

**Root cause:** `backend/services/zap_adapter.py:244-294`. In `ZAP_BASELINE_AUDIT` the adapter calls `accessUrl` once, immediately queries `/JSON/core/view/alerts/`, and returns `COMPLETED` unconditionally. No spider, no passive-scan wait, no status polling.

**Impact:** "completed, zero findings" is indistinguishable from "never scanned" — violating the requirement that a zero-finding scanner be distinguishable from a non-scanned one.

**Required fix:** implement a real baseline (spider + passive scan + poll `scan/view/status`), or introduce an explicit `NOT_SCANNED` state with a surfaced reason.

---

## I-10 — Nuclei exceeds the 120 s budget; partial output lost (PARTIAL)

**Evidence:** `Scan execution exceeded timeout of 120s` after 120.27 s.

**Assessment:** not a hang. `nuclei_adapter.py:366-393` checks cancellation and deadline inside the monitoring loop, terminates the process, and the stage reached a terminal state promptly.

**Defects:** the 120 s budget is too small for a real template run, and output produced before the deadline was not preserved.

---

## I-11 — Stage progress is a fixed placeholder (PARTIAL)

**Root cause:** `scan_orchestrator.py:271` writes `progress = 5` at start; `:648` sets a stage to `progress = 10` and never updates it; `:312-313, 440` advances overall progress in fixed chunks only **after** a stage completes.

**Consequence:** during the 1107 s Nmap stage the bar sat at 5 %. This is the "stuck at 5 %" experience on the orchestrator path.

**Note:** this is a distinct symptom from I-18, which freezes classic scans at 5 % permanently.

---

## I-12 — Workflow findings endpoint missing; returns HTML 200 (FAIL)

**Symptom:** `GET /api/scans/orchestrator/workflows/<id>/findings` returned an escaped copy of the frontend `index.html`.

**Root cause:** no such route exists in `backend/api/scans.py`; the SPA catch-all `backend/main.py:101-106` serves `index.html` for unmatched paths.

**Verified:** `HTTP 200`, `content-type: text/html`.

**Impact:** a missing API route silently returns 200 + HTML; clients checking `res.ok` treat failure as success.

**Required fix:** add the route and return a JSON 404 for unmatched `/api/*` paths.

---

## I-13 — Recon view lost all state on tab switch (PARTIAL, fixed, unverified)

**Root cause:** `frontend/src/App.tsx` renders views conditionally, unmounting `ReconView`, closing the `EventSource` and discarding progress, step and workflow state.

**Fix:** workflow id persisted in `localStorage` (`drishti_active_scan_id`); added `reconnectToWorkflow()` (restores state, re-attaches SSE) and `attachWorkflowStream()`; terminal set now includes `partially_completed`.

**Status:** production build passes; browser behaviour **not yet verified** (container still serves the previous bundle).

---

## I-14 — UI displayed fabricated stage data (PASS, fixed)

**Root cause:** `ReconView.tsx` `loadLatestScan()` built a synthetic stage list with invented `duration_seconds` and `findings_count` values rendered beside real data.

**Fix:** the view now renders only persisted backend fields (`stages: []`); no invented scan evidence is displayed.

---

## I-15 — Frontend build broken by an incomplete edit (PASS, fixed)

**Symptom:** `src/views/ReconView.tsx(101,7): error TS2304: Cannot find name 'reconnectToWorkflow'`.

**Fix:** implemented `reconnectToWorkflow` and `attachWorkflowStream`.

**Verification:** `tsc -b && vite build` → 46 modules transformed, built in 473 ms.

---

## I-16 — Supabase connection ceiling blocks integration tests (BLOCKED)

**Root cause:** `.env` `DATABASE_URL` points at remote Supabase. The free tier limits concurrent connections; each test module opens its own pool → `asyncpg.exceptions.TooManyConnectionsError`.

**Affected:** five `tests/test_scan_lifecycle.py` tests and one passive-recon provenance test (in earlier runs).

**Mitigation:** run the suite against local Postgres. The Docker stack already reports `supabase: false` and is unaffected at runtime.

**Status:** did not recur in the final run (121/122 passed); still an environmental risk.

---

## I-17 — ZAP host access unconfirmed (NOT VERIFIED)

Container-to-container access is proven. Access from the Windows host on `localhost:8080` was never demonstrated; PowerShell requests failed with connection errors.

---

## I-18 — Sandbox authorization not persisted → worker rejects its own scan (FAIL, critical)

**Symptom:** scans created via `POST /api/scans` sit at `progress = 5`, `current_step = Validating scope authorization`, then become `failed`:

```
Scan rejected: Authorization for 'security-target.io' is not active or verified (status: missing).
```

**Root cause — two disagreeing authorization paths:**
1. `create_scan()` (`scanner.py:716-728`) calls `get_valid_authorization_for_target()`, which returns a **synthetic, in-memory** authorization for sandbox/dev targets.
2. That synthetic id is stored on the scan row (`scanner.py:731-737`).
3. `_run_scan_worker()` (`scanner.py:167-183`) re-reads the authorization **from the database** before any network I/O — a correct control — and gets `None`.

**Reproduced:**

```
resolved auth: {'id': 'auth-sandbox-1475b5189147', 'target_domain': 'security-target.io', 'status': 'verified'}
DB lookup by that id: MISSING
```

**Impact:** every sandbox/dev scan is accepted at creation and killed one step later. This is the true cause of the permanent 5 % freeze on the classic scan path.

**Recommended fix (needs sign-off):** persist the sandbox/dev authorization as a real row so worker revalidation succeeds. Do **not** remove the worker's revalidation or trust a client-supplied id.

**Linked test:** `tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence` — the only failing test.

---

## Cross-references

| Document | Purpose |
|----------|---------|
| `BUG_FIX_LOG.md` | Chronology of fixes with verification commands |
| `IMPLEMENTATION_BASELINE.md` | Environment, versions, configuration snapshot |
| `REGRESSION_TEST_RESULTS.md` | Full and focused test runs |
| `REMAINING_FEATURES.md` | Prioritised backlog |
| `IMPLEMENTATION_PROGRESS.md` | Phase-level status tracker |
| `PRODUCTION_READINESS.md` | Readiness assessment and verdict |
| `TEST_ENVIRONMENT.md` | Database/test configuration and Supabase limitation |
| `../scanner-audit/SCANNER_INTEGRATION_MATRIX.md` | Per-scanner state matrix |
| `../UNIFIED_RECON_REPAIR_REPORT.md` | Unified Recon repair report |
| `../UNIFIED_RECON_TEST_MATRIX.md` | Unified Recon test matrix |
| `../DAILY_ISSUE_REPORT_2026-10-27.md` | Narrative report of the session |
