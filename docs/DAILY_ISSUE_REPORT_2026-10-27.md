# DRISHTI — Issue Report: 2026-10-27

**Scope:** Unified Recon end-to-end run against an authorized target (`www.curezy.in`), scanner integration audit, test-suite triage, frontend regression.
**Method:** Live workflow inspection, container runtime checks, code tracing, deterministic parser reproduction, frontend production build.
**Verdict vocabulary:** PASS / PARTIAL / FAIL / BLOCKED / NOT VERIFIED

> **Documentation integrity note (read first).** An earlier summary in this session claimed that six files under `docs/project-audit/` had been created. **That was incorrect — the directory is empty.** Only `docs/scanner-audit/SCANNER_INTEGRATION_MATRIX.md` existed, and it overstated readiness (it marked all five scanners as working while the live run shows Nmap and Trivy failing). This report supersedes those claims and is based only on reproducible evidence.

---

## 1. Executive summary

| # | Issue | Area | Status |
|---|-------|------|--------|
| I-01 | ZAP API rejected requests from the DRISHTI container | ZAP | **PASS** (fixed) |
| I-02 | `SANDBOX_ALLOWLIST` shadowed real DB authorizations in tests | Test env | **PASS** (fixed) |
| I-03 | Passive-recon source assertion too narrow | Tests | **PASS** (fixed) |
| I-04 | Orchestrator test poll window too short | Tests | **PASS** (fixed) |
| I-05 | Truncated-XML chaos test expected the wrong contract | Tests | **PASS** (fixed) |
| I-06 | **Valid Nmap XML rejected — parser rejects real scans** | Nmap | **FAIL** |
| I-07 | **Nmap has no effective timeout when cancellation is wired** | Nmap | **FAIL** |
| I-08 | **Trivy treats a hostname as a filesystem path** | Trivy | **FAIL** |
| I-09 | **ZAP reports `COMPLETED` without performing a scan** | ZAP | **FAIL** |
| I-10 | Nuclei exceeds the 120 s stage budget | Nuclei | **PARTIAL** |
| I-11 | Stage progress is a fixed placeholder, not real progress | Orchestrator | **PARTIAL** |
| I-12 | Workflow findings endpoint does not exist (returns HTML 200) | API | **FAIL** |
| I-13 | Recon view lost all state on tab switch | Frontend | **PARTIAL** (fixed, unverified in browser) |
| I-14 | UI displayed fabricated stage durations and finding counts | Frontend | **PASS** (fixed) |
| I-15 | Frontend build was broken by an incomplete edit | Frontend | **PASS** (fixed) |
| I-16 | Supabase connection ceiling blocks integration tests | Test env | **BLOCKED** (did not recur) |
| I-17 | ZAP host-port access from Windows never confirmed | ZAP | **NOT VERIFIED** |
| I-18 | **Sandbox authorization is not persisted, so the worker rejects its own scan** | Authorization | **FAIL** |

**Bottom line:** the orchestration *plumbing* works — a workflow was created, authorized, executed, persisted and finalized as `partially_completed`. But **three of the five scanners did not produce usable results**, and two of those failures are silent or misreported. The system is not ready to be described as "all scanners operational".

---

## 2. Live end-to-end run — observed evidence

Workflow: `wf-1793120244-www-curezy-in`, target `www.curezy.in`, all five scanners requested.

| Stage | Status | Duration | Findings | Error / note |
|-------|--------|----------|----------|--------------|
| nmap | **failed** | **1107.11 s** | 0 | `XML containing DTD / External Entities is strictly rejected for security.` |
| httpx | completed | 2.89 s | 3 | — |
| zap | completed | **0.74 s** | 0 | Suspiciously fast — see I-09 |
| trivy | **failed** | 0.05 s | 0 | `Target validation rejected: Target path does not exist: /app/www.curezy.in` |
| nuclei | **failed** | 120.27 s | 0 | `Scan execution exceeded timeout of 120s` |

Final workflow state: `partially_completed`, progress 100, step `Workflow orchestration finalized`.

**What this proves**
- Authorization was enforced and the workflow executed end-to-end.
- Partial-success policy worked: one failing scanner did not erase httpx's 3 findings.
- The UI's "stuck at 5 %" was **not a hang** — the first stage (nmap) genuinely ran for 18.5 minutes while overall progress is only written at stage boundaries (I-11).

---

## 3. Detailed findings

### I-06 — Valid Nmap XML is rejected (FAIL, highest impact)

**Symptom:** every real Nmap stage fails after the scan itself succeeds. The XML is produced correctly, then discarded.

**Root cause:** `backend/services/nmap_parser.py:40-44`

```python
xml_lower = xml_content.lower()
if "<!entity" in xml_lower or "<!doctype" in xml_lower:
    if "system" in xml_lower or "public" in xml_lower or "%" in xml_lower:
        raise NmapXMLParsingError("XML containing DTD / External Entities is strictly rejected for security.")
```

The second condition scans the **entire document** for the substrings `system`, `public` and `%`. Real `nmap -A` output almost always contains at least one of them — for example a TLS certificate issuer of `Public CA`, a banner containing `system`, or a `%` in script output.

**Reproduced deterministically** (sanitized fixture, no network):

| Fixture | Result |
|---------|--------|
| Valid Nmap XML with `<!DOCTYPE nmaprun>` and no cert text | **PARSED** (1 host) |
| Valid Nmap XML with `<!DOCTYPE nmaprun>` + `<script id="ssl-cert" output="subject=CN=app.local; issuer=CN=Public CA"/>` | **REJECTED** |
| XML with `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | **REJECTED** (correct) |

**Conclusion:** the rejection is caused by incidental document *content*, not by the DOCTYPE itself. The standard `<!DOCTYPE nmaprun>` alone parses fine.

**Required fix (not yet applied):** stop scanning the whole document. Strip or neutralise only the exact literal declaration `<!DOCTYPE nmaprun>` before parsing, and reject any *other* DOCTYPE or `<!ENTITY` occurrence. Keep entity expansion and external DTD resolution disabled. XXE rejection must remain intact.

**Impact:** Nmap contributes zero findings on every real scan, and burns the full scan budget doing it.

---

### I-07 — Nmap timeout is never enforced when a cancel event exists (FAIL, safety)

**Root cause:** `backend/services/nmap_adapter.py:380-403`

```python
wait_task = asyncio.create_task(proc.communicate())
if cancel_event:
    while not wait_task.done():          # <-- no deadline in this loop
        if cancel_event.is_set():
            ...
        await asyncio.sleep(0.2)

stdout_bytes, stderr_bytes = await asyncio.wait_for(wait_task, timeout=float(timeout_seconds))
```

When `cancel_event` is supplied — and the orchestrator **always** supplies one (`scan_orchestrator.py:578-618`) — execution is governed solely by the `while` loop. The `asyncio.wait_for(..., timeout=...)` on the next line is only reached *after* the process has already exited, so it can never fire.

**Evidence:** the orchestrator passes `timeout=120` (`scan_orchestrator.py:571`), yet the stage ran **1107.11 s**. A 120 s budget was exceeded by a factor of 9 with no timeout event.

**Contrast:** `nuclei_adapter.py:366-393` performs the deadline check *inside* the monitoring loop and terminated correctly at 120 s. Nmap is the outlier.

**Impact:** any slow or hanging Nmap run can occupy a worker indefinitely; the documented timeout guarantee is not real for the most-used scanner.

---

### I-08 — Trivy receives a hostname and treats it as a local path (FAIL)

**Symptom:** `Target validation rejected: Target path does not exist: /app/www.curezy.in` after 0.05 s.

**Root cause chain:**
1. `scan_orchestrator.py:600-608` calls the Trivy adapter with the workflow `target` (`www.curezy.in`) and `ScanProfile.TRIVY_FULL_LOCAL`.
2. `trivy_adapter.py:186` does `target_path = Path(clean).resolve()`. Relative to the process CWD (`/app`), the hostname becomes `/app/www.curezy.in`.
3. `trivy_adapter.py:195-196` rejects it because the path does not exist.

**Missing capability:** the orchestrator's eligibility gate (`scan_orchestrator.py:322-345`) only checks *availability* and *dependency*. There is **no target-type check**, so a web target is unconditionally routed to a filesystem scanner.

**Required fix (not yet applied):** introduce explicit target typing (`filesystem` / `image` / `repository` / `website`). For a website-only workflow, mark Trivy `SKIPPED` with a reason (`No filesystem/image/repository target configured`) rather than running it and failing. Never derive a filesystem path from a hostname.

---

### I-09 — ZAP reports `COMPLETED` without performing a scan (FAIL, false success)

**Evidence:** the ZAP stage finished in **0.74 s** with 0 findings against a live website.

**Root cause:** `backend/services/zap_adapter.py:244-294`. In `ZAP_BASELINE_AUDIT` mode the adapter:
1. calls `accessUrl` once (a single HTTP fetch performed by ZAP),
2. immediately queries `/JSON/core/view/alerts/`,
3. returns `ScannerExecutionState.COMPLETED` unconditionally.

There is no spider, no passive-scan wait, no polling of scan progress, and no check that any scanning actually occurred. The only failure paths are transport exceptions.

**Why this matters:** a `completed` stage with 0 findings is currently indistinguishable from "ZAP never analysed the target". The user's requirement — *"a completed scanner with zero findings must be distinguishable from a scanner that failed or returned invalid output"* — is not met for ZAP.

**Required fix (not yet applied):** either implement a real baseline (spider + passive scan + poll `scan/view/status` until completion) or introduce an explicit `NO_FINDINGS` vs `NOT_SCANNED` distinction with the reason surfaced to the UI.

---

### I-10 — Nuclei exceeds the 120 s stage budget (PARTIAL)

**Evidence:** `Scan execution exceeded timeout of 120s` after 120.27 s.

**Assessment:** this is **not** a hang or a lifecycle defect. `nuclei_adapter.py:366-393` checks both cancellation and the deadline inside its monitoring loop, terminates the process, and the stage reached a terminal state promptly. The workflow then finalised correctly.

**Actual defects:**
1. The 120 s budget (`scan_orchestrator.py:571`) is too small for a template-based scan of a real host. Either the budget must be configurable per scanner or the template set must be constrained.
2. Zero partial results were preserved — a timed-out run that produced output before the deadline reported 0 findings.

**Status:** lifecycle handling **PASS**, capacity and partial-output handling **FAIL**.

---

### I-11 — Progress is a placeholder, not work progress (PARTIAL)

**Root cause:**
- `scan_orchestrator.py:271` writes `progress = 5` at start.
- `scan_orchestrator.py:648` sets the stage row to `progress = 10` when it starts and never updates it.
- `scan_orchestrator.py:312-313, 440` advances *overall* progress in fixed chunks (`80 // stage_count`) only **after** a stage completes.

**Consequence:** during the 18.5-minute Nmap stage the overall bar sat at 5 % and the stage bar at 10 %. The user reasonably read this as "stuck". Nothing was stuck.

**Status:** the percentages are not fabricated randomly, but they do not reflect real work. They need either genuine per-scanner progress or an explicit "running, elapsed 18m" indicator instead of a frozen percentage.

---

### I-12 — Workflow findings endpoint is missing and returns HTML 200 (FAIL)

**Symptom:** `Invoke-RestMethod ".../orchestrator/workflows/<id>/findings"` printed an escaped copy of the frontend `index.html`.

**Root cause:**
- No such route exists. `backend/api/scans.py` defines `/findings/all`, `/{scan_id}/findings`, `/{scan_id}/trivy-findings`, `/{scan_id}/nuclei-findings`, `/orchestrator/capabilities`, `/orchestrator/workflows`, `/orchestrator/workflows/{id}`, `.../cancel`, `.../stream` — but **no** `.../workflows/{id}/findings`.
- The SPA catch-all `backend/main.py:101-106` serves `index.html` for any unmatched path.

**Verified:** `HTTP 200`, `content-type: text/html`.

**Why it matters:** a missing API route silently returns a 200 with HTML instead of a 404. Any client that checks `res.ok` will treat the failure as success. This is the same class of bug as a false-positive scanner status.

**Required fix (not yet applied):** add the route (aggregating stage findings by workflow id) and make unmatched `/api/*` paths return a JSON 404 instead of falling through to the SPA.

---

### I-13 — Recon view lost all state when switching tabs (PARTIAL — fixed, unverified)

**Root cause:** `frontend/src/App.tsx` renders views conditionally, so navigating away from Recon unmounts `ReconView`. That closed the `EventSource` and discarded `progress`, `statusText`, `currentScanId` and `orchestratorWorkflow`. The backend kept scanning; the UI simply forgot.

**Fix applied:**
- Persist the active workflow id in `localStorage` (`drishti_active_scan_id`).
- Added `reconnectToWorkflow()` — fetches current workflow state, restores progress/step/target, and re-attaches the SSE stream if the workflow is still active.
- Added `attachWorkflowStream()` so the stream setup is not duplicated.
- Terminal-state set now includes `partially_completed` (previously the spinner never stopped for a partially completed workflow).

**Status:** build passes; **not yet verified in a browser**. The running container still serves the previous bundle, so a rebuild/restart is required.

---

### I-14 — UI displayed fabricated stage data (PASS — fixed)

**Root cause:** `ReconView.tsx` `loadLatestScan()` built a synthetic stage list for the latest scan:

```tsx
{ stage_name: 'nmap',  status: 'completed', duration_seconds: 0.8, findings_count: 1, ... }
{ stage_name: 'httpx', status: 'completed', duration_seconds: 0.5, findings_count: 1, ... }
{ stage_name: 'cve_intel', status: 'completed', duration_seconds: 1.1, findings_count: 2, ... }
```

Those durations and counts were invented and rendered next to real data.

**Fix applied:** the view now shows only fields actually persisted by the backend (`stages: []`), so no invented scan evidence is displayed.

---

### I-15 — Frontend build was broken (PASS — fixed)

`npm run build` failed with `src/views/ReconView.tsx(101,7): error TS2304: Cannot find name 'reconnectToWorkflow'` — a reference introduced without its definition.

**Fix applied:** implemented `reconnectToWorkflow` and `attachWorkflowStream`.
**Verification:** `tsc -b && vite build` → `✓ 46 modules transformed`, `built in 473ms`.

---

### I-16 — Supabase connection ceiling blocks integration tests (BLOCKED)

`.env` points `DATABASE_URL` at a **remote Supabase** instance. The free tier enforces a low concurrent-connection limit, and each test module opens its own pool, producing `asyncpg.exceptions.TooManyConnectionsError`.

Affected: five `tests/test_scan_lifecycle.py` tests plus one passive-recon provenance test.

**Mitigation:** run the suite against the local Postgres service (the Docker stack already reports `supabase: false`, i.e. it uses the local instance and is unaffected at runtime).

---

### I-17 — ZAP host access unconfirmed (NOT VERIFIED)

Container-to-container access is proven (`{"version":"2.17.0"}`). Access from the Windows host on `localhost:8080` was never successfully demonstrated — PowerShell `Invoke-WebRequest` failed with connection errors. The port mapping should work; it has not been confirmed.

---

### I-18 — Sandbox authorization is not persisted, so the worker rejects its own scan (FAIL)

**This is the real cause of the "stuck at 5 %" report.**

**Observed:** scans created through `POST /api/scans` sit at `progress = 5`, `current_step = Validating scope authorization`, then flip to `failed`:

```
Scan rejected: Authorization for 'security-target.io' is not active or verified (status: missing).
```

**Root cause — two authorization paths that disagree:**

1. `create_scan()` (`scanner.py:716-728`) calls `get_valid_authorization_for_target()`, which for a sandbox/dev target returns a **synthetic, in-memory** authorization.
2. That synthetic id is written onto the scan row (`scanner.py:731-737`).
3. `_run_scan_worker()` (`scanner.py:167-183`) then deliberately **re-reads the authorization from the database** before any network I/O — a correct security control — and gets `None`, because the synthetic row was never persisted.

**Reproduced:**

```
resolved auth: {'id': 'auth-sandbox-1475b5189147', 'target_domain': 'security-target.io', 'status': 'verified'}
DB lookup by that id: MISSING
```

**Consequence:** every sandbox/dev-mode scan is accepted at creation and killed one step later. The UI shows a frozen 5 % bar because progress is only advanced after authorization succeeds.

**Two distinct "5 %" symptoms — do not conflate them:**

| Path | What happens | Cause |
|------|--------------|-------|
| `POST /api/scans` (classic) | frozen at 5 %, then `failed` | I-18 — synthetic authorization not persisted |
| `POST /api/scans/orchestrator/workflows` | 5 % for ~18 min, then advances | I-11 — progress written only at stage boundaries; Nmap ran 1107 s |

**Recommended fix (not applied — this touches authorization semantics and needs sign-off):** make the sandbox/dev authorization a real persisted row (upsert on resolve) so the worker's revalidation finds it, keeping the DB revalidation control intact. Do **not** fix this by removing the worker's revalidation or by trusting an id passed from the client.

**Note:** this single defect accounts for the only remaining test failure — `tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence`.

---

## 4. Fixes actually verified today

| Fix | Verification |
|-----|--------------|
| ZAP allow-list via mounted `config.xml` | `curl http://zap:8080/JSON/core/view/version/?apikey=***` → `{"version":"2.17.0"}` |
| `clear_sandbox_allowlist` fixture in two test modules | affected authorization tests pass |
| Passive-recon source assertion widened to `active_dns` / `passive_ct` | test passes |
| Orchestrator poll window 30 → 60 iterations | `test_multi_scanner_workflow_orchestration` PASS |
| Chaos test accepts a controlled `NmapXMLParsingError` | `test_truncated_xml_graceful_recovery` PASS |
| Recon state persistence + SSE reattach | production build passes |
| Fabricated stage data removed | production build passes |

---

## 5. What is genuinely working

- **httpx (ProjectDiscovery CLI):** completed in 2.89 s, produced 3 findings — the only scanner to deliver results in the live run.
- **Authorization:** enforced at the workflow boundary; the target was accepted only because a verified DNS TXT authorization existed.
- **Partial-success policy:** a failed stage did not discard another stage's findings; the workflow finalised as `partially_completed`.
- **Persistence & status vocabulary:** stage rows, durations and errors were written and read back accurately.
- **Binaries present in the container:** Nmap 7.95, httpx v1.6.0, Nuclei v3.3.2, Trivy 0.76.1, ZAP 2.17.0.

---

## 6. Prioritised remediation plan

| Priority | Item | Effort | Acceptance |
|----------|------|--------|------------|
| P0 | I-18 Sandbox authorization must be persisted so worker revalidation succeeds | M | sandbox scan reaches `completed`; DB revalidation control preserved; lifecycle test passes |
| P0 | I-06 Nmap DOCTYPE handling — narrow pre-processing, keep XXE rejection | S | valid Nmap XML parses; XXE/entity/malformed/oversized rejected; regression tests added |
| P0 | I-07 Nmap timeout inside the monitoring loop | S | a stalled process terminates at the configured deadline with `TIMED_OUT` |
| P0 | I-08 Trivy target typing + `SKIPPED` for website-only scans | M | hostname never becomes a path; skipped stage has a reason and does not fail the workflow |
| P1 | I-09 ZAP baseline really scans (spider + passive + poll) | M | `COMPLETED` only after a scan; zero-findings distinguishable from not-scanned |
| P1 | I-12 workflow findings route + JSON 404 for `/api/*` | S | endpoint returns findings; unknown API paths return 404 JSON |
| P2 | I-10 Nuclei per-scanner budget + preserve partial output | S | long runs terminate cleanly and keep partial findings |
| P2 | I-11 real progress or explicit elapsed-time indicator | M | no frozen 5 %/10 % during long stages |
| P2 | I-16 local Postgres test profile | S | full suite green without Supabase |
| P3 | I-13 browser verification of reconnect | S | tab switch during a scan resumes progress |
| P3 | I-17 confirm host access to ZAP | XS | `http://localhost:8080` reachable from Windows |

---

## 7. Test suite status

Command: `.venv\Scripts\python -m pytest tests/ -q --tb=line`

### 7.1 Result

```
1 failed, 121 passed, 1 warning in 357.71s (0:05:57)
```

| Metric | Count |
|--------|-------|
| Passed | **121** |
| Failed | **1** |
| Skipped | 0 |
| Warnings | 1 (`StarletteDeprecationWarning: HTTP_422_UNPROCESSABLE_ENTITY`) |
| Total collected | 122 |

**The single failure is a product defect, not an environment problem:**

```
tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence
AssertionError: Scan did not reach completed state within time limit
```

Confirmed deterministic — it also fails when run in isolation (27.83 s). The scan row ends as `failed` at `progress = 5` with `Authorization for 'security-target.io' is not active or verified (status: missing)`. See **I-18**.

**Improvement over the session baseline:** 114 passed / 8 failed → **121 passed / 1 failed**. The seven recovered tests were the ZAP allow-list, the sandbox-allowlist fixture, the passive-recon source assertion, the orchestrator poll window, the truncated-XML contract, and the five scan-lifecycle tests that had been blocked by the Supabase connection ceiling (I-16 did not recur in this run).

**Caveat:** a passing mocked test is not evidence that a scanner works. The live run in §2 remains the authority for scanner readiness, and there Nmap, ZAP and Trivy fail.

---

## 8. Honest readiness statement

DRISHTI's orchestration, authorization, persistence and partial-success handling work. **Scanner result quality does not yet match that plumbing:** Nmap is rejected by its own parser, Trivy is routed an invalid target type, and ZAP reports success without scanning. Until I-06, I-08 and I-09 are fixed, any claim that "all five scanners are operational" is unsupported.

In addition, **the classic `/api/scans` path cannot complete a sandbox scan at all** because of I-18 — it fails at the authorization revalidation step. The orchestrator workflow path is unaffected, which is why the two behave so differently.

**Correction to earlier advice in this session:** the "stuck at 5 %" was diagnosed at the time as a ZAP health-check hang or a stale cancellation flag. That was wrong. The proven cause is I-18 (classic scans) and I-11 (orchestrator scans). Restarting containers would not have fixed either.
