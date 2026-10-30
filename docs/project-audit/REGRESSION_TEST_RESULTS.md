# DRISHTI — Regression Test Results

**Run date:** 2026-10-27 · **Compiled:** 2026-10-28
**Interpreter:** `.venv\Scripts\python` (Python 3.12.14)
**Pytest:** 9.1.1 · anyio 4.15.1 · asyncio 1.4.0 (STRICT mode)

---

## 1. Full suite

```
Command: .venv\Scripts\python -m pytest tests/ -q --tb=line
Result:  1 failed, 121 passed, 1 warning in 357.71s (0:05:57)
```

| Metric | Value |
|---|---|
| Collected | 122 |
| Passed | **121** |
| Failed | **1** |
| Skipped | 0 |
| Errors | 0 |
| Warnings | 1 |
| Duration | 5 m 57 s |

### Progression

| Point in time | Passed | Failed | Notes |
|---|---|---|---|
| Session baseline | 114 | 8 | ZAP allow-list, sandbox shadowing, timing, XML contract, Supabase pool |
| After targeted fixes | 121 | 1 | Only the sandbox-authorization defect remains |

---

## 2. The single failure

```
tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence
AssertionError: Scan did not reach completed state within time limit
tests/test_scan_lifecycle.py:55
```

**Reproduced in isolation** (27.83 s) — therefore **not** flaky and **not** ordering-dependent.

**Root cause:** defect **I-18**. The scan row ends as:

```
status: failed
progress: 5
current_step: Validating scope authorization
error_message: Scan rejected: Authorization for 'security-target.io'
               is not active or verified (status: missing).
```

**Mechanism:** `create_scan()` accepts a synthetic sandbox authorization (`auth-sandbox-…`) and stores its id on the scan row; `_run_scan_worker()` then re-reads that id from the database — where it does not exist — and aborts.

**Verdict:** the test is correct. The product is wrong.

---

## 3. Focused runs

| Command | Result |
|---|---|
| `pytest tests/test_phase11_orchestrator.py::test_multi_scanner_workflow_orchestration tests/test_production_chaos.py::test_truncated_xml_graceful_recovery -v` | **2 passed in 21.30 s** |
| `pytest tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence -q` | **1 failed in 27.83 s** (deterministic) |

---

## 4. Warning detail

```
tests/test_dns_verification_autorecon.py::test_api_challenge_endpoints
StarletteDeprecationWarning: 'HTTP_422_UNPROCESSABLE_ENTITY' is deprecated.
Use 'HTTP_422_UNPROCESSABLE_CONTENT' instead.
```

Non-blocking. Should be updated when the Starlette version is next bumped.

---

## 5. Tests recovered during the session

| Test | Previous failure | Fix |
|---|---|---|
| `test_dns_txt_challenge_verification_lifecycle` | sandbox allow-list shadowed DB auth | `clear_sandbox_allowlist` fixture |
| `test_passive_reconnaissance_provenance_and_audit` | narrow source assertion | widened to `active_dns` / `passive_ct` |
| `test_scan_lifecycle_vulnerability_enrichment` | sandbox allow-list shadowing | fixture |
| `test_multi_scanner_workflow_orchestration` | 3 s poll window too short | 6 s window |
| `test_truncated_xml_graceful_recovery` | test demanded a list for unrecoverable input | accepts controlled error |
| Five `test_scan_lifecycle.py` tests | `TooManyConnectionsError` (Supabase) | did not recur this run |

---

## 6. Test integrity statement

- **No assertion was weakened to force a pass.** The two test-side changes (I-04, I-05) align the tests with documented contracts and still assert real behaviour.
- **No test was skipped** to improve the count.
- **The remaining failure was not suppressed.** It is reported as a product defect.
- **Mocked tests are not treated as proof that a scanner works.** Scanner readiness is judged from the live workflow in §7.

---

## 7. What the tests do *not* prove

The suite passes while Nmap, ZAP and Trivy fail in production because those adapters are exercised with **mocked subprocess output**. A green suite is therefore necessary but not sufficient.

| Claim | Proven by tests? | Proven by live run? |
|---|---|---|
| Adapters parse valid fixtures | yes | — |
| Adapters handle malformed input | yes | — |
| Nmap parses **real** Nmap XML | **no** | **no — fails (I-06)** |
| ZAP performs a real scan | **no** | **no — false success (I-09)** |
| Trivy receives a valid target | **no** | **no — fails (I-08)** |
| Nuclei completes within budget | **no** | **no — times out (I-10)** |
| httpx produces real findings | partially | **yes — 3 findings** |

---

## 8. How to reproduce

```powershell
cd D:\drishti

# Full suite
.venv\Scripts\python -m pytest tests/ -q

# Verbose with short tracebacks
.venv\Scripts\python -m pytest tests/ -v --tb=short

# Single failing test
.venv\Scripts\python -m pytest tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence -q

# Inspect the scan rows written by the test
@'
import asyncio
from backend.db.database import init_db, get_db

async def main():
    await init_db()
    async with get_db() as db:
        async with db.execute(
            "SELECT id,target,status,progress,current_step,error_message FROM scans ORDER BY created_at DESC LIMIT 5"
        ) as cur:
            for r in await cur.fetchall():
                print(dict(r))
asyncio.run(main())
'@ | .venv\Scripts\python -
```

**Environment note:** the suite reads `DATABASE_URL` from `.env`, which currently targets remote Supabase. See `TEST_ENVIRONMENT.md` before running in CI.
