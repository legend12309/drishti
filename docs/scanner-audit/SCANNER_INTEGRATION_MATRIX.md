# DRISHTI Scanner Integration Matrix

**Last verified:** 2026-10-27 against workflow `wf-1793120244-www-curezy-in` (target `www.curezy.in`, all five scanners requested).
**Rule applied:** a state is only marked ✅ when it was demonstrated by runtime evidence or a passing test — never because adapter code or a config entry exists.

| Scanner | IMPLEMENTED | REGISTERED | INSTALLED | CONFIGURED | AVAILABLE | CONNECTIVITY_VERIFIED | PARSE_VERIFIED | PERSISTENCE_VERIFIED | END_TO_END_VERIFIED | READY |
|---|---|---|---|---|---|---|---|---|---|---|
| **Nmap** | ✅ | ✅ | ✅ 7.95 | ✅ | ✅ | ✅ (local subprocess) | ❌ **valid XML rejected** | ⚠️ only on fixtures | ❌ | ❌ **FAIL** |
| **OWASP ZAP** | ✅ | ✅ | ✅ 2.17.0 (container) | ✅ (key + allow-list) | ✅ | ✅ container→container | ✅ (alert parser) | ✅ | ❌ **no scan performed** | ❌ **FAIL** |
| **httpx (PD CLI)** | ✅ | ✅ | ✅ v1.6.0 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ 3 findings in 2.89 s | ✅ **PASS** |
| **Nuclei** | ✅ | ✅ | ✅ v3.3.2 | ⚠️ budget too small | ✅ | ✅ | ✅ | ✅ | ⚠️ timeout at 120 s | ⚠️ **PARTIAL** |
| **Trivy** | ✅ | ✅ | ✅ 0.76.1 | ⚠️ no target typing | ✅ | ✅ | ✅ | ✅ | ❌ **hostname routed as path** | ❌ **FAIL** |

**Legend:** ✅ verified · ⚠️ partial / works with a known limitation · ❌ fails or not demonstrated

---

## Live run evidence

| Stage | Status | Duration | Findings | Error |
|---|---|---|---|---|
| nmap | failed | 1107.11 s | 0 | `XML containing DTD / External Entities is strictly rejected for security.` |
| httpx | completed | 2.89 s | 3 | — |
| zap | completed | 0.74 s | 0 | none — but no scan was actually run |
| trivy | failed | 0.05 s | 0 | `Target path does not exist: /app/www.curezy.in` |
| nuclei | failed | 120.27 s | 0 | `Scan execution exceeded timeout of 120s` |

Workflow finalised as `partially_completed` at 100 %.

---

## Per-scanner detail

### Nmap — FAIL
- **Binary:** `nmap 7.95` inside `drishti_platform`. ✅
- **Command contract:** `nmap -Pn -A -T2 -oX - <target>` (`nmap_adapter.py:170-173`). `-A` is intrusive (OS detection, version probes, NSE default scripts) and must only run under an approved policy.
- **Blocking defect 1:** `nmap_parser.py:40-44` rejects any document containing the substrings `system`, `public` or `%` once a DOCTYPE is present. Valid output containing a TLS issuer of `Public CA` is rejected; the same XML without that word parses. XXE is still correctly rejected.
- **Blocking defect 2:** `nmap_adapter.py:380-403` applies its timeout only *after* the process exits when a cancel event is present, so the 120 s budget is unenforced — observed runtime 1107 s.
- **Not verified:** end-to-end findings, because parsing never succeeds.

### OWASP ZAP — FAIL
- **Service:** `ghcr.io/zaproxy/zaproxy:stable`, API `2.17.0`, reachable from the DRISHTI container with API-key auth. ✅
- **Config:** allow-list and `api.key` in `zap-config.xml`, mounted at `/home/zap/.ZAP/config.xml`. ✅
- **Defect:** `zap_adapter.py:244-294` calls `accessUrl` once, immediately reads alerts, and returns `COMPLETED` with no spider, no passive-scan wait and no status polling. The 0.74 s / 0 findings result therefore proves nothing about the target.
- **Host access:** `localhost:8080` from Windows — **NOT VERIFIED**.

### httpx (ProjectDiscovery CLI) — PASS
- **Binary:** v1.6.0, distinct from the Python `httpx` library. ✅
- **Evidence:** completed in 2.89 s with 3 findings, the only stage to produce results.
- **Note:** `httpx -version` exits non-zero by design; exit code alone is not a health signal.

### Nuclei — PARTIAL
- **Binary:** v3.3.2, templates directory configured. ✅
- **Lifecycle:** cancellation and deadline are checked inside the monitoring loop; the process was terminated at 120 s and the stage reached a terminal state. ✅
- **Limitation:** the 120 s stage budget is too small for a full template run, and output produced before the deadline was not preserved.

### Trivy — FAIL
- **Binary:** 0.76.1. ✅
- **Defect:** the orchestrator passes a hostname with `TRIVY_FULL_LOCAL`; `trivy_adapter.py:186` resolves it relative to `/app`, producing `/app/www.curezy.in`, which does not exist.
- **Missing capability:** no target typing (`filesystem` / `image` / `repository` / `website`) and no eligibility gate in `scan_orchestrator.py:322-345`.
- **Filesystem vs image:** only the filesystem path was exercised; container-image and repository modes remain **NOT VERIFIED**.

---

## What is verified end-to-end

- Workflow creation, authorization enforcement, stage sequencing, persistence and finalisation. ✅
- Partial-success policy: a failed stage did not erase httpx's findings. ✅
- Scanner status vocabulary (`completed` / `failed` / `skipped` / `partially_completed`) is persisted and returned accurately. ✅

## What remains unverified

- Nmap, ZAP and Trivy producing real, persisted findings.
- Nuclei completing within budget.
- Container-image and repository Trivy modes.
- Frontend rendering of a reconnected in-flight scan.
