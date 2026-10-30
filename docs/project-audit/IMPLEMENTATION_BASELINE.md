# DRISHTI — Implementation Baseline

**Captured:** 2026-10-27 · **Compiled:** 2026-10-28
**Purpose:** the reference state against which every later change is measured. If a future result disagrees with this document, re-verify the environment first.

---

## 1. Repository shape

| Item | Count |
|---|---|
| Backend service modules | 33 |
| Backend API modules | 10 |
| API routes | 62 |
| Test files | 17 |
| Frontend views | 10 |
| Frontend components | 6 |

Top-level layout:

```
D:\drishti\
├── backend\
│   ├── api\            auth, authorizations, routes, scans, settings, sse,
│   │                   vulnerabilities, graph, llm
│   ├── services\       scanner adapters, orchestrator, parsers, risk, LLM router
│   ├── db\             database.py (asyncpg pool, SQL adapters)
│   └── main.py         FastAPI app, SPA fallback
├── frontend\           React 18 + Vite + TypeScript
├── tests\              17 test modules (no conftest.py)
├── docs\
├── docker-compose.yml
├── zap-config.xml
├── requirements.txt
└── .env
```

**Version control:** the directory is **not a git repository**. There is no diff history; all changes are working-tree edits only. This is a traceability gap that should be corrected.

---

## 2. Runtime environment

| Component | Value |
|---|---|
| Host OS | Windows (win32) |
| Python (tests) | 3.12.14 (`.venv`) |
| Node / npm | used for frontend build |
| Docker services | `drishti_platform`, `drishti_zap`, `drishti_postgres` |
| Container uptime at capture | platform 3 h, zap 2 h, postgres 3 h |

---

## 3. Services

| Service | Image | Port | Health |
|---|---|---|---|
| `drishti_platform` | DRISHTI image (API + scanner binaries) | 8000 | healthy |
| `drishti_zap` | `ghcr.io/zaproxy/zaproxy:stable` | 8080 | healthy |
| `drishti_postgres` | PostgreSQL 16.15 | 5432 | healthy |

---

## 4. Scanner binaries

| Scanner | Version | Location | Invocation |
|---|---|---|---|
| Nmap | 7.95 | inside `drishti_platform` | local subprocess |
| ProjectDiscovery httpx | v1.6.0 | inside `drishti_platform` | local subprocess |
| Nuclei | v3.3.2 | inside `drishti_platform` | local subprocess |
| Trivy | 0.76.1 | inside `drishti_platform` | local subprocess |
| OWASP ZAP | 2.17.0 | `drishti_zap` daemon | REST API |

**Note:** `httpx -version` and `nuclei -version` exit non-zero by design; exit code alone is not a health signal.

---

## 5. Configuration

### 5.1 Environment variables (names only — no secret values recorded)

| Variable | Purpose | State |
|---|---|---|
| `DATABASE_URL` | PostgreSQL DSN | points at **remote Supabase** |
| `DRISHTI_DEV_MODE` | development bypass | present (`false`) |
| `SANDBOX_ALLOWLIST` | pre-authorized sandbox domains | populated with test domains |
| `GEMINI_API_KEY` | Gemini provider | present |
| `GROQ_API_KEY` | Groq provider | present |
| `NVIDIA_API_KEY` | NVIDIA NIM provider | present |
| `HUGGINGFACE_API_KEY` / `HF_TOKEN` | Hugging Face provider | present |
| `ZAP_API_URL` / `ZAP_API_KEY` | ZAP connection | configured |

### 5.2 Docker vs tests — two different databases

| Consumer | Database | Consequence |
|---|---|---|
| Docker stack | local `postgres` service | healthy, `supabase: false` |
| Test suite | remote Supabase (from `.env`) | subject to free-tier connection ceiling |

This split is the root of I-16 and must be resolved before CI can be trusted.

### 5.3 ZAP configuration

- Real config file: `config.xml` (mounted from `zap-config.xml`).
- `zap.conf` is **legacy and ignored by the daemon** — should be removed.
- Allow-list entries are hierarchical XML and matched against the request **Host header**.
- Permitted hosts: `127.0.0.1`, `localhost`, `zap`, `172.18.0.1`, `172.18.0.2`, `172.18.0.4`.

---

## 6. Baseline test result

```
Command: .venv\Scripts\python -m pytest tests/ -q
Result:  1 failed, 121 passed, 1 warning in 357.71s (0:05:57)
```

| Metric | Baseline (session start) | Current |
|---|---|---|
| Collected | 122 | 122 |
| Passed | 114 | **121** |
| Failed | 8 | **1** |
| Warning | 1 | 1 |

The remaining failure is `tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence`, caused by defect **I-18** (sandbox authorization not persisted).

---

## 7. Baseline live-run result

Workflow `wf-1793120244-www-curezy-in`, target `www.curezy.in`:

| Stage | Status | Duration | Findings |
|---|---|---|---|
| nmap | failed | 1107.11 s | 0 |
| httpx | completed | 2.89 s | 3 |
| zap | completed | 0.74 s | 0 |
| trivy | failed | 0.05 s | 0 |
| nuclei | failed | 120.27 s | 0 |

Final: `partially_completed`, progress 100.

---

## 8. Baseline frontend build

```
✓ 46 modules transformed
✓ built in 473ms
dist/assets/index-D1dgi4v7.js   281.80 kB │ gzip: 75.77 kB
dist/assets/index-YHNQ1v-D.css    1.15 kB │ gzip:  0.53 kB
```

---

## 9. Known constraints at baseline

| Constraint | Impact | Status |
|---|---|---|
| Remote Supabase free tier | connection ceiling for tests | open (I-16) |
| No git repository | no change history, no diff review | open |
| No `tests/conftest.py` | each module calls `init_db()` itself | accepted |
| ZAP host port unverified | demo risk on Windows | open (I-17) |
| Container serves pre-fix bundle | frontend fixes not live until rebuild | open |

---

## 10. Commands used for verification

```powershell
# Test suite
cd D:\drishti
.venv\Scripts\python -m pytest tests/ -q

# Focused runs
.venv\Scripts\python -m pytest tests/test_scan_lifecycle.py::test_scan_lifecycle_and_findings_persistence -q

# Frontend build
cd D:\drishti\frontend
npm run build

# Runtime health
Invoke-RestMethod http://localhost:8000/api/health

# Workflow status
Invoke-RestMethod "http://localhost:8000/api/scans/orchestrator/workflows/<workflow_id>"

# ZAP connectivity (container → container)
docker exec drishti_platform curl -s "http://zap:8080/JSON/core/view/version/?apikey=***"

# Binaries
docker exec drishti_platform nmap --version
docker exec drishti_platform httpx -version
docker exec drishti_platform nuclei -version
docker exec drishti_platform trivy --version
```
