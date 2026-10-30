# DRISHTI — Test Environment

**Compiled:** 2026-10-28
**Purpose:** explain how tests connect to a database, why that is fragile today, and how to make it deterministic.

---

## 1. The core problem

DRISHTI uses **two different databases** depending on how it is started:

| Consumer | Source of `DATABASE_URL` | Actual database |
|---|---|---|
| Docker stack | `docker-compose.yml` default | local `postgres` service |
| Test suite | `.env` | **remote Supabase** |

The running platform reports `"supabase": false` and is healthy. The test suite, however, connects to Supabase, whose free tier caps concurrent connections.

**Symptom observed:**

```
asyncpg.exceptions.TooManyConnectionsError:
remaining connection slots are reserved for roles with the SUPERUSER attribute
```

This affected five `tests/test_scan_lifecycle.py` tests plus one passive-recon provenance test in earlier runs. It did **not** recur in the final run, which makes it an intermittent, environment-dependent failure — the worst kind.

---

## 2. Why it happens

- There is **no `tests/conftest.py`**; each test module calls `await init_db()` itself.
- Each module therefore creates its own connection pool.
- Pools are not reliably closed between modules.
- Supabase free tier allows only a small number of concurrent connections.

Result: the suite exhausts the remote pool partway through the run.

---

## 3. Recommended fix — a local PostgreSQL test profile

Run the suite against the containerised PostgreSQL that already exists in the stack.

### 3.1 Start only the database

```powershell
docker compose -f D:\drishti\docker-compose.yml up -d postgres
```

### 3.2 Point tests at it (process-scoped, no `.env` edit)

```powershell
$env:DATABASE_URL = "postgresql://postgres:devpass@localhost:5432/drishti"
cd D:\drishti
.venv\Scripts\python -m pytest tests/ -q
```

`docker-compose.yml` already maps port 5432 to the host, so `localhost:5432` reaches the container.

### 3.3 Or use a dedicated test database

```powershell
docker exec drishti_postgres createdb -U postgres drishti_test
$env:DATABASE_URL = "postgresql://postgres:devpass@localhost:5432/drishti_test"
```

A separate database prevents tests from writing into development data.

### 3.4 Add a session-scoped fixture (recommended)

Create `tests/conftest.py` so the pool is initialised once and closed once:

```python
import os
import pytest
import pytest_asyncio
from backend.db.database import init_db, close_db   # adjust to the real shutdown helper

@pytest.fixture(scope="session", autouse=True)
def _force_local_db():
    if os.getenv("DRISHTI_TEST_DB"):
        os.environ["DATABASE_URL"] = os.environ["DRISHTI_TEST_DB"]

@pytest_asyncio.fixture(scope="session", autouse=True)
async def _db_session():
    await init_db()
    yield
    await close_db()
```

> Verify the shutdown helper name in `backend/db/database.py` before adding this. The goal is one pool per session, not one per module.

---

## 4. Sandbox allow-list in tests

`.env` `SANDBOX_ALLOWLIST` contains test domains (`security-target.io`, `company.com`, `target.local`, `provenance-test.net`, `verify-test.org`).

Because `get_valid_authorization_for_target()` short-circuits on sandbox targets **before** the database lookup, a synthetic authorization shadows any real row. Two modules now clear it explicitly:

```python
@pytest.fixture(autouse=True)
def clear_sandbox_allowlist(monkeypatch):
    monkeypatch.setenv("SANDBOX_ALLOWLIST", "")
```

**Caveat:** this fixture hides defect **I-18** in those modules. It makes the tests pass; it does not make the product correct. Once I-18 is fixed, the fixture should be re-evaluated — the tests should be able to pass *with* a sandbox target.

---

## 5. Environment variables relevant to tests

| Variable | Purpose | Notes |
|---|---|---|
| `DATABASE_URL` | PostgreSQL DSN | override to local for tests |
| `DRISHTI_DEV_MODE` | development bypass | currently `false` |
| `SANDBOX_ALLOWLIST` | pre-authorized domains | shadows DB auth — see §4 |
| `ZAP_API_URL` | ZAP endpoint | not required by unit tests |
| `ZAP_API_KEY` | ZAP auth | never log the value |
| `GEMINI_API_KEY`, `GROQ_API_KEY`, `NVIDIA_API_KEY`, `HUGGINGFACE_API_KEY` | AI providers | tests use offline fallback |

**Never** commit real values. Keep `.env` out of version control and maintain a `.env.example` with names and non-secret placeholders.

---

## 6. Verification checklist before trusting a test run

1. `echo $env:DATABASE_URL` → confirm it targets the intended database.
2. `docker ps` → confirm `drishti_postgres` is healthy.
3. Run a single module first (`pytest tests/test_scan_lifecycle.py -q`).
4. Run the full suite.
5. If `TooManyConnectionsError` appears, stop and fix the pool lifecycle — do **not** treat it as a test failure to be skipped.

---

## 7. Known-good command sequence

```powershell
cd D:\drishti

# 1. Local database
docker compose -f .\docker-compose.yml up -d postgres

# 2. Isolate tests
$env:DATABASE_URL = "postgresql://postgres:devpass@localhost:5432/drishti"

# 3. Sanity: one module
.venv\Scripts\python -m pytest tests\test_scan_lifecycle.py -q

# 4. Full suite
.venv\Scripts\python -m pytest tests\ -q

# 5. Restore for the app (if needed)
Remove-Item Env:\DATABASE_URL
```
