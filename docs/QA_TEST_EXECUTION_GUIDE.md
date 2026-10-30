# DRISHTI — QA TEST EXECUTION GUIDE
**Operational Instructions for Human and Automated QA Execution**  
**Version:** 1.0.0  
**Target Environment:** Local Workstation / Staging Lab  

---

## 1. Prerequisites & Environment Setup

### 1.1 Hardware and OS Requirements
- **Operating System:** Windows 10/11, macOS 13+, or Ubuntu 22.04+ LTS.
- **Node.js:** v18.18+ or v20+ LTS (`node -v`).
- **Python:** v3.11 or v3.12 (`python --version`).
- **RAM:** Minimum 8 GB (16 GB recommended for concurrent scanner execution).

### 1.2 Repository & Service Topology
```
           +---------------------------------------------+
           |           React Frontend (Vite)             |
           |           http://127.0.0.1:5173             |
           +----------------------+----------------------+
                                  | HTTP / SSE
                                  v
           +---------------------------------------------+
           |          FastAPI Application Core           |
           |           http://127.0.0.1:8000             |
           +----------------------+----------------------+
                                  | asyncpg / TLS
                                  v
+--------------------------------------------------------------------+
|                Supabase PostgreSQL Managed Cluster                 |
|            aws-0-ap-south-1.pooler.supabase.com:6543               |
+--------------------------------------------------------------------+
```

---

## 2. Service Startup & Verification

### Step 1: Verify Supabase Database Connectivity
Before starting services, confirm outbound connectivity to the Supabase instance:
```powershell
# In repository root (E:\drishti)
E:\drishti\.venv\Scripts\python.exe -c "
import asyncio
from backend.database.supabase import get_db_pool

async def check():
    pool = await get_db_pool()
    async with pool.acquire() as conn:
        ver = await conn.fetchval('SELECT version()')
        print('[SUCCESS] Connected to:', ver)

asyncio.run(check())
"
```
*Expected Output:* `[SUCCESS] Connected to: PostgreSQL 17.11 on aarch64-unknown-linux-gnu...`

### Step 2: Start Backend Server
Ensure `PYTHONPATH` includes the repository root:
```powershell
$env:PYTHONPATH="E:\drishti"
Set-Location "E:\drishti"
E:\drishti\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
Verify the API health check:
- Open `http://127.0.0.1:8000/health` in your browser or curl:
  ```json
  {"status":"healthy","database":{"status":"connected","version":"PostgreSQL 17.11...","pool_size":3}}
  ```

### Step 3: Start Frontend Dev Server
In a separate terminal:
```powershell
Set-Location "E:\drishti\frontend"
npm run dev -- --host 127.0.0.1 --port 5173
```
- Open `http://127.0.0.1:5173` in a Chromium or Firefox browser.

---

## 3. Scanner Tool Verification & Lab Isolation

### 3.1 Understanding Scanner Availability vs Code Correctness
DRISHTI is architected with adapter layers that decouple execution logic from binary availability. 
When executing test cases in Category C (`SCAN-01` to `SCAN-05`), check the capabilities endpoint first:
```bash
curl -X GET http://127.0.0.1:8000/api/scans/orchestrator/capabilities
```
```json
{
  "nmap": {"is_available": false, "version": null},
  "httpx": {"is_available": false, "version": null},
  "zap": {"is_available": false, "version": null},
  "trivy": {"is_available": false, "version": null},
  "nuclei": {"is_available": false, "version": null}
}
```
> **IMPORTANT NOTE FOR QA TESTERS:**
> If `is_available` is `false`, the orchestrator is designed to skip missing stages without crashing if `allow_partial_completion=true`. This is the **expected graceful degradation behavior** on standard developer machines without security tool suites installed. Do not log this as a code bug. Log as an environment limitation unless an unhandled 500 Internal Server Error occurs.

### 3.2 Safe Test Targets
Never launch test scans against unauthorized external production systems. Use exclusively:
1. `scanme.nmap.org` (Officially authorized Nmap test target for port scanning).
2. Local dockerized targets (e.g. `bkimminich/juice-shop` or `vulnerables/web-dvwa`).
3. Offline synthetic mock profiles provided in test fixtures.

---

## 4. Manual QA Execution Procedure

### 4.1 Step-by-Step Scenario Walkthrough

#### Scenario 1: Authentication & Navigation Sanity (AUTH-01, UI-01)
1. Launch browser in Incognito mode.
2. Open `http://127.0.0.1:5173/login`.
3. Enter default credentials or initiate mock login.
4. Verify landing on `/dashboard`. Check browser network tab: observe JWT token in request headers for `/api/*` endpoints.
5. Click through all primary sidebar links:
   - Dashboard (`/dashboard`)
   - Targets (`/targets`)
   - Scans (`/scans`)
   - Vulnerabilities (`/vulnerabilities`)
   - Attack Graph (`/attack-graph`)
   - Reports (`/reports`)
   - Settings (`/settings`)
6. Ensure no console errors (`Uncaught TypeError`, `ChunkLoadError`) occur.

#### Scenario 2: Scope Verification & Cryptographic Challenge (SCOPE-01, SCOPE-02)
1. In Targets view, attempt to add target `127.0.0.1`.
2. Verify system blocks target addition with notification that loopback addresses are disallowed.
3. Add domain `test-lab.example.org`.
4. Click "Verify Scope" -> "Generate Challenge".
5. Observe generated verification token: `drishti-verify=<token>`.
6. Confirm backend stores unverified challenge in database.

#### Scenario 3: AutoRecon Launch & SSE Observation (SCAN-01, SCAN-03)
1. Navigate to `/scans` -> "New Assessment".
2. Select target and profile "Full AutoRecon".
3. Click "Start Coordinated Assessment".
4. Observe immediate redirect to workflow execution dashboard.
5. In Network tab, locate EventStream connection: `/api/scans/orchestrator/workflows/{id}/stream`.
6. Verify live stage progression messages.
7. Click "Cancel Assessment" to test `SCAN-04`. Ensure state flips to `CANCELLED` cleanly.

#### Scenario 4: Attack Graph Interaction (GRAPH-01, GRAPH-02)
1. Navigate to `/attack-graph`.
2. Verify interactive Canvas loads.
3. Drag nodes, zoom in/out with mouse wheel.
4. Click on an asset node: verify slide-over panel displays associated CVEs and risk score.
5. Toggle "Critical Path Highlight": verify path edges are highlighted with animated gradient.

---

## 5. Capturing QA Evidence

When recording manual test outcomes:
1. **Screenshots:** Save full browser screenshots with DevTools console open to `docs/qa_evidence/<TEST-ID>_<TIMESTAMP>.png`.
2. **Network Payloads:** Save relevant request/response JSON from the Network tab.
3. **Backend Logs:** Check running Uvicorn log stream for any traceback or warning logs.
4. **Database State:** Query Supabase directly via SQL to verify records:
   ```sql
   SELECT id, target, status, created_at FROM scans ORDER BY created_at DESC LIMIT 5;
   ```
