import asyncio
import sys
sys.path.insert(0, 'D:/drishti')
from backend.main import app
from httpx import AsyncClient, ASGITransport

endpoints = [
    ("GET", "/api/health", None),
    ("POST", "/api/health/pipeline-test", {}),
    ("POST", "/api/auth/login", {"username": "local-operator-dev", "role": "SecOps Lead"}),
    ("GET", "/api/auth/profile", None),
    ("GET", "/api/authorizations/check?target=iiit-bh.ac.in&scope=FULL_PASSIVE", None),
    ("GET", "/api/scans?limit=1", None),
    ("GET", "/api/scans/latest", None),
    ("GET", "/api/scans/wf-1793941076-iiit-bh-ac-in", None),
    ("GET", "/api/scans/wf-1793941076-iiit-bh-ac-in/findings", None),
    ("GET", "/api/scans/wf-1793941076-iiit-bh-ac-in/observations", None),
    ("GET", "/api/scans/telemetry/logs", None),
    ("GET", "/api/recon/latest", None),
    ("GET", "/api/recon/latest?target=iiit-bh.ac.in", None),
    ("GET", "/api/vulnerabilities/latest", None),
    ("GET", "/api/vulnerabilities/latest?target=iiit-bh.ac.in", None),
    ("GET", "/api/vulnerabilities/scan/wf-1793941076-iiit-bh-ac-in", None),
    ("GET", "/api/graph/latest", None),
    ("GET", "/api/graph/latest?target=iiit-bh.ac.in", None),
    ("GET", "/api/graph/latest/paths?target_domain=iiit-bh.ac.in", None),
    ("POST", "/api/defense/generate", {"cve_id": "CWE-538", "target": "iiit-bh.ac.in"}),
    ("POST", "/api/defense/verify", {"target_url": "https://iiit-bh.ac.in", "expected_status": 403}),
    ("POST", "/api/reports/generate", {"target": "iiit-bh.ac.in", "format": "TEXT"}),
    ("GET", "/api/reports/latest", None),
    ("GET", "/api/settings", None),
    ("GET", "/api/stix/bundle", None),
    ("GET", "/api/audit/logs", None),
    ("GET", "/api/audit/ledger", None),
    ("GET", "/api/security/audit", None),
]

async def run_full_suite():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", timeout=10.0) as client:
        passed = 0
        failed = 0
        print(f"{'METHOD':<6} | {'ENDPOINT':<50} | {'STATUS':<8} | DETAIL")
        print("-" * 80)
        for method, url, body in endpoints:
            try:
                if method == "GET":
                    res = await client.get(url)
                else:
                    res = await client.post(url, json=body)
                if res.status_code < 400:
                    passed += 1
                    print(f"{method:<6} | {url:<50} | [ 200 OK ] | {len(res.content)} bytes")
                else:
                    failed += 1
                    print(f"{method:<6} | {url:<50} | [ {res.status_code} ] | {res.text[:80]}")
            except Exception as e:
                failed += 1
                print(f"{method:<6} | {url:<50} | [ EXC ]   | {e}")
        print("-" * 80)
        print(f"TOTAL: {passed} PASSED, {failed} FAILED")

if __name__ == "__main__":
    asyncio.run(run_full_suite())
