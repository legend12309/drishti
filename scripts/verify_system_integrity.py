import asyncio
import sys
from httpx import ASGITransport, AsyncClient
from backend.main import app
from backend.db.database import init_db

async def test_full_system():
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        print("=== [1] TESTING HEALTH & ENCLAVE ATTESTATION ===")
        res = await client.get("/api/health")
        assert res.status_code == 200, f"Expected 200, got {res.status_code}"
        data = res.json()
        assert "attestation" in data, "attestation missing from health"
        print(f"Health Status: {data['status']}, Enclave Node: {data['attestation']['node_id']}")
        
        # Verify Headers
        assert "x-drishti-author" in res.headers, "Missing x-drishti-author header"
        assert "x-drishti-enclave-node" in res.headers, "Missing x-drishti-enclave-node header"
        assert "x-drishti-ip-protection" in res.headers, "Missing x-drishti-ip-protection header"
        print(f"Attestation Headers: Author='{res.headers['x-drishti-author']}', IP='{res.headers['x-drishti-ip-protection']}'")

        print("\n=== [2] TESTING DEDICATED ATTESTATION ENDPOINT ===")
        res = await client.get("/api/system/attestation")
        assert res.status_code == 200
        att = res.json()
        assert att["status"] in ("ATTESTED & IMMUTABLE", "success")
        assert "attestation" in att
        assert "codebase_integrity" in att
        assert att["codebase_integrity"]["status"] == "VERIFIED_GENUINE"
        print(f"Attestation Status: {att['attestation']['status']}, Modules: {att['codebase_integrity']['checked_modules']}")

        print("\n=== [3] TESTING REPORT GENERATION & RFC COMPLIANCE ===")
        res = await client.get("/api/reports/latest?target=iiit-bh.ac.in")
        assert res.status_code == 200
        rpt = res.json()
        assert "content_text" in rpt
        content = rpt["content_text"]
        assert "PROPRIETARY INTELLECTUAL PROPERTY" in content or "Alex Morgan" in content
        assert "ENCLAVE NODE ID" in content
        # Check no bogus CNAME loops
        assert "[CNAME ] iiit-bh.ac.in\n" not in content
        print(f"Report for iiit-bh.ac.in: Size {len(content)} bytes, Watermark Verified.")

        print("\n=== [4] TESTING STIX 2.1 THREAT INTEL BUNDLE ===")
        res = await client.get("/api/stix/bundle?target=iiit-bh.ac.in")
        assert res.status_code == 200
        stix = res.json()
        assert stix.get("spec_version") == "2.1"
        objects = stix.get("objects", [])
        identities = [o for o in objects if o.get("type") == "identity"]
        assert len(identities) > 0, "No identity SDO in STIX bundle"
        print(f"STIX Objects: {len(objects)}, Generator: {identities[0]['name']}")

        print("\n=== [5] TESTING ERROR SHIELDING & FAULT CONTAINMENT ===")
        # Hit non-existent API route
        res = await client.get("/api/this-does-not-exist-at-all")
        assert res.status_code == 404
        # Verify attestation headers are preserved even on 404
        assert "x-drishti-author" in res.headers
        print("404 Fault containment verified.")

        # Test settings endpoint
        res = await client.get("/api/settings")
        assert res.status_code == 200
        print(f"Settings engine mode: {res.json()['engine_mode']['mode']}")

        # Test attack graph
        res = await client.get("/api/graph/paths?scan_id=wf-seed-vvdx-in")
        assert res.status_code in (200, 404)
        print("Graph paths endpoint verified.")

        # Test vulnerabilities
        res = await client.get("/api/vulnerabilities?limit=5")
        assert res.status_code == 200
        print(f"Vulnerabilities returned: {len(res.json().get('vulnerabilities', []))}")

        print("\n>>> ALL SYSTEM INTEGRITY & ANTI-COPY CHECKS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    asyncio.run(test_full_system())
