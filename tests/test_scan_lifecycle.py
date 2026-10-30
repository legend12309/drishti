import asyncio
import json
import pytest
from httpx import ASGITransport, AsyncClient
from backend.main import app
from backend.db.database import get_db, init_db, db_queue
from backend.services.scanner import create_scan, get_scan_status, get_scan_findings


@pytest.mark.asyncio
async def test_authorization_boundary():
    """Verify that malformed or unauthorized targets are rejected."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Invalid domain format
        res_invalid = await client.post("/api/scans", json={"target": "http://invalid domain!#$"})
        assert res_invalid.status_code == 400

        # 2. Empty target
        res_empty = await client.post("/api/scans", json={"target": ""})
        assert res_empty.status_code == 400

        # 3. Valid permitted domain
        res_valid = await client.post("/api/scans", json={"target": "company.com"})
        assert res_valid.status_code == 201
        data = res_valid.json()
        assert "scan_id" in data
        assert data["target"] == "company.com"
        assert data["status"] in ("pending", "running")


@pytest.mark.asyncio
async def test_scan_lifecycle_and_findings_persistence():
    """Verify complete lifecycle: pending -> running -> completed, and findings persisted in SQLite."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Start scan
        create_res = await client.post("/api/scans", json={"target": "security-target.io"})
        assert create_res.status_code == 201
        scan_id = create_res.json()["scan_id"]

        # Poll status until completed (timeout 16s)
        completed = False
        for _ in range(80):
            await asyncio.sleep(0.2)
            status_res = await client.get(f"/api/scans/{scan_id}")
            assert status_res.status_code == 200
            scan_data = status_res.json()
            if scan_data["status"] == "completed":
                completed = True
                assert scan_data["progress"] == 100
                assert scan_data["completed_at"] is not None
                break

        assert completed, "Scan did not reach completed state within time limit"

        # Check findings persistence
        findings_res = await client.get(f"/api/scans/{scan_id}/findings")
        assert findings_res.status_code == 200
        findings_data = findings_res.json()
        assert findings_data["total"] >= 5
        hosts = [f["host"] for f in findings_data["findings"]]
        assert "vpn.security-target.io" in hosts
        assert "api.security-target.io" in hosts

        # Check page refresh survival (/api/scans/latest)
        latest_res = await client.get("/api/scans/latest?target=security-target.io")
        assert latest_res.status_code == 200
        latest_data = latest_res.json()
        assert latest_data["status"] == "success"
        assert latest_data["scan"]["id"] == scan_id
        assert len(latest_data["scan"]["findings"]) >= 5


@pytest.mark.asyncio
async def test_scan_cancellation():
    """Verify that an active scan can be cancelled."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create scan
        create_res = await client.post("/api/scans", json={"target": "cancel-demo.net"})
        assert create_res.status_code == 201
        scan_id = create_res.json()["scan_id"]

        # Immediately cancel
        cancel_res = await client.post(f"/api/scans/{scan_id}/cancel")
        assert cancel_res.status_code == 200
        assert cancel_res.json()["status"] == "cancelled"

        # Allow worker loop to process cancellation
        await asyncio.sleep(0.2)
        status_res = await client.get(f"/api/scans/{scan_id}")
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "cancelled"


@pytest.mark.asyncio
async def test_interrupted_scan_recovery():
    """Verify that interrupted/abandoned scans from a prior crash are marked failed on startup."""
    orphan_id = "scan-interrupted-test-999"
    await init_db()
    # Insert an abandoned running scan directly into SQLite
    await db_queue.execute_write(
        """
        INSERT OR REPLACE INTO scans (id, target, status, progress, current_step)
        VALUES (?, 'interrupted.com', 'running', 45, 'Enumerating subdomains')
        """,
        (orphan_id,)
    )

    # Re-initialize DB (simulating application reboot)
    await init_db()

    # Verify status is recovered to failed
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(f"/api/scans/{orphan_id}")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "failed"
        assert "interrupted" in data["error_message"].lower()


@pytest.mark.asyncio
async def test_scan_sse_stream_and_reconnect():
    """Verify SSE stream connects, receives events, and supports reconnection with Last-Event-ID."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        create_res = await client.post("/api/scans", json={"target": "sse-reconnect.org"})
        scan_id = create_res.json()["scan_id"]

        # 1. Initial connection
        first_event_id = None
        async with client.stream("GET", f"/api/scans/{scan_id}/stream") as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers.get("content-type", "")

            async for line in response.aiter_lines():
                if line.startswith("id: "):
                    first_event_id = line.replace("id: ", "").strip()
                if line.startswith("data: "):
                    break

        assert first_event_id is not None

        # 2. Reconnect with Last-Event-ID
        headers = {"Last-Event-ID": first_event_id}
        reconnect_events = []
        async with client.stream("GET", f"/api/scans/{scan_id}/stream", headers=headers) as response:
            assert response.status_code == 200
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    raw_json = line.replace("data: ", "").strip()
                    try:
                        event = json.loads(raw_json)
                        reconnect_events.append(event)
                        if len(reconnect_events) >= 1:
                            break
                    except Exception:
                        pass

        assert len(reconnect_events) >= 1
        assert reconnect_events[0]["type"] in ("reconnected", "init", "progress", "completed")
