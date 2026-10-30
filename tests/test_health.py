import pytest
from httpx import ASGITransport, AsyncClient
from backend.main import app
from backend.db.database import init_db


@pytest.mark.asyncio
async def test_health_endpoint():
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "operational"
        assert "database" in data
        assert data["database"]["status"] in ("connected", "operational")
        assert "memory" in data
        assert "engines" in data
        assert "recon" in data["engines"]
        assert "intel" in data["engines"]
        assert "graph" in data["engines"]
        assert "stix" in data["engines"]


@pytest.mark.asyncio
async def test_settings_endpoint():
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. GET settings - should report valid engine mode and keys structure
        res = await client.get("/api/settings")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert "engine_mode" in data
        assert data["engine_mode"]["mode"] in ("LOCAL_COMMODITY", "CLOUD_ACCELERATED")
        assert "google" in data["keys"]
        assert "nvidia" in data["keys"]
        assert "huggingface" in data["keys"]
        assert "groq" in data["keys"]

        # 2. Force local mode toggle
        local_res = await client.post("/api/settings", json={"force_local_mode": True})
        assert local_res.status_code == 200
        assert local_res.json()["engine_mode"]["mode"] == "LOCAL_COMMODITY"

        # 3. Dynamic cloud acceleration toggle
        cloud_res = await client.post(
            "/api/settings",
            json={
                "groq_api_key": "gsk_test123456789",
                "nvidia_api_key": "nvapi-test123456789",
                "huggingface_api_key": "hf_test123456789",
                "gemini_api_key": "AIzaSyTest123456789",
                "force_local_mode": False,
            },
        )
        assert cloud_res.status_code == 200
        cloud_data = cloud_res.json()
        assert cloud_data["engine_mode"]["mode"] == "CLOUD_ACCELERATED"
        assert "Groq" in cloud_data["engine_mode"]["provider"]
        assert "NVIDIA" in cloud_data["engine_mode"]["provider"]
        assert "Hugging Face" in cloud_data["engine_mode"]["provider"]
        assert "Google" in cloud_data["engine_mode"]["provider"]

        # 4. Clean up back to user's saved configuration state
        await client.post("/api/settings", json={"force_local_mode": False})


@pytest.mark.asyncio
async def test_operator_auth_endpoint():
    """Verify operator authentication, session validation, and logout."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Login
        login_res = await client.post(
            "/api/auth/login",
            json={"username": "local-operator-dev", "password": "any-password", "role": "SecOps Lead"}
        )
        assert login_res.status_code == 200
        data = login_res.json()
        assert data["status"] == "success"
        assert "token" in data
        assert data["operator"]["id"] == "local-operator-dev"
        assert data["operator"]["role"] == "SecOps Lead"

        # 2. Get profile me
        me_res = await client.get("/api/auth/me")
        assert me_res.status_code == 200
        assert me_res.json()["authenticated"] is True
        assert me_res.json()["operator"]["name"] == "Alex Morgan"

        # 3. Logout
        logout_res = await client.post("/api/auth/logout")
        assert logout_res.status_code == 200
        assert logout_res.json()["status"] == "success"
