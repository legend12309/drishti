import asyncio
import sys
sys.path.insert(0, 'D:/drishti')
from backend.main import app
from httpx import AsyncClient, ASGITransport

async def test_routes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", timeout=3.0) as client:
        errors = []
        for route in app.routes:
            methods = getattr(route, 'methods', None)
            path = getattr(route, 'path', None)
            if methods and 'GET' in methods and '{' not in path and 'stream' not in path:
                try:
                    res = await client.get(path)
                    if res.status_code >= 500:
                        errors.append((path, res.status_code, res.text[:200]))
                        print(f"[FAIL] GET {path} -> {res.status_code}")
                    else:
                        print(f"[OK] GET {path} -> {res.status_code}")
                except Exception as e:
                    errors.append((path, 'EXCEPTION', str(e)))
                    print(f"[ERR] GET {path} -> {e}")
        print("\nSummary:")
        if errors:
            print(f"FAILED ROUTES ({len(errors)}):")
            for p, c, err in errors:
                print(f"  {p} [{c}]: {err}")
        else:
            print("ALL ROUTES PASSED!")

if __name__ == "__main__":
    asyncio.run(test_routes())
