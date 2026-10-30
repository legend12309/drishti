from contextlib import asynccontextmanager
import os
from pathlib import Path
import time
from typing import Any, Dict
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import psutil

from backend.api.auth import router as auth_router
from backend.api.authorizations import router as authorizations_router
from backend.api.routes import router as engines_router
from backend.api.scans import router as scans_router
from backend.api.settings import router as settings_router
from backend.api.sse import router as sse_router
from backend.api.vulnerabilities import router as vulnerabilities_router
from backend.api.graph import router as graph_router
from backend.api.llm import router as llm_router
from backend.db.database import get_db, init_db, get_db_status
from backend.engines import get_active_engines

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
START_TIME = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="DRISHTI Cyber Intelligence Platform",
    version="0.1.0",
    docs_url="/api/docs",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(authorizations_router)
app.include_router(sse_router)
app.include_router(settings_router)
app.include_router(scans_router)
app.include_router(vulnerabilities_router)
app.include_router(graph_router)
app.include_router(llm_router)
app.include_router(engines_router)

# Compatibility route: /api/v1/stream
from backend.api.sse import event_generator
@app.get("/api/v1/stream", tags=["Telemetry"])
async def stream_api_v1():
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )

@app.get("/health", tags=["System"])
@app.get("/api/health", tags=["System"])
async def health_check() -> Dict[str, Any]:
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    sys_mem = psutil.virtual_memory()

    db_status = await get_db_status()

    return {
        "status": "operational",
        "platform": "DRISHTI",
        "version": "v1.0.0-rc1",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "database": db_status,
        "memory": {
            "rss_mb": round(mem_info.rss / (1024 * 1024), 2),
            "vms_mb": round(mem_info.vms / (1024 * 1024), 2),
            "system_used_percent": sys_mem.percent,
            "system_available_mb": round(sys_mem.available / (1024 * 1024), 2),
        },
        "engines": get_active_engines(),
    }

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    # Serve SPA for non-API paths only
    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str = ""):
        if full_path.startswith("api/") or full_path == "api":
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        file_path = FRONTEND_DIST / full_path
        if full_path and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIST / "index.html")
else:
    @app.get("/", include_in_schema=False)
    async def index_placeholder():
        return JSONResponse({
            "message": "DRISHTI API active. Build frontend in /frontend to serve SPA.",
            "health": "/health",
            "docs": "/api/docs"
        })
