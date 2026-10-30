import asyncio
import json
import time
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/stream", tags=["Telemetry"])

async def event_generator():
    while True:
        payload = {"timestamp": time.time(), "type": "heartbeat", "message": "SSE pipeline active"}
        yield f"data: {json.dumps(payload)}\n\n"
        await asyncio.sleep(5)

@router.get("/threats")
async def stream_threats():
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )


@router.get("/v1/stream")
async def stream_v1_telemetry():
    """Alias for /api/v1/stream telemetry pipeline."""
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"}
    )
