"""
SentryAI - Real-Time Code Auditor Server
FastAPI WebSockets + REST API + Static Dashboard Mount
"""

import asyncio
import json
import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from engine.auditor import audit_source_code

app = FastAPI(
    title="SentryAI - Real-Time AI Code Auditor",
    description="AST + heuristic Python code quality / security analyzer",
    version="1.0.0"
)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

class AuditRequest(BaseModel):
    code: str
    language: str = "python"

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>SentryAI Engine Running</h1>")

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SentryAI Real-Time Code Auditor",
        "engine": "AST + heuristic pattern rules (no ML model)",
        "version": "1.0.0"
    }

@app.post("/api/audit")
async def audit_endpoint(payload: AuditRequest):
    result = audit_source_code(payload.code, payload.language)
    return JSONResponse(content=result)

@app.websocket("/ws/audit")
async def websocket_audit_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                data = json.loads(raw_data)
                code = data.get("code", "")
                language = data.get("language", "python")
                
                # Perform instant AST & regex audit
                result = audit_source_code(code, language)
                
                # Send immediate response
                await websocket.send_json({
                    "type": "audit_result",
                    "data": result
                })
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Malformed JSON payload received."
                })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
