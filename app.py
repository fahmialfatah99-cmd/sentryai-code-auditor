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


HISTORY_DB = Path(__file__).parent / "audits.db"


def _history_conn():
    import sqlite3

    conn = sqlite3.connect(HISTORY_DB)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT DEFAULT (datetime('now','localtime')),
            language TEXT DEFAULT 'python',
            score INTEGER DEFAULT 0,
            issues INTEGER DEFAULT 0,
            code_preview TEXT DEFAULT '')"""
    )
    return conn


def _history_save(language: str, result: dict, code: str) -> int:
    conn = _history_conn()
    cur = conn.execute(
        "INSERT INTO audits (language, score, issues, code_preview) VALUES (?,?,?,?)",
        (language, int(result.get("health_score", 0)), int(result.get("total_issues", 0)), code[:300]),
    )
    conn.commit()
    last = cur.lastrowid or 0
    conn.close()
    return int(last)

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
    try:
        result["audit_id"] = _history_save(payload.language, result, payload.code)
    except Exception:
        pass
    return JSONResponse(content=result)


@app.get("/api/history")
async def history_endpoint(limit: int = 10):
    conn = _history_conn()
    rows = conn.execute(
        "SELECT id, ts, language, score, issues FROM audits ORDER BY id DESC LIMIT ?",
        (max(1, min(limit, 50)),),
    ).fetchall()
    conn.close()
    return {"history": [
        {"id": r[0], "ts": r[1], "language": r[2], "score": r[3], "issues": r[4]} for r in rows
    ]}


@app.get("/api/report/{audit_id}")
async def report_endpoint(audit_id: int):
    from fastapi.responses import PlainTextResponse

    conn = _history_conn()
    row = conn.execute(
        "SELECT id, ts, language, score, issues, code_preview FROM audits WHERE id = ?", (audit_id,)
    ).fetchone()
    conn.close()
    if not row:
        return JSONResponse(content={"error": "audit tak ditemukan"}, status_code=404)
    md = (
        f"# Laporan Audit SentryAI #{row[0]}\n\n"
        f"- Waktu: {row[1]} | Bahasa: {row[2]} | Skor: {row[3]} | Temuan: {row[4]}\n\n"
        f"## Cuplikan kode\n```{row[2]}\n{row[5]}\n```\n"
    )
    return PlainTextResponse(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=audit-{row[0]}.md"},
    )

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
