# SentryAI — Real-Time Code Auditor

Tempel kode Python → dapat temuan keamanan & kualitas + saran patch dalam milidetik.
Backend **FastAPI + WebSocket**, frontend **Next.js**, mesin aturan **AST + heuristik**.

> Status jujur: mesin 100% rule-based (tanpa model ML). Cakupan: Python,
> 8 keluarga aturan. Bukan pengganti SonarQube/Semgrep — pendamping instan.

## Yang terverifikasi jalan

- `POST /api/audit` → skor 0–100, grade risiko, temuan per baris + remediasi (teruji: p50 1,9 ms lokal)
- WebSocket `/ws/audit` → audit live per ketikan
- 4/4 pytest lolos (`tests/test_auditor.py`)
- Frontend Next.js build sukses, end-to-end via rewrite teruji
- JavaScript: 6 aturan (eval, innerHTML, document.write, timer-string, outerHTML, shell)
- Riwayat audit (SQLite) + unduh laporan Markdown (`/api/history`, `/api/report/{id}`)

## Aturan yang dideteksi

| ID | Temuan |
|---|---|
| SEC-001 | `eval()`/eksekusi dinamis berbahaya (RCE) |
| SEC-002/003 | SQL injection via f-string / konkatenasi |
| SEC-004+ | `os.system`, `yaml.load` tak aman, secret hardcoded (regex + entropi Shannon) |
| QLT | `except: pass` diam-diam, loop kuadratik, syntax error |

Tidak ditangani: XSS, IDOR, ReDoS, bahasa selain Python.

## Jalankan

```bash
# Backend (butuh Python 3.10+, fastapi, uvicorn, pydantic)
python -m uvicorn app:app --port 8000
# → http://localhost:8000 (dashboard statis + GET /api/health)

# Frontend (butuh Node 18+)
cd frontend && npm install && npm run build && npm run start -- -p 3000
# → http://localhost:3000 (rewrite /api → backend :8000)
```

## API

```bash
curl -X POST localhost:8000/api/audit \
  -H 'Content-Type: application/json' \
  -d '{"code": "x = eval(y)", "language": "python"}'
```

## Struktur

```
app.py                 # FastAPI: REST + WebSocket + static
engine/auditor.py      # Mesin aturan AST/heuristik + auto-patch
tests/test_auditor.py  # 4 tes keamanan inti
frontend/              # Next.js: form audit tersambung backend
static/                # Dashboard statis alternatif
ARCHITECTURE.md        # Desain + batas kemampuan (jujur)
```

Lisensi: MIT.
