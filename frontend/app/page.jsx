"use client";

import { useState } from "react";

const SAMPLE = `import sqlite3

def get_user(uid):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()
`;

export default function Home() {
  const [code, setCode] = useState(SAMPLE);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function runAudit() {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, language: "python" }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setResult(await res.json());
    } catch (e) {
      setError(`Audit gagal: ${e.message}. Pastikan backend FastAPI jalan di :8000.`);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold">SentryAI — Code Auditor</h1>
      <p className="text-sm text-slate-400 mt-1">
        Aturan AST + heuristik (Python). Skor, temuan, dan saran patch dari backend.
      </p>
      <textarea
        value={code}
        onChange={(e) => setCode(e.target.value)}
        rows={10}
        spellCheck={false}
        className="w-full mt-4 p-3 rounded bg-[#11151d] border border-slate-700 font-mono text-sm"
      />
      <button
        onClick={runAudit}
        disabled={loading}
        className="mt-3 px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 font-semibold"
      >
        {loading ? "Mengaudit…" : "Audit Sekarang"}
      </button>
      {error && <p className="mt-3 text-red-400">{error}</p>}
      {result && (
        <div className="mt-4 p-4 rounded bg-[#11151d] border border-slate-700">
          <p>
            Skor: <b>{result.health_score}</b> · Grade: <b>{result.risk_grade}</b> ·{" "}
            {result.total_issues} temuan · {result.latency_ms} ms
          </p>
          <ul className="mt-2 space-y-2">
            {(result.findings || []).map((f, i) => (
              <li key={i} className="text-sm">
                <span className="font-mono text-xs px-1 rounded bg-slate-700">
                  {f.severity}
                </span>{" "}
                <b>{f.title}</b>{" "}
                <span className="text-slate-400">(baris {f.line})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </main>
  );
}
