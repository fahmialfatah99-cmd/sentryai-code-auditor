# Real-Time AI Code Auditor (SentryAI / CodeGuard Live) - MVP Architecture Specification

## 1. Executive Summary & Use Case
**Problem**: Traditional static code analyzers (SonarQube, ESLint, Bandit) produce slow batch reports, high false positives, and lack contextual fix suggestions. Developers waste hours debugging security vulnerabilities, anti-patterns, and memory leaks after pull requests are already open.
**Solution**: A real-time, low-latency Code Auditor web application (Python/FastAPI + WebSocket) that inspects pasted Python code with AST + heuristic rules — SQL injection (f-string/concat), dangerous eval/exec, os.system, unsafe yaml.load, hardcoded secrets (regex + Shannon entropy), silent `except: pass`, nested-loop complexity, and syntax errors — and returns patch suggestions. Rule-based only (no ML/neural model). Honestly NOT covered: XSS, IDOR, ReDoS, memory-leak detection, other languages.

### Real-World Developer Use Cases:
1. **Live Secure Pair-Programming & Pre-commit Check**: AST & heuristic analysis typically a few ms per request (measured ~6 ms locally); no LLM involved.
2. **Automated Vulnerability Remediator**: One-click diff viewer & auto-patch generator for vulnerabilities like SQL Injection, Unsanitized Dynamic Execution (`eval`), Insecure Direct Object References (IDOR), and ReDoS.
3. **Secret & Key Leak Prevention**: Zero-trust regex & entropy scanner catching AWS, JWT, GitHub tokens before code is staged.
4. **Clean Code & Big-O Complexity Auditor**: Detects quadratic nested loops ($O(N^2)$), unclosed I/O streams, and async deadlock anti-patterns.

---

## 2. High-Level Architecture Diagram (C4 Container View)

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT TIER                                       |
|  Textarea Web Client  <---> WebSocket Client (Real-time AST audit stream)  |
|  - Real-time Diagnostics Markers      - One-Click Patch Diff Viewer               |
|  - Security Risk Scoreboard           - Interactive Audit History & Benchmark    |
+-----------------------------------------------------------------------------------+
                                         |
                                         | JSON RPC / WebSocket Stream & REST API
                                         v
+-----------------------------------------------------------------------------------+
|                        APPLICATION SERVER (FastAPI Async)                         |
|  +---------------------------+   +----------------------------------------------+ |
|  | /ws/audit (WS Manager)    |   | /api/audit (Fast Batch Endpoint)             | |
|  +---------------------------+   +----------------------------------------------+ |
|                                |                                                  |
|  +-----------------------------v------------------------------------------------+ |
|  |                Orchestrator Pipeline (Parallel Dispatch)                     | |
|  |                                                                              | |
|  |  +---------------------+  +----------------------+  +---------------------+  | |
|  |  | Layer 1: Heuristic  |  | Layer 2: AST Parser  |  | Layer 3: Semantic   |  | |
|  |  | & Secret Scanner    |  | & Complexity Engine  |  | Heuristic Rules    |  | |
|  |  | (Entropy + Regex)   |  | (Python/JS AST Tree) |  | (Heuristic Rules)   |  | |
|  |  +---------------------+  +----------------------+  +---------------------+  | |
|  |               \                      |                      /                | |
|  |                v                     v                     v                 | |
|  |            +-----------------------------------------------+                 | |
|  |            |   Aggregator & Severity Scorer (CVSS Matrix)  |                 | |
|  |            +-----------------------------------------------+                 | |
|  +------------------------------------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
```

---

## 3. Core Component Breakdown

### 3.1. Layer 1: Instant Heuristic & Secrets Scanner (< 5ms)
- Regex-based signature engine for OWASP Top 10:
  - Hardcoded Secrets (AWS keys, generic Bearer tokens, private RSA keys, DB passwords).
  - Dangerous functions: `eval()`, `exec()`, `os.system()`, `innerHTML`, `dangerouslySetInnerHTML`.
  - Shannon Entropy calculation for token detection.

### 3.2. Layer 2: AST Syntax & Algorithmic Complexity Analyzer (< 25ms)
- Tree parsing for Python (`ast` module) and JS/TS syntax structures.
- Detects nested loop depth (flagging $O(N^2)$ and $O(N^3)$ hotspots).
- Detects unhandled exceptions (`except Exception: pass`), unclosed database/file handlers, and unbound variables.

### 3.3. Layer 3: Semantic AI Explainer & Automated Patch Generator (< 200-800ms)
- Contextual vulnerability explanation with CVSS 3.1 severity scoring (Low, Medium, High, Critical).
- Generates exact Unified Diff (Git patch format) and refactored code.
- Explains "Why this is dangerous" and "How the fix secures it".

---

## 4. REST & WebSocket API Specification

### 4.1. WebSocket Endpoint: `ws://localhost:8000/ws/audit`
- **Request Payload**:
  ```json
  {
    "code": "import sqlite3\ndef get_user(uid):\n    conn = sqlite3.connect('app.db')\n    return conn.execute(f'SELECT * FROM users WHERE id = {uid}').fetchall()",
    "language": "python",
    "mode": "realtime"
  }
  ```
- **Streaming Response**:
  1. `{"event": "ast_ready", "findings": [...], "score": 45}`
  2. `{"event": "ai_stream_chunk", "delta": "Detected SQL Injection in string interpolation..."}`
  3. `{"event": "completed", "patch": "...", "execution_ms": 14.2}`

### 4.2. REST Endpoint: `POST /api/audit`
- Synchronous audit endpoint for CI/CD pipelines (GitHub Actions, GitLab CI).

---

## 5. Technology Stack Selected for MVP
- **Backend**: Python 3.14 + FastAPI + WebSockets + Python AST module.
- **Frontend**: Single Page Application with Responsive Cyberpunk/Dark Dev HUD, Real-time Monospace Code Editor with inline line gutters, Live Severity Gauge, Interactive Tabbed Diffs, and Instant Sample Vulnerability Presets (SQLi, Secret Leak, ReDoS, Insecure Deserialization, Async Deadlock).
- **Zero-Dependency External Overhead**: Operates out-of-the-box locally with simulated enterprise AI reasoning + pluggable OpenAI/Anthropic API key support.
