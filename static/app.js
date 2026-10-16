/**
 * SentryAI Frontend Client
 * WebSocket Real-Time synchronization, live line numbers, presets, and diff preview
 */

let ws = null;
let currentPatchCode = "";
let debounceTimer = null;

const PRESETS = {
  sqli: `import sqlite3

def query_user_records(user_id):
    # Vulnerable SQL direct f-string interpolation
    db = sqlite3.connect("production.db")
    cursor = db.cursor()
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    return cursor.execute(query).fetchall()
`,
  rce: `import json

def process_dynamic_payload(raw_json_str):
    # CRITICAL: eval used to parse JSON payload
    payload = eval(raw_json_str)
    return payload.get("action", "noop")
`,
  secrets: `import requests

# CRITICAL: Hardcoded AWS credentials & API tokens
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE12"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def fetch_s3_bucket():
    return requests.get("https://s3.amazonaws.com", auth=(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY))
`,
  loops: `def find_duplicate_items(dataset):
    # Quadratic complexity O(N^2)
    duplicates = []
    for i in range(len(dataset)):
        for j in range(len(dataset)):
            if i != j and dataset[i] == dataset[j]:
                duplicates.append(dataset[i])
    return duplicates
`,
  clean: `import os
import sqlite3
import logging

logger = logging.getLogger(__name__)

def fetch_user_secure(user_id: int):
    """Secure database query using parameterized bound values."""
    db_path = os.getenv("DB_PATH", "app.db")
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
        return cursor.fetchone()
`
};

// Initialize WebSocket Connection
function initWebSocket() {
  const loc = window.location;
  let wsUri = (loc.protocol === "https:" ? "wss://" : "ws://") + loc.host + "/ws/audit";
  
  const statusBadge = document.getElementById("connectionBadge");
  const statusText = document.getElementById("connectionText");

  try {
    ws = new WebSocket(wsUri);

    ws.onopen = () => {
      statusBadge.querySelector(".status-dot").classList.add("connected");
      statusText.textContent = "CONNECTED (LIVE AST)";
      logTerminal("[WS] Connected to SentryAI Real-Time Audit Socket.");
      // Trigger initial audit
      triggerAudit();
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "audit_result") {
          renderAuditResults(payload.data);
        } else if (payload.type === "error") {
          logTerminal(`[ERROR] ${payload.message}`);
        }
      } catch (err) {
        logTerminal(`[ERROR] Failed to parse socket message: ${err}`);
      }
    };

    ws.onclose = () => {
      statusBadge.querySelector(".status-dot").classList.remove("connected");
      statusText.textContent = "OFFLINE (RECONNECTING...)";
      logTerminal("[WS] Connection lost. Reconnecting in 2 seconds...");
      setTimeout(initWebSocket, 2000);
    };

    ws.onerror = (err) => {
      console.error("WS Error:", err);
      ws.close();
    };
  } catch (err) {
    statusText.textContent = "STANDALONE MODE";
  }
}

// Update line gutters
function updateGutter() {
  const editor = document.getElementById("codeEditor");
  const gutter = document.getElementById("lineGutter");
  const lineCount = editor.value.split("\n").length;
  let gutterContent = "";
  for (let i = 1; i <= Math.max(lineCount, 1); i++) {
    gutterContent += i + "<br>";
  }
  gutter.innerHTML = gutterContent;
}

// Sync Editor Scroll
const codeEditor = document.getElementById("codeEditor");
const lineGutter = document.getElementById("lineGutter");

codeEditor.addEventListener("scroll", () => {
  lineGutter.scrollTop = codeEditor.scrollTop;
});

// Real-time live input listener with 200ms debounce
codeEditor.addEventListener("input", () => {
  updateGutter();
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    triggerAudit();
  }, 200);
});

// Trigger audit via WS or fallback REST
function triggerAudit() {
  const code = codeEditor.value;
  if (!code.trim()) {
    renderEmptyState();
    return;
  }

  const langEl = document.getElementById("langSelect");
  const lang = langEl ? langEl.value : "python";
  const payload = {
    code: code,
    language: lang
  };

  showAuditMood("/static/lottie/loading.lottie", true);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
    fetchHistoryMini();
  } else {
    // REST API fallback
    fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => { renderAuditResults(data); rememberAuditId(data); fetchHistoryMini(); })
    .catch(err => logTerminal(`[REST ERROR] ${err.message}`));
  }
}

// Render Auditor Output
function showAuditMood(src, loop) {
  const el = document.getElementById("auditMood");
  if (!el) return;
  el.style.display = "block";
  if (el.getAttribute("src") !== src) el.setAttribute("src", src);
  try { el.loop = !!loop; } catch (e) {}
}

function renderAuditResults(data) {
  const mood = document.getElementById("auditMood");
  if (mood) {
    if ((data.total_issues || 0) === 0) {
      showAuditMood("/static/lottie/success.lottie", false);
    } else {
      mood.style.display = "none";
    }
  }
  // Latency
  document.getElementById("latencyMetric").innerHTML = `<i class="fa-solid fa-stopwatch"></i> ${data.latency_ms} ms`;
  logTerminal(`[AUDIT] Processed in ${data.latency_ms}ms | Findings: ${data.total_issues} | Score: ${data.health_score}`);

  // Health Score & Gauge
  const scoreEl = document.getElementById("healthScore");
  const circleEl = document.getElementById("scoreCircle");
  const gradeEl = document.getElementById("riskGrade");
  const findingCountEl = document.getElementById("findingCount");

  scoreEl.textContent = data.health_score;
  gradeEl.textContent = data.risk_grade;
  gradeEl.style.color = data.status_color;
  circleEl.style.borderColor = data.status_color;
  circleEl.style.boxShadow = `0 0 15px ${data.status_color}55`;
  findingCountEl.textContent = `${data.total_issues} issue${data.total_issues === 1 ? '' : 's'} detected`;

  // Pills count
  let crit = 0, high = 0, warn = 0;
  data.findings.forEach(f => {
    const s = f.severity.toUpperCase();
    if (s === "CRITICAL") crit++;
    else if (s === "HIGH") high++;
    else warn++;
  });

  document.getElementById("critCount").textContent = crit;
  document.getElementById("highCount").textContent = high;
  document.getElementById("warnCount").textContent = warn;
  document.getElementById("tabCount").textContent = data.total_issues;

  // Findings List
  const listEl = document.getElementById("findingsList");
  if (data.findings.length === 0) {
    listEl.innerHTML = `
      <div class="empty-state">
        <i class="fa-solid fa-shield-check"></i>
        <p>No vulnerabilities detected. AST and pattern checks are clean!</p>
      </div>
    `;
  } else {
    listEl.innerHTML = data.findings.map(f => {
      const sevClass = f.severity.toLowerCase();
      return `
        <div class="finding-item sev-${sevClass}">
          <div class="finding-header">
            <span class="finding-badge sev-${sevClass}">${f.severity} // ${f.rule_id}</span>
            <span class="finding-line">Line ${f.line}</span>
          </div>
          <div class="finding-title">${f.title}</div>
          <div class="finding-desc">${f.description}</div>
          <div class="finding-suggestion">
            <i class="fa-solid fa-circle-info"></i>
            <div><strong>Recommended Remediation:</strong> ${f.suggestion}</div>
          </div>
        </div>
      `;
    }).join("");
  }

  // Patch
  currentPatchCode = data.patch;
  document.getElementById("patchedCodeDisplay").textContent = data.patch;
  const actionsList = document.getElementById("patchActionList");
  actionsList.innerHTML = (data.patch_actions || []).map(act => `<li><i class="fa-solid fa-check"></i> ${act}</li>`).join("");
}

function renderEmptyState() {
  document.getElementById("healthScore").textContent = "100";
  document.getElementById("riskGrade").textContent = "A+ SECURE";
  document.getElementById("findingCount").textContent = "0 issues detected";
  document.getElementById("findingsList").innerHTML = `
    <div class="empty-state">
      <i class="fa-solid fa-shield-check"></i>
      <p>No vulnerabilities detected. Start typing or choose a preset above.</p>
    </div>
  `;
}

// Preset Loader
function loadPreset(key) {
  if (PRESETS[key]) {
    codeEditor.value = PRESETS[key];
    updateGutter();
    triggerAudit();
    logTerminal(`[PRESET] Loaded preset template: ${key.toUpperCase()}`);
  }
}

// Tab switcher
function switchTab(tabId) {
  document.getElementById("tabFindings").classList.toggle("active", tabId === "findings");
  document.getElementById("tabPatch").classList.toggle("active", tabId === "patch");
  document.getElementById("findingsView").classList.toggle("active", tabId === "findings");
  document.getElementById("patchView").classList.toggle("active", tabId === "patch");
}

// Apply Patch to Editor
function applyPatchedCode() {
  if (currentPatchCode) {
    codeEditor.value = currentPatchCode;
    updateGutter();
    triggerAudit();
    switchTab("findings");
    logTerminal("[REMEDIATION] Successfully applied AST automated patch to editor buffer.");
  }
}

function clearEditor() {
  codeEditor.value = "";
  updateGutter();
  renderEmptyState();
}

function copyCode() {
  navigator.clipboard.writeText(codeEditor.value);
  logTerminal("[CLIPBOARD] Source code copied to clipboard.");
}

function logTerminal(msg) {
  const term = document.getElementById("terminalLogs");
  const div = document.createElement("div");
  const time = new Date().toLocaleTimeString();
  div.textContent = `[${time}] ${msg}`;
  term.appendChild(div);
  term.scrollTop = term.scrollHeight;
}

// Start application
window.addEventListener("DOMContentLoaded", () => {
  loadPreset("sqli");
  initWebSocket();
});

let lastAuditId = null;
function rememberAuditId(data) {
  if (data && data.audit_id) {
    lastAuditId = data.audit_id;
    const b = document.getElementById("dlReportBtn");
    if (b) b.style.display = "";
  }
}
function downloadReport() {
  if (lastAuditId) window.open("/api/report/" + lastAuditId, "_blank");
}
async function fetchHistoryMini() {
  try {
    const res = await fetch("/api/history?limit=5");
    const d = await res.json();
    const el = document.getElementById("historyMini");
    if (!el) return;
    const rows = d.history || [];
    el.textContent = rows.length
      ? "Riwayat: " + rows.map(r => `#${r.id} ${r.score} (${r.issues})`).join(" · ")
      : "Riwayat: kosong";
  } catch (e) {}
}
window.addEventListener("DOMContentLoaded", () => { fetchHistoryMini(); });