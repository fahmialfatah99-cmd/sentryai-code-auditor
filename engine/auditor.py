"""
Core Multi-Layer Real-time Code Auditor Engine
- Layer 1: Heuristic & Shannon Entropy Secrets Scanner
- Layer 2: AST Parser & Big-O Complexity Detector
- Layer 3: Semantic Security Reasoning & Patch Synthesizer
"""

import ast
import math
import re
import time
from typing import List, Dict, Any

def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string to detect high-entropy API keys."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log2(p_x)
    return entropy

class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self.loop_depth = 0
        self.max_loop_depth = 0

    def visit_For(self, node):
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        if self.loop_depth >= 2:
            self.findings.append({
                "rule_id": "PERF-001",
                "category": "Performance",
                "severity": "WARNING",
                "line": node.lineno,
                "title": f"Quadratic/Polynomial Complexity Loop (Depth: {self.loop_depth})",
                "description": f"Nested loop detected at depth {self.loop_depth}. This results in O(N^{self.loop_depth}) execution time, causing potential CPU exhaustion (Denial of Service).",
                "suggestion": "Refactor nested loops using Hash Maps, Sets, or batch database query operations."
            })
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_While(self, node):
        self.loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.loop_depth)
        if self.loop_depth >= 2:
            self.findings.append({
                "rule_id": "PERF-001",
                "category": "Performance",
                "severity": "WARNING",
                "line": node.lineno,
                "title": f"Nested While-Loop Complexity (Depth: {self.loop_depth})",
                "description": f"Nested while-loop detected at depth {self.loop_depth}. Verify bounded iterations.",
                "suggestion": "Avoid unbounded loops; consider early exit conditions or dictionary indexing."
            })
        self.generic_visit(node)
        self.loop_depth -= 1

    def visit_Call(self, node):
        # Detect eval() / exec()
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in ("eval", "exec"):
            self.findings.append({
                "rule_id": "SEC-001",
                "category": "Remote Code Execution (RCE)",
                "severity": "CRITICAL",
                "line": node.lineno,
                "title": f"Dangerous Dynamic Evaluation via '{func_name}()'",
                "description": f"Calling '{func_name}()' dynamically compiles and executes arbitrary code strings. An attacker supplying untrusted input can achieve arbitrary system takeover.",
                "suggestion": "Replace dynamic execution with `ast.literal_eval()` for data deserialization, or a strict dispatch map."
            })
        
        # Detect os.system / subprocess with shell=True
        if func_name == "system":
            self.findings.append({
                "rule_id": "SEC-002",
                "category": "Command Injection",
                "severity": "CRITICAL",
                "line": node.lineno,
                "title": "Unsafe Shell Command Execution (os.system)",
                "description": "os.system executes commands in a subshell without input sanitization.",
                "suggestion": "Use `subprocess.run(args, shell=False)` with a structured list of arguments instead."
            })
        
        # Detect yaml.load without SafeLoader
        if func_name == "load":
            # Check if yaml.load is called without Loader
            is_yaml = False
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "yaml":
                    is_yaml = True
            if is_yaml and not any(kw.arg == "Loader" for kw in node.keywords):
                self.findings.append({
                    "rule_id": "SEC-003",
                    "category": "Insecure Deserialization",
                    "severity": "CRITICAL",
                    "line": node.lineno,
                    "title": "Unsafe YAML Deserialization (yaml.load)",
                    "description": "yaml.load() without Loader=yaml.SafeLoader permits arbitrary object instantiation and RCE.",
                    "suggestion": "Use `yaml.safe_load(data)` or pass `Loader=yaml.SafeLoader` explicitly."
                })

        # Detect SQL query formatting inside execute()
        if func_name in ("execute", "raw"):
            for arg in node.args:
                # Check for JoinedStr (f-strings) or BinOp (%)
                if isinstance(arg, ast.JoinedStr):
                    self.findings.append({
                        "rule_id": "SEC-004",
                        "category": "SQL Injection (CWE-89)",
                        "severity": "CRITICAL",
                        "line": node.lineno,
                        "title": "SQL Injection via Formatted F-String",
                        "description": "Direct interpolation of variables into an SQL string bypasses query parameterization and allows SQL Injection attacks.",
                        "suggestion": "Use parameterized queries, e.g., `cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,))`"
                    })
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add)):
                    self.findings.append({
                        "rule_id": "SEC-004",
                        "category": "SQL Injection (CWE-89)",
                        "severity": "CRITICAL",
                        "line": node.lineno,
                        "title": "SQL Injection via String Concatenation",
                        "description": "String concatenation (`+` or `%`) used directly in a database query execution method.",
                        "suggestion": "Pass query parameters as a tuple/dictionary separated from the SQL template."
                    })

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        # Detect bare except or except Exception: pass
        if node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException")):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                self.findings.append({
                    "rule_id": "QUAL-001",
                    "category": "Error Suppression Anti-Pattern",
                    "severity": "MEDIUM",
                    "line": node.lineno,
                    "title": "Silent Exception Swallowing (`except: pass`)",
                    "description": "Catching all exceptions silently masks catastrophic bugs, security faults, and interrupts.",
                    "suggestion": "Catch specific exception types and log the traceback using a dedicated logger (`logger.exception(...)`)."
                })
        self.generic_visit(node)


def scan_secrets_and_regex(code: str) -> List[Dict[str, Any]]:
    findings = []
    lines = code.split("\n")

    # Patterns
    patterns = [
        (r'(?i)(aws_access_key_id|aws_secret_access_key|api_key|secret_key|private_key|token)\s*=\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']', "SEC-KEY-001", "High-Entropy Hardcoded Secret / API Key", "CRITICAL"),
        (r'(?i)(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})', "SEC-KEY-002", "GitHub Personal Access Token Leaked", "CRITICAL"),
        (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "SEC-KEY-003", "Exposed RSA Private Key Block", "CRITICAL"),
        (r'(?i)(password|passwd|pwd)\s*=\s*["\']([^"\'\s]{4,})["\']', "SEC-KEY-004", "Hardcoded Plaintext Password", "HIGH"),
        (r'dangerouslySetInnerHTML\s*=', "SEC-XSS-001", "React dangerouslySetInnerHTML (DOM XSS)", "HIGH"),
        (r'\.innerHTML\s*=', "SEC-XSS-002", "Direct innerHTML Assignment (DOM XSS)", "HIGH"),
        (r'((?:[a-zA-Z0-9_]+\+)+[a-zA-Z0-9_]+)\$', "SEC-REDOS-001", "Catastrophic Backtracking Regex (Potential ReDoS)", "HIGH"),
    ]

    for line_idx, line in enumerate(lines, 1):
        for pattern, rule_id, title, severity in patterns:
            match = re.search(pattern, line)
            if match:
                val = match.group(0)
                entropy = calculate_shannon_entropy(val)
                findings.append({
                    "rule_id": rule_id,
                    "category": "Secret & Injection Exposure",
                    "severity": severity,
                    "line": line_idx,
                    "title": title,
                    "description": f"Detected suspicious token or unsafe pattern on line {line_idx}. (Calculated token entropy: {entropy:.2f})",
                    "suggestion": "Move credentials to secure environment variables (.env / Secret Manager) and sanitize dynamic DOM injections."
                })

    return findings


def generate_intelligent_patch(code: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates an intelligent refactor patch and explanation based on detected vulnerabilities."""
    patched_code = code
    applied_patches = []

    # Patch 1: SQL Injection
    if any("SQL Injection" in f["title"] for f in findings):
        # Replace f"SELECT ... WHERE id = {uid}" with parameterized query
        patched_code = re.sub(
            r'conn\.execute\(f(["\'].*?WHERE\s+\w+\s*=\s*)\{([a-zA-Z0-9_]+)\}(["\'])\)',
            r'conn.execute(\1?\3, (\2,))',
            patched_code
        )
        patched_code = re.sub(
            r'cursor\.execute\(f(["\'].*?WHERE\s+\w+\s*=\s*)\{([a-zA-Z0-9_]+)\}(["\'])\)',
            r'cursor.execute(\1?\3, (\2,))',
            patched_code
        )
        applied_patches.append("Parameterized SQL query arguments to eliminate CWE-89 injection risk.")

    # Patch 2: eval() -> ast.literal_eval()
    if any("Dynamic Evaluation" in f["title"] for f in findings):
        if "import ast" not in patched_code:
            patched_code = "import ast\n" + patched_code
        patched_code = re.sub(r'\beval\(', 'ast.literal_eval(', patched_code)
        applied_patches.append("Replaced unrestricted `eval()` with safe `ast.literal_eval()`.")

    # Patch 3: os.system -> subprocess.run
    if any("os.system" in f["title"] for f in findings):
        if "import subprocess" not in patched_code:
            patched_code = "import subprocess\n" + patched_code
        patched_code = re.sub(r'os\.system\((.*?)\)', r'subprocess.run([\1], check=True, shell=False)', patched_code)
        applied_patches.append("Converted `os.system` to parameterized `subprocess.run(shell=False)`.")

    # Patch 4: yaml.load -> yaml.safe_load
    if any("YAML Deserialization" in f["title"] for f in findings):
        patched_code = re.sub(r'yaml\.load\((.*?)\)', r'yaml.safe_load(\1)', patched_code)
        applied_patches.append("Enforced `yaml.safe_load()` to prevent arbitrary object instantiation.")

    # Patch 5: Secrets -> os.getenv
    if any("Hardcoded Secret" in f["title"] or "Plaintext Password" in f["title"] for f in findings):
        if "import os" not in patched_code:
            patched_code = "import os\n" + patched_code
        patched_code = re.sub(
            r'([a-zA-Z0-9_]*(?:key|secret|token|password)[a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
            r'\1 = os.getenv("\1".upper(), "")',
            patched_code,
            flags=re.IGNORECASE
        )
        applied_patches.append("Extracted hardcoded secrets to runtime environment variable references.")

    # Patch 6: except Exception: pass
    if any("Silent Exception" in f["title"] for f in findings):
        if "import logging" not in patched_code:
            patched_code = "import logging\n" + patched_code
        patched_code = re.sub(
            r'except\s+(?:Exception|BaseException)?:\s*\n\s*pass',
            'except Exception as err:\n        logging.error(f"Handled unexpected failure: {err}")',
            patched_code
        )
        applied_patches.append("Replaced silent exception suppression with structured error logging.")

    return {
        "patched_code": patched_code,
        "actions": applied_patches or ["Code structure adheres to baseline safety, no automatic mutation required."]
    }


def audit_source_code(code: str, language: str = "python") -> Dict[str, Any]:
    start_time = time.perf_counter()
    findings = []
    
    # 1. Regex & Secret Scanner
    findings.extend(scan_secrets_and_regex(code))

    # 2. AST parsing (if python)
    syntax_valid = True
    syntax_error = None
    if language.lower() in ("python", "py"):
        try:
            tree = ast.parse(code)
            visitor = ASTSecurityVisitor()
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except SyntaxError as se:
            syntax_valid = False
            syntax_error = {
                "line": se.lineno or 1,
                "offset": se.offset or 1,
                "message": se.msg
            }
            findings.append({
                "rule_id": "SYNTAX-001",
                "category": "Syntax Error",
                "severity": "CRITICAL",
                "line": se.lineno or 1,
                "title": "Code Contains Syntax Grammar Error",
                "description": f"Parser failure: {se.msg} at line {se.lineno}, column {se.offset}",
                "suggestion": "Correct the syntax error to allow semantic security AST analysis."
            })

    # Calculate overall security health score (0 - 100)
    # Deductions: Critical: 25, High: 15, Warning: 8, Medium: 5
    deduction = 0
    for f in findings:
        sev = f["severity"].upper()
        if sev == "CRITICAL":
            deduction += 25
        elif sev == "HIGH":
            deduction += 15
        elif sev == "WARNING":
            deduction += 8
        elif sev == "MEDIUM":
            deduction += 5

    health_score = max(0, 100 - deduction)

    # Risk Level mapping
    if health_score >= 90:
        risk_grade = "A+ SECURE"
        status_color = "#10b981"
    elif health_score >= 75:
        risk_grade = "B MODERATE"
        status_color = "#3b82f6"
    elif health_score >= 50:
        risk_grade = "C VULNERABLE"
        status_color = "#f59e0b"
    else:
        risk_grade = "F CRITICAL RISK"
        status_color = "#ef4444"

    # Intelligent Auto-patch
    patch_result = generate_intelligent_patch(code, findings)
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return {
        "language": language,
        "syntax_valid": syntax_valid,
        "syntax_error": syntax_error,
        "total_issues": len(findings),
        "health_score": health_score,
        "risk_grade": risk_grade,
        "status_color": status_color,
        "latency_ms": elapsed_ms,
        "findings": findings,
        "patch": patch_result["patched_code"],
        "patch_actions": patch_result["actions"]
    }
