import pytest
from engine.auditor import audit_source_code

def test_sql_injection_detection():
    vulnerable_sql = """
def get_user(uid):
    conn = get_db()
    return conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall()
"""
    result = audit_source_code(vulnerable_sql, "python")
    assert result["total_issues"] > 0
    assert any("SQL Injection" in f["title"] for f in result["findings"])
    assert "conn.execute(\"SELECT * FROM users WHERE id = ?\", (uid,))" in result["patch"]

def test_hardcoded_secrets_detection():
    secret_code = 'AWS_SECRET_ACCESS_KEY = "AKIA1234567890ABCDEF1234567890"'
    result = audit_source_code(secret_code, "python")
    assert any("Secret" in f["title"] for f in result["findings"])
    assert "os.getenv" in result["patch"]

def test_eval_rce_detection():
    eval_code = "data = eval(user_input)"
    result = audit_source_code(eval_code, "python")
    assert any("Dangerous Dynamic Evaluation" in f["title"] for f in result["findings"])
    assert "ast.literal_eval" in result["patch"]

def test_nested_loop_performance():
    nested_code = """
for i in range(100):
    for j in range(100):
        print(i, j)
"""
    result = audit_source_code(nested_code, "python")
    assert any("Quadratic/Polynomial Complexity" in f["title"] for f in result["findings"])

if __name__ == "__main__":
    test_sql_injection_detection()
    test_hardcoded_secrets_detection()
    test_eval_rce_detection()
    test_nested_loop_performance()
    print("All Auditor Engine tests passed successfully!")
