"""Week 2: Web/API vulnerabilities (BOLA/IDOR, SQLi, XSS, SSRF, path traversal).
Attack tests against the vulnerable variant (expected to SUCCEED = the flaw exists)
and regression tests against the secure variant (expected to be BLOCKED)."""
from .conftest import token


# ---------- BOLA / IDOR ----------
def test_vuln_idor_reads_others_order(vuln):
    r = vuln.get("/orders/2", headers={"X-User": "alice"})
    assert r.status_code == 200 and r.json()["owner"] == "bob"  # FLAW: BOLA/IDOR


def test_idor_blocked_cross_user(sec):
    h = token(sec, "alice", "alice-test-pw")
    assert sec.get("/orders/2", headers=h).status_code == 403


def test_owner_can_read_own_order(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.get("/orders/1", headers=h)
    assert r.status_code == 200 and r.json()["owner"] == "alice"


def test_admin_can_read_any_order(sec):
    h = token(sec, "root_admin", "admin-test-pw")
    assert sec.get("/orders/2", headers=h).status_code == 200


# ---------- SQL injection ----------
def test_vuln_sqli_union_exfiltrates_users(vuln):
    payload = "' UNION SELECT username FROM users --"
    r = vuln.get("/search", params={"q": payload}, headers={"X-User": "alice"})
    assert r.status_code == 200
    names = [row["name"] for row in r.json()]
    assert "root_admin" in names  # FLAW: SQLi exfiltrates the users table


def test_sqli_blocked_by_parameterization(sec):
    h = token(sec, "alice", "alice-test-pw")
    payload = "' UNION SELECT username FROM users --"
    r = sec.get("/search", params={"q": payload}, headers=h)
    assert r.status_code == 200
    names = [row["name"] for row in r.json()]
    assert "root_admin" not in names


def test_search_finds_matching_product(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.get("/search", params={"q": "widget"}, headers=h)
    assert r.status_code == 200
    assert any(row["name"] == "widget-stand" for row in r.json())


# ---------- XSS ----------
def test_vuln_xss_reflects_script_unescaped(vuln):
    payload = "<script>alert(1)</script>"
    r = vuln.get("/echo", params={"msg": payload})
    assert r.status_code == 200 and payload in r.text  # FLAW: reflected XSS


def test_xss_output_escaped(sec):
    payload = "<script>alert(1)</script>"
    r = sec.get("/echo", params={"msg": payload})
    assert r.status_code == 200
    assert payload not in r.text
    assert "&lt;script&gt;" in r.text


def test_echo_sets_csp_header(sec):
    r = sec.get("/echo", params={"msg": "hi"})
    assert "Content-Security-Policy" in r.headers


# ---------- SSRF ----------
def test_vuln_ssrf_reaches_internal_metadata(vuln):
    r = vuln.post(
        "/fetch-avatar",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers={"X-User": "alice"},
    )
    assert r.status_code == 200
    assert "cloud-credentials" in r.json()["body"]  # FLAW: SSRF reaches internal metadata


def test_ssrf_blocked_internal_host(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.post(
        "/fetch-avatar",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=h,
    )
    assert r.status_code == 400


def test_ssrf_allows_external_host(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.post("/fetch-avatar", json={"url": "https://example.com/avatar.png"}, headers=h)
    assert r.status_code == 200


# ---------- path traversal ----------
def test_vuln_path_traversal_reads_secret_outside_root(vuln):
    r = vuln.get("/files", params={"name": "../secret.txt"}, headers={"X-User": "alice"})
    assert r.status_code == 200 and "top-secret" in r.text  # FLAW: path traversal


def test_path_traversal_blocked(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.get("/files", params={"name": "../secret.txt"}, headers=h)
    assert r.status_code == 400


def test_files_serves_public_notes(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.get("/files", params={"name": "notes.txt"}, headers=h)
    assert r.status_code == 200 and "welcome" in r.text
