"""Attack tests against the vulnerable variant (expected to SUCCEED = the flaw exists)
and regression tests against the secure variant (expected to be BLOCKED)."""
import time

from .conftest import token


# ---------- reproduction of flaws (vulnerable variant) ----------
def test_vuln_client_can_claim_admin_role(vuln):
    r = vuln.get("/admin/users", headers={"X-User": "mallory", "X-Role": "admin"})
    assert r.status_code == 200  # FLAW: privilege escalation by header


def test_vuln_user_reads_other_users_note(vuln):
    r = vuln.get("/profile/bob", headers={"X-User": "alice"})
    assert r.status_code == 200 and "private note" in r.json()["note"]  # FLAW: BOLA/IDOR


# ---------- authentication ----------
def test_health_is_public(sec):
    assert sec.get("/health").status_code == 200


def test_no_token_rejected(sec):
    assert sec.get("/profile").status_code == 401
    assert sec.get("/admin/users").status_code == 401


def test_forged_identity_headers_ignored(sec):
    r = sec.get("/admin/users", headers={"X-User": "root_admin", "X-Role": "admin"})
    assert r.status_code == 401


def test_tampered_token_rejected(sec):
    h = token(sec, "alice", "alice-test-pw")
    bad = {"Authorization": h["Authorization"][:-2] + "00"}
    assert sec.get("/profile", headers=bad).status_code == 401


def test_expired_token_rejected(sec, monkeypatch):
    h = token(sec, "alice", "alice-test-pw")
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 10_000)
    assert sec.get("/profile", headers=h).status_code == 401


def test_login_errors_do_not_reveal_user_existence(sec):
    a = sec.post("/login", json={"username": "alice", "password": "wrong"})
    b = sec.post("/login", json={"username": "nobody", "password": "wrong"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_oversized_input_rejected(sec):
    r = sec.post("/login", json={"username": "a" * 1000, "password": "x"})
    assert r.status_code == 422


# ---------- authorization ----------
def test_normal_user_cannot_access_admin(sec):
    h = token(sec, "alice", "alice-test-pw")
    assert sec.get("/admin/users", headers=h).status_code == 403


def test_admin_can_access_admin(sec):
    h = token(sec, "root_admin", "admin-test-pw")
    r = sec.get("/admin/users", headers=h)
    assert r.status_code == 200 and len(r.json()) == 3


def test_user_cannot_read_other_profile(sec):
    h = token(sec, "alice", "alice-test-pw")
    assert sec.get("/profile/bob", headers=h).status_code == 403


def test_user_can_read_own_profile(sec):
    h = token(sec, "alice", "alice-test-pw")
    r = sec.get("/profile/alice", headers=h)
    assert r.status_code == 200 and r.json()["username"] == "alice"


def test_admin_can_read_any_profile(sec):
    h = token(sec, "root_admin", "admin-test-pw")
    assert sec.get("/profile/bob", headers=h).status_code == 200


def test_role_not_taken_from_request(sec):
    h = token(sec, "alice", "alice-test-pw")
    h["X-Role"] = "admin"
    assert sec.get("/admin/users", headers=h).status_code == 403


# ---------- hardening / logging ----------
def test_security_headers_present(sec):
    r = sec.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


def test_denials_are_logged_without_secrets(sec, caplog):
    h = token(sec, "alice", "alice-test-pw")
    with caplog.at_level("WARNING", logger="lab01.security"):
        sec.get("/admin/users", headers=h)
    text = caplog.text
    assert "authz_denied" in text
    assert "alice-test-pw" not in text and h["Authorization"][7:] not in text
