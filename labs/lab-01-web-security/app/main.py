"""Lab 01: toy API used to study authentication vs authorization.

create_app(secure=False) builds an INTENTIONALLY VULNERABLE variant for local study.
create_app(secure=True) builds the fixed variant.
Synthetic users and passwords only. Do not deploy either variant.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

log = logging.getLogger("lab01.security")

TOKEN_TTL_SECONDS = 900
_ITER = 100_000


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)


def _make_users() -> dict:
    users = {}
    for name, pw, role in [
        ("alice", "alice-test-pw", "user"),
        ("bob", "bob-test-pw", "user"),
        ("root_admin", "admin-test-pw", "admin"),
    ]:
        salt = secrets.token_bytes(16)
        users[name] = {"salt": salt, "hash": _hash(pw, salt), "role": role,
                       "email": f"{name}@example.test", "note": f"private note for {name}"}
    return users


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


def create_app(secure: bool = True) -> FastAPI:
    app = FastAPI(title=f"lab01 ({'secure' if secure else 'VULNERABLE'})")
    users = _make_users()
    secret = os.environ.get("LAB_SIGNING_SECRET") or secrets.token_hex(32)
    secret_b = secret.encode()
    dummy_salt = secrets.token_bytes(16)

    # ---------- token helpers (secure variant) ----------
    def issue_token(sub: str) -> str:
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": sub, "exp": int(time.time()) + TOKEN_TTL_SECONDS}).encode()
        ).decode()
        sig = hmac.new(secret_b, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}"

    def verify_token(token: str):
        try:
            payload, sig = token.split(".", 1)
            expected = hmac.new(secret_b, payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            data = json.loads(base64.urlsafe_b64decode(payload.encode()))
            if data["exp"] < time.time() or data["sub"] not in users:
                return None
            return data["sub"]
        except Exception:
            return None

    # ---------- middleware ----------
    @app.middleware("http")
    async def headers(request: Request, call_next):
        resp = await call_next(request)
        if secure:
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------- identity ----------
    def current_user(
        authorization: str | None = Header(default=None),
        x_user: str | None = Header(default=None),
        x_role: str | None = Header(default=None),
    ) -> dict:
        if not secure:
            # VULNERABLE: identity and role are taken from client-controlled headers.
            if not x_user:
                raise HTTPException(401, "missing X-User")
            return {"name": x_user, "role": x_role or "user"}
        if not authorization or not authorization.startswith("Bearer "):
            log.warning("authn_denied reason=missing_token")
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
        sub = verify_token(authorization[7:])
        if sub is None:
            log.warning("authn_denied reason=invalid_token")
            raise HTTPException(401, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
        # Role comes from the server-side store, never from the request.
        return {"name": sub, "role": users[sub]["role"]}

    # ---------- routes ----------
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/login")
    def login(body: LoginBody):
        u = users.get(body.username)
        salt = u["salt"] if u else dummy_salt
        ok = hmac.compare_digest(_hash(body.password, salt), u["hash"] if u else b"x" * 32)
        if not u or not ok:
            log.warning("login_failed")
            raise HTTPException(401, "invalid credentials")  # same message for both cases
        return {"access_token": issue_token(body.username), "token_type": "bearer"}

    @app.get("/profile")
    def my_profile(user: dict = Depends(current_user)):
        u = users.get(user["name"])
        if not u:
            raise HTTPException(404, "not found")
        return {"username": user["name"], "email": u["email"], "role": u["role"]}

    @app.get("/profile/{username}")
    def get_profile(username: str, user: dict = Depends(current_user)):
        if secure and user["name"] != username and user["role"] != "admin":
            log.warning("authz_denied actor=%s target=%s", user["name"], username)
            raise HTTPException(403, "forbidden")
        u = users.get(username)
        if not u:
            raise HTTPException(404, "not found")
        return {"username": username, "email": u["email"], "note": u["note"]}

    @app.get("/admin/users")
    def admin_users(user: dict = Depends(current_user)):
        if user["role"] != "admin":
            if secure:
                log.warning("authz_denied actor=%s resource=admin", user["name"])
            raise HTTPException(403, "forbidden")
        return [{"username": n, "role": v["role"], "email": v["email"]} for n, v in users.items()]

    return app


# `uvicorn app.main:app` runs the SECURE variant. Use app.main:vulnerable_app only on localhost for study.
app = create_app(secure=True)
vulnerable_app = create_app(secure=False)
