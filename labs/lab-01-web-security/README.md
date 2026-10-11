# Lab 01 — Auth & access control (Week 1) + Web/API vulnerabilities (Week 2)

Local-only toy API with a deliberately vulnerable variant (`create_app(secure=False)`) and a fixed one (`create_app(secure=True)`). Week 2 extended the same app with BOLA/IDOR (`/orders/{id}`), SQL injection (`/search`), XSS (`/echo`), SSRF (`/fetch-avatar`), and path traversal (`/files`).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pytest -q
uvicorn app.main:app --port 8001        # secure variant, localhost only
```
Try with curl (secure): `POST /login` → use the bearer token on `/profile`, `/admin/users`, `/orders/{id}`, `/search?q=`, `/fetch-avatar`, `/files?name=`. `/echo?msg=` needs no token.
Synthetic users: alice, bob (role user), root_admin (admin). Test passwords are in `tests/test_auth.py`; they protect nothing real.

Optional: proxy the requests through Burp Suite Community Edition or browser dev tools and observe headers.

Last run (2026-10-12, Python 3.11.9, FastAPI 0.141.1): 33 passed. No rate limiting, token revocation, TLS, real DNS resolution (SSRF), or filesystem sandboxing (path traversal) in this lab.
