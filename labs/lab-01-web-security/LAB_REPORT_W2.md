# Lab report: Week 2 — Web/API vulnerabilities (lab-01-web-security)

- Date / environment / versions: 2026-10-12, Python 3.11.9, FastAPI 0.141.1, Starlette 1.7.0, pytest 8.4.2, Windows 11 (PowerShell/Git Bash)
- Scope & authorization (own toy app only): `labs/lab-01-web-security`, a local synthetic FastAPI app created for this course. No real users, secrets, or external network targets. Tested against the vulnerable (`secure=False`) and secure (`secure=True`) variants of `create_app()` only.

## BOLA/IDOR — `/orders/{id}`

| Field | Entry |
|---|---|
| Asset | Orders table (owner-tagged records) |
| Trust boundary | Network edge; caller identity vs. object ownership |
| Attacker capability | Authenticated as any user; send arbitrary order ids |
| Preconditions | Valid account; knowledge/guessability of another user's order id |
| Reproduction steps | `GET /orders/2` with `X-User: alice` against `secure=False` |
| Expected vs observed | Expected 403 (alice does not own order 2); observed 200 with bob's order |
| Impact | Disclosure of another user's order data (C) |
| Root cause | Handler authenticated the caller but never checked ownership before returning the object |
| Mitigation | Require `user["name"] == order["owner"] or user["role"] == "admin"`, else 403 |
| Regression test (file::name) | `tests/test_web_vulns.py::test_idor_blocked_cross_user` |
| Post-fix result (actually run? Y/N, output) | Y — `pytest labs/lab-01-web-security -q` → 33 passed |
| Remaining risk / how tests could miss it | A new object-returning route is unprotected unless it repeats this check explicitly |

## SQL injection — `/search`

| Field | Entry |
|---|---|
| Asset | In-memory `products` table and mirrored `users` table (username/role) |
| Trust boundary | Network edge; query parameter vs. SQL query text |
| Attacker capability | Authenticated as any user; send arbitrary `q` search text |
| Preconditions | None beyond authentication |
| Reproduction steps | `GET /search?q=' UNION SELECT username FROM users --` against `secure=False` |
| Expected vs observed | Expected only product-name matches; observed `root_admin` (from `users`) in results |
| Impact | Disclosure of the users table via a product-search endpoint (C) |
| Root cause | Query built by f-string interpolation of client input into raw SQL |
| Mitigation | Parameterized query: `cursor.execute("... WHERE name LIKE ?", (f"%{q}%",))` |
| Regression test (file::name) | `tests/test_web_vulns.py::test_sqli_blocked_by_parameterization` |
| Post-fix result (actually run? Y/N, output) | Y — `pytest labs/lab-01-web-security -q` → 33 passed |
| Remaining risk / how tests could miss it | Only this one query path was audited; a second raw-SQL call elsewhere would not be caught by this test |

## Cross-site scripting — `/echo`

| Field | Entry |
|---|---|
| Asset | HTML response rendered in a caller's browser |
| Trust boundary | Network edge; query parameter vs. HTML output |
| Attacker capability | Unauthenticated; send arbitrary `msg` text in a link a victim might click |
| Preconditions | A victim must load a crafted URL (reflected XSS) |
| Reproduction steps | `GET /echo?msg=<script>alert(1)</script>` against `secure=False` |
| Expected vs observed | Expected HTML-escaped text in the response body; observed raw, executable `<script>` tag |
| Impact | Script execution in a victim's browser session (I/C, depending on what the session can do) |
| Root cause | Client input written into the HTML response with no output encoding |
| Mitigation | `html.escape(msg)` before embedding in the response, plus a `Content-Security-Policy: default-src 'none'` header as a second layer |
| Regression test (file::name) | `tests/test_web_vulns.py::test_xss_output_escaped` |
| Post-fix result (actually run? Y/N, output) | Y — `pytest labs/lab-01-web-security -q` → 33 passed |
| Remaining risk / how tests could miss it | Only reflected XSS on this one endpoint is covered; no stored or DOM-based XSS in this lab |

## SSRF — `/fetch-avatar`

| Field | Entry |
|---|---|
| Asset | Server's outbound fetch capability; simulated internal metadata/admin endpoints |
| Trust boundary | Network edge; client-supplied URL vs. server-initiated fetch |
| Attacker capability | Authenticated as any user; send an arbitrary URL for the server to "fetch" |
| Preconditions | None beyond authentication |
| Reproduction steps | `POST /fetch-avatar {"url": "http://169.254.169.254/latest/meta-data/"}` against `secure=False` |
| Expected vs observed | Expected 400 (internal host blocked); observed 200 with a simulated metadata body |
| Impact | Server-side reach into internal-only endpoints (C) — simulated here, not a real network call |
| Root cause | Fetch target accepted any URL with no scheme or destination validation before dispatch |
| Mitigation | Require `https` scheme; reject loopback/link-local/private IP literals and a short internal-name list before resolving |
| Regression test (file::name) | `tests/test_web_vulns.py::test_ssrf_blocked_internal_host` |
| Post-fix result (actually run? Y/N, output) | Y — `pytest labs/lab-01-web-security -q` → 33 passed |
| Remaining risk / how tests could miss it | No real DNS resolution is performed; a hostname that only *resolves* to an internal IP (rather than being a literal one) would not be caught |

## Path traversal — `/files`

| Field | Entry |
|---|---|
| Asset | Files outside the served `public/` directory (synthetic `secret.txt`) |
| Trust boundary | Network edge; query parameter vs. filesystem path |
| Attacker capability | Authenticated as any user; send an arbitrary `name` value |
| Preconditions | None beyond authentication |
| Reproduction steps | `GET /files?name=../secret.txt` against `secure=False` |
| Expected vs observed | Expected 400 (path escapes served root); observed 200 with the secret file's contents |
| Impact | Disclosure of files outside the intended directory (C) |
| Root cause | Client-supplied filename joined onto the base directory with no normalization or containment check |
| Mitigation | `os.path.realpath()` the joined path, then verify `os.path.commonpath([real, root]) == root` before reading |
| Regression test (file::name) | `tests/test_web_vulns.py::test_path_traversal_blocked` |
| Post-fix result (actually run? Y/N, output) | Y — `pytest labs/lab-01-web-security -q` → 33 passed |
| Remaining risk / how tests could miss it | OS-path-based only; no chroot/sandboxing; symlink edge cases beyond `realpath`'s own resolution are not separately tested |

Facts vs assumptions vs experimental observations:
- **Facts:** all five vulnerable-variant reproductions and all five secure-variant blocks were executed via `pytest` on 2026-10-12 with the versions listed above; full suite result was 33 passed.
- **Assumptions:** OWASP/PortSwigger category framing used in the chapter is general industry knowledge, not independently re-verified per claim beyond the URL reachability checks in `resources/official-docs.md`.
- **Experimental observations:** the SSRF and path-traversal reproductions used the exact request shapes shown above; no other payload variants were tried.
