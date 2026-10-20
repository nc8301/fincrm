# FinCRM

A small customer relationship management (CRM) web app for a fictional US bank, built so the security and compliance controls are part of the design from the first commit, not bolted on after.

**Live app:** `https://fincrm-4z51.onrender.com`  |  **Stack:** Python 3 · Flask · SQLite · Argon2id · server-rendered HTML (no JavaScript)

## Architecture

FinCRM is a single Flask service with server-rendered pages and a SQLite database. I chose server-side sessions in a cookie over JWTs because a bank needs to be able to end a session *immediately* (logout, role change, disabled user, suspected theft); a stateless JWT can't be revoked without a deny-list. Only a SHA-256 hash of each session token is stored, so a database leak can't be replayed as live sessions. There is no client-side JavaScript, which removes a whole class of token-handling and XSS risk, and a strict Content-Security-Policy enforces it.

Access control is one permission map (`PERMS` in `app.py`) checked by a `@require(permission)` decorator on every route, deny-by-default. Roles are built around segregation of duties: **Admin** manages users and reviews the audit log but cannot create or change customer data; **Manager** has full customer access and is the only role that can set credit limits; **Analyst** can view, add and update customers but not credit limits; **Viewer** is read-only with masked PII. Denied attempts are themselves logged.

Every security-relevant event (logins, failures, lockouts, customer record views, creates/updates with before/after values, denied access, role changes, session expiry) is written to an append-only, hash-chained `audit_log`. Each entry stores the hash of the one before it, SQLite triggers block `UPDATE`/`DELETE`, and the log entry is written in the same transaction as the data change so a change can't commit without its record. Managers and Admins can run **Verify log integrity** in the UI to recompute the chain.

| Role | View customers | Add / edit | Set credit limit | Audit log | Manage users |
|---|---|---|---|---|---|
| Admin | masked | no | no | yes | yes |
| Manager | full | yes | yes | yes | no |
| Analyst | full | yes | no | no | no |
| Viewer | masked | no | no | no | no |

## Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
APP_ENV=development python app.py      # http://127.0.0.1:5000
```

`APP_ENV=development` only relaxes the HTTPS redirect and `Secure` cookie flag so it works on plain `http://localhost`. Without it the app runs in production mode. The database is created and seeded with demo data on first start.

Run the tests (RBAC, CSRF, lockout, session replay after logout, audit-chain tamper detection, HTTPS redirect, headers):

```bash
pip install pytest && python -m pytest tests -q
```

## Test logins (demo data only)

| Username | Password | Role |
|---|---|---|
| `admin_demo` | `Admin-Demo#2026!` | Admin |
| `manager_demo` | `Manager-Demo#2026!` | Manager |
| `analyst_demo` | `Analyst-Demo#2026!` | Analyst |
| `viewer_demo` | `Viewer-Demo#2026!` | Viewer |

Things worth trying: log in as `analyst_demo` and edit a customer; log in as `manager_demo` and change a credit limit; log in as `admin_demo` and open **Audit log** → **High-risk only** → **Verify log integrity**; fail a login five times to see the lockout.

## Deploy (Render, free tier)

1. Push this repo to GitHub (public).
2. On render.com: **New → Web Service** → connect the repo.
3. Build command: `pip install -r requirements.txt`  ·  Start command: `gunicorn app:app --workers 1 --bind 0.0.0.0:$PORT`
4. Render terminates TLS and sets `X-Forwarded-Proto`; the app redirects any HTTP request to HTTPS and sends HSTS. Do **not** set `APP_ENV=development` there.

The free tier has an ephemeral disk, so the demo database resets on redeploy or restart (the demo accounts above are re-seeded automatically). Keep `--workers 1` with SQLite.

## Control summary

| Area | Control |
|---|---|
| Passwords | Argon2id, 12+ char minimum for new users, generic login errors, timing-equalised unknown-user path, lockout after 5 failures (15 min) |
| Sessions | 256-bit random token, hash-only storage, HttpOnly + Secure + SameSite=Strict cookie, 15 min idle / 8 h absolute timeout, rotated on login, deleted server-side on logout/role change/disable |
| Request integrity | CSRF token on every POST (separate pre-login token for the login form), parameterised SQL, validated input, auto-escaped templates |
| Data protection | Only SSN last 4 stored, role-based masking, `Cache-Control: no-store`, PII redacted from audit details |
| Transit | HTTPS redirect, HSTS, CSP, X-Frame-Options, nosniff, no-referrer |
| Audit / SOX 404 / FFIEC | Append-only hash-chained log, same-transaction writes, before/after values, high-risk event filter, integrity verification |
| NIST CSF | **Protect:** authN, RBAC, data security, protective tech. **Detect:** continuous logging, high-risk review, chain verification |

## Known gaps (what I'd do next)

No MFA or password reset/expiry flow; lockout is per-account only (no per-IP rate limiting); credit-limit increases are detective (logged and reviewable) rather than preventive (maker-checker approval); the audit log lives in the same database as the app, so it should be shipped to an external write-once store or SIEM with alerting and the head hash anchored elsewhere; no encryption at rest, backups/DR, formal change-management evidence, periodic access recertification, or penetration test; GLBA data-retention rules are not modelled.
