"""FinCRM - a small CRM for a fictional US bank, built security/compliance-first.

Controls (see README for the full mapping):
  Argon2id password hashing, server-side sessions (idle + absolute timeout, rotation on login,
  revocation on logout/role change), CSRF tokens, RBAC with segregation of duties,
  parameterised SQL, HTTPS enforcement + security headers, account lockout,
  and an append-only, hash-chained audit trail written in the same transaction as the change.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import (Flask, abort, g, make_response, redirect, render_template,
                   request, url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "fincrm.db"))
DEV = os.environ.get("APP_ENV") == "development"   # default is production-safe
SECURE = not DEV
IDLE_TIMEOUT = timedelta(minutes=15)
ABSOLUTE_TIMEOUT = timedelta(hours=8)
MAX_FAILED = 5
LOCK_FOR = timedelta(minutes=15)
SESSION_COOKIE = "fincrm_session"
LOGIN_CSRF_COOKIE = "fincrm_lcsrf"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
ph = PasswordHasher()  # Argon2id
DUMMY_HASH = ph.hash("dummy-password-for-timing")

# ---------------------------------------------------------------- RBAC
ROLES = ("admin", "manager", "analyst", "viewer")
PERMS = {
    # Admin administers users + reviews the log but cannot create/alter customer data (segregation of duties).
    "admin":   {"customer:view_masked", "user:manage", "audit:view"},
    "manager": {"customer:view_masked", "customer:view", "customer:create", "customer:update", "customer:set_credit", "audit:view"},
    "analyst": {"customer:view_masked", "customer:view", "customer:create", "customer:update"},
    "viewer":  {"customer:view_masked"},
}
HIGH_RISK = ("LOGIN_LOCKOUT", "ACCESS_DENIED", "CUSTOMER_CREDIT_LIMIT_CHANGE", "USER_CREATE",
             "ROLE_CHANGE", "USER_DISABLE", "USER_ENABLE", "SESSION_EXPIRED")
SENSITIVE_FIELDS = {"ssn_last4", "phone"}
ACCOUNT_TYPES = ("checking", "savings", "credit", "loan")
STATUSES = ("active", "frozen", "closed")
MSGS = {"created": "Customer created.", "updated": "Customer updated.", "nochange": "No changes made.",
        "user_created": "User created.", "user_updated": "User updated.", "loggedout": "You have been logged out.",
        "expired": "Your session expired. Please log in again."}


# ---------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc)


def ts(dt=None):
    return (dt or now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def entry_hash(prev, e):
    return sha(prev + json.dumps(e, sort_keys=True, separators=(",", ":")))


def log_event(action, target_type=None, target_id=None, details=None, actor=None):
    """Append to the hash-chained audit log. Joins the caller's transaction if one is open,
    so a data change and its log entry commit (or roll back) together."""
    db = get_db()
    user = g.get("user")
    if actor is None:
        actor = (user["id"], user["username"], user["role"]) if user else (None, None, None)
    own = not db.in_transaction
    if own:
        db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "GENESIS"
        e = {"ts": ts(), "actor_id": actor[0], "actor_username": actor[1], "role": actor[2],
             "action": action, "target_type": target_type,
             "target_id": None if target_id is None else str(target_id),
             "details": json.dumps(details, sort_keys=True) if details else None,
             "ip": request.remote_addr if request else None}
        db.execute("INSERT INTO audit_log (ts,actor_id,actor_username,role,action,target_type,target_id,details,ip,prev_hash,hash)"
                   " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (e["ts"], e["actor_id"], e["actor_username"], e["role"], action, e["target_type"],
                    e["target_id"], e["details"], e["ip"], prev, entry_hash(prev, e)))
        if own:
            db.execute("COMMIT")
    except Exception:
        if own and db.in_transaction:
            db.execute("ROLLBACK")
        raise


def verify_chain():
    """Recompute every hash. Detects edits, mid-chain deletions and gaps. Returns (ok, count, bad_id, head)."""
    db = get_db()
    prev, count, last_id = "GENESIS", 0, 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        e = {k: r[k] for k in ("ts", "actor_id", "actor_username", "role", "action",
                               "target_type", "target_id", "details", "ip")}
        if r["id"] != last_id + 1 or r["prev_hash"] != prev or r["hash"] != entry_hash(prev, e):
            return False, count, r["id"], prev
        prev, count, last_id = r["hash"], count + 1, r["id"]
    return True, count, None, prev


def can(perm):
    return bool(g.get("user")) and perm in PERMS[g.user["role"]]


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.user:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def require(perm):
    def deco(f):
        @wraps(f)
        @login_required
        def wrapper(*a, **kw):
            if not can(perm):
                deny(perm)
            return f(*a, **kw)
        return wrapper
    return deco


def deny(reason):
    log_event("ACCESS_DENIED", "route", request.path, {"needed": reason, "method": request.method})
    abort(403)


def mask_customer(c, masked):
    c = dict(c)
    if masked:
        c["ssn_last4"] = "••••"
        digits = re.sub(r"\D", "", c["phone"])
        c["phone"] = "•••-•••-" + digits[-4:]
        local, _, domain = c["email"].partition("@")
        c["email"] = local[:1] + "•••@" + domain
    return c


# ---------------------------------------------------------------- request lifecycle
@app.before_request
def gate():
    # 1) HTTPS enforcement (TLS terminates at the platform proxy; ProxyFix reads X-Forwarded-Proto)
    if SECURE and not request.is_secure:
        return redirect(request.url.replace("http://", "https://", 1), 301)
    # 2) session lookup with idle + absolute timeout
    g.user = g.session = None
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db = get_db()
        s = db.execute("SELECT * FROM sessions WHERE token_hash=?", (sha(token),)).fetchone()
        if s:
            u = db.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()
            n = now()
            expired = n > parse(s["expires_at"]) or n - parse(s["last_seen"]) > IDLE_TIMEOUT
            if expired or not u or not u["active"]:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (s["token_hash"],))
                if u:
                    log_event("SESSION_EXPIRED", "session", None, actor=(u["id"], u["username"], u["role"]))
                g.expired = True
            else:
                db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (ts(n), s["token_hash"]))
                g.user, g.session = u, s
    # 3) CSRF on every state-changing request except login (which has its own pre-session token)
    if request.method == "POST" and request.endpoint != "login":
        if not g.user:
            return redirect(url_for("login"))
        sent = request.form.get("csrf_token", "")
        if not hmac.compare_digest(sent, g.session["csrf"]):
            log_event("CSRF_REJECTED", "route", request.path)
            abort(400)


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; frame-ancestors 'none'; "
                                               "form-action 'self'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cache-Control"] = "no-store"   # no cached PII, no back-button after logout
    if SECURE:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.context_processor
def inject():
    return {"user": g.get("user"), "csrf": g.session["csrf"] if g.get("session") else "",
            "can": can, "msg": MSGS.get(request.args.get("msg", ""))}


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def http_error(e):
    return render_template("error.html", code=e.code, name=e.name), e.code


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, name="Server error"), 500


# ---------------------------------------------------------------- auth
def new_session(user, old_token=None):
    db = get_db()
    if old_token:  # rotate: never reuse a pre-login identifier (session fixation)
        db.execute("DELETE FROM sessions WHERE token_hash=?", (sha(old_token),))
    token, csrf, n = secrets.token_urlsafe(32), secrets.token_urlsafe(32), now()
    db.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?)",
               (sha(token), user["id"], csrf, ts(n), ts(n), ts(n + ABSOLUTE_TIMEOUT), request.remote_addr))
    return token


def set_session_cookie(resp, token):
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, secure=SECURE, samesite="Strict",
                    max_age=int(ABSOLUTE_TIMEOUT.total_seconds()), path="/")


@app.route("/")
def index():
    return redirect(url_for("customers" if g.user else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        tok = secrets.token_urlsafe(24)
        resp = make_response(render_template("login.html", lcsrf=tok, error=None,
                                             info=MSGS.get(request.args.get("msg", "")) or ("Your session expired. Please log in again." if g.get("expired") else None)))
        resp.set_cookie(LOGIN_CSRF_COOKIE, tok, httponly=True, secure=SECURE, samesite="Strict", max_age=600)
        if g.get("expired"):
            resp.delete_cookie(SESSION_COOKIE)
        return resp

    cookie_tok, form_tok = request.cookies.get(LOGIN_CSRF_COOKIE, ""), request.form.get("lcsrf", "")
    if not cookie_tok or not hmac.compare_digest(cookie_tok, form_tok):
        abort(400)
    username = request.form.get("username", "").strip().lower()[:64]
    password = request.form.get("password", "")[:256]
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    generic = "Invalid username or password."

    def fail(reason, actor=(None, None, None)):
        log_event("LOGIN_FAILURE", "user", username, {"reason": reason}, actor=actor)
        return render_template("login.html", lcsrf=cookie_tok, error=generic, info=None), 401

    if not u:
        try:
            ph.verify(DUMMY_HASH, password)  # equalise timing so usernames can't be enumerated
        except Exception:
            pass
        return fail("unknown_user")
    actor = (u["id"], u["username"], u["role"])
    if u["locked_until"] and now() < parse(u["locked_until"]):
        return fail("account_locked", actor)
    if not u["active"]:
        return fail("account_disabled", actor)
    try:
        ph.verify(u["password_hash"], password)
    except (VerifyMismatchError, InvalidHashError):
        attempts = u["failed_attempts"] + 1
        if attempts >= MAX_FAILED:
            db.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?", (ts(now() + LOCK_FOR), u["id"]))
            log_event("LOGIN_LOCKOUT", "user", u["id"], {"after_attempts": attempts}, actor=actor)
        else:
            db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (attempts, u["id"]))
        return fail("bad_password", actor)

    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (u["id"],))
    if ph.check_needs_rehash(u["password_hash"]):
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (ph.hash(password), u["id"]))
    token = new_session(u, request.cookies.get(SESSION_COOKIE))
    log_event("LOGIN_SUCCESS", "user", u["id"], actor=actor)
    resp = redirect(url_for("customers"))
    set_session_cookie(resp, token)
    resp.delete_cookie(LOGIN_CSRF_COOKIE)
    return resp


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    get_db().execute("DELETE FROM sessions WHERE token_hash=?", (g.session["token_hash"],))
    log_event("LOGOUT", "user", g.user["id"])
    resp = redirect(url_for("login", msg="loggedout"))
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ---------------------------------------------------------------- customers
def validate_customer(f, allow_credit):
    errs, v = [], {}
    v["full_name"] = f.get("full_name", "").strip()
    v["email"] = f.get("email", "").strip().lower()
    v["phone"] = f.get("phone", "").strip()
    v["ssn_last4"] = f.get("ssn_last4", "").strip()
    v["account_type"] = f.get("account_type", "")
    v["status"] = f.get("status", "active")
    if not 1 <= len(v["full_name"]) <= 100:
        errs.append("Name is required (max 100 characters).")
    if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}", v["email"]):
        errs.append("Enter a valid email address.")
    if not 10 <= len(re.sub(r"\D", "", v["phone"])) <= 15 or not re.fullmatch(r"[\d\s()+.-]{10,25}", v["phone"]):
        errs.append("Enter a valid phone number.")
    if not re.fullmatch(r"\d{4}", v["ssn_last4"]):
        errs.append("SSN last 4 must be exactly 4 digits (full SSNs are never stored).")
    if v["account_type"] not in ACCOUNT_TYPES:
        errs.append("Choose an account type.")
    if v["status"] not in STATUSES:
        errs.append("Choose a valid status.")
    raw = f.get("credit_limit", "0").strip() or "0"
    if re.fullmatch(r"\d{1,7}", raw) and int(raw) <= 1_000_000:
        v["credit_limit"] = int(raw)
    else:
        errs.append("Credit limit must be a whole number from 0 to 1,000,000.")
        v["credit_limit"] = 0
    return v, errs


@app.route("/customers")
@require("customer:view_masked")
def customers():
    q = request.args.get("q", "").strip()[:100]
    masked = not can("customer:view")
    db = get_db()
    if q:
        like = f"%{q}%"
        rows = db.execute("SELECT * FROM customers WHERE full_name LIKE ? OR email LIKE ? ORDER BY id", (like, like)).fetchall()
    else:
        rows = db.execute("SELECT * FROM customers ORDER BY id").fetchall()
    log_event("CUSTOMER_LIST_VIEW", "customer", None, {"query": q, "results": len(rows), "masked": masked})
    return render_template("customers.html", rows=[mask_customer(r, masked) for r in rows], q=q)


@app.route("/customers/<int:cid>")
@require("customer:view_masked")
def customer_detail(cid):
    c = get_db().execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    masked = not can("customer:view")
    log_event("CUSTOMER_VIEW", "customer", cid, {"masked": masked})
    return render_template("customer_detail.html", c=mask_customer(c, masked))


@app.route("/customers/new", methods=["GET", "POST"])
@require("customer:create")
def customer_new():
    if request.method == "GET":
        return render_template("customer_form.html", c={"status": "active", "credit_limit": 0}, errors=[], new=True)
    v, errs = validate_customer(request.form, can("customer:set_credit"))
    if not can("customer:set_credit"):
        v["credit_limit"] = 0  # analysts cannot grant credit
    if errs:
        return render_template("customer_form.html", c=v, errors=errs, new=True), 400
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        cur = db.execute("INSERT INTO customers (full_name,email,phone,ssn_last4,account_type,credit_limit,status,created_by,created_at)"
                         " VALUES (?,?,?,?,?,?,?,?,?)",
                         (v["full_name"], v["email"], v["phone"], v["ssn_last4"], v["account_type"],
                          v["credit_limit"], v["status"], g.user["id"], ts()))
        log_event("CUSTOMER_CREATE", "customer", cur.lastrowid, {"account_type": v["account_type"], "credit_limit": v["credit_limit"]})
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return redirect(url_for("customer_detail", cid=cur.lastrowid, msg="created"))


@app.route("/customers/<int:cid>/edit", methods=["GET", "POST"])
@require("customer:update")
def customer_edit(cid):
    db = get_db()
    old = db.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    if not old:
        abort(404)
    if request.method == "GET":
        return render_template("customer_form.html", c=dict(old), errors=[], new=False)
    v, errs = validate_customer(request.form, can("customer:set_credit"))
    if not can("customer:set_credit"):
        if "credit_limit" in request.form and v["credit_limit"] != old["credit_limit"]:
            deny("customer:set_credit")      # tampered form -> denied + logged
        v["credit_limit"] = old["credit_limit"]
    if errs:
        return render_template("customer_form.html", c={**v, "id": cid}, errors=errs, new=False), 400
    changes = {k: [old[k], v[k]] for k in v if old[k] != v[k]}
    if not changes:
        return redirect(url_for("customer_detail", cid=cid, msg="nochange"))
    shown = {k: ["[redacted]", "[redacted]"] if k in SENSITIVE_FIELDS else val for k, val in changes.items()}
    db.execute("BEGIN IMMEDIATE")
    try:
        sets = ", ".join(f"{k}=?" for k in changes)   # keys come from our own validated dict, never user input
        db.execute(f"UPDATE customers SET {sets}, updated_by=?, updated_at=? WHERE id=?",
                   (*[v[k] for k in changes], g.user["id"], ts(), cid))
        log_event("CUSTOMER_UPDATE", "customer", cid, {"changes": shown})
        if "credit_limit" in changes:
            log_event("CUSTOMER_CREDIT_LIMIT_CHANGE", "customer", cid, {"from": old["credit_limit"], "to": v["credit_limit"]})
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return redirect(url_for("customer_detail", cid=cid, msg="updated"))


# ---------------------------------------------------------------- audit (detective control)
@app.route("/audit")
@require("audit:view")
def audit():
    action = request.args.get("action", "")
    risky = request.args.get("risk") == "1"
    db = get_db()
    sql, args = "SELECT * FROM audit_log", []
    if risky:
        sql += f" WHERE action IN ({','.join('?' * len(HIGH_RISK))}) OR (action='LOGIN_FAILURE')"
        args += list(HIGH_RISK)
    elif action:
        sql += " WHERE action=?"
        args.append(action)
    rows = db.execute(sql + " ORDER BY id DESC LIMIT 200", args).fetchall()
    actions = [r[0] for r in db.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    log_event("AUDIT_LOG_VIEW", "audit_log", None, {"filter": action or ("high_risk" if risky else "none")})
    return render_template("audit.html", rows=rows, actions=actions, action=action, risky=risky)


@app.route("/audit/verify")
@require("audit:view")
def audit_verify():
    ok, count, bad, head = verify_chain()
    log_event("AUDIT_CHAIN_VERIFY", "audit_log", None, {"ok": ok, "entries": count})
    return render_template("verify.html", ok=ok, count=count, bad=bad, head=head)


# ---------------------------------------------------------------- user admin
@app.route("/users", methods=["GET", "POST"])
@require("user:manage")
def users():
    db, errs = get_db(), []
    if request.method == "POST":
        name = request.form.get("username", "").strip().lower()
        role, pw = request.form.get("role", ""), request.form.get("password", "")
        if not re.fullmatch(r"[a-z0-9._-]{3,32}", name):
            errs.append("Username: 3-32 chars, letters/digits/._- only.")
        if role not in ROLES:
            errs.append("Choose a role.")
        if len(pw) < 12 or len(pw) > 128 or name in pw.lower():
            errs.append("Password must be 12-128 characters and not contain the username.")
        if not errs and db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
            errs.append("That username already exists.")
        if not errs:
            db.execute("BEGIN IMMEDIATE")
            try:
                cur = db.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                                 (name, ph.hash(pw), role, ts()))
                log_event("USER_CREATE", "user", cur.lastrowid, {"username": name, "role": role})
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise
            return redirect(url_for("users", msg="user_created"))
    return render_template("users.html", rows=db.execute("SELECT * FROM users ORDER BY id").fetchall(),
                           roles=ROLES, errors=errs), (400 if errs else 200)


@app.route("/users/<int:uid>/update", methods=["POST"])
@require("user:manage")
def user_update(uid):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        abort(404)
    if uid == g.user["id"]:
        abort(400)  # nobody changes their own privileges or disables themselves
    action = request.form.get("do")
    db.execute("BEGIN IMMEDIATE")
    try:
        if action == "role" and request.form.get("role") in ROLES and request.form["role"] != target["role"]:
            db.execute("UPDATE users SET role=? WHERE id=?", (request.form["role"], uid))
            log_event("ROLE_CHANGE", "user", uid, {"from": target["role"], "to": request.form["role"]})
        elif action == "toggle":
            new = 0 if target["active"] else 1
            db.execute("UPDATE users SET active=? WHERE id=?", (new, uid))
            log_event("USER_ENABLE" if new else "USER_DISABLE", "user", uid, {"username": target["username"]})
        else:
            db.execute("ROLLBACK")
            return redirect(url_for("users"))
        db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))  # privilege change takes effect immediately
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return redirect(url_for("users", msg="user_updated"))


# ---------------------------------------------------------------- init + demo seed
def init_db():
    db = sqlite3.connect(DB_PATH, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(open(os.path.join(BASE, "schema.sql")).read())
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 and os.environ.get("DEMO_SEED", "1") == "1":
        demo = [("admin_demo", "admin", "Admin-Demo#2026!"), ("manager_demo", "manager", "Manager-Demo#2026!"),
                ("analyst_demo", "analyst", "Analyst-Demo#2026!"), ("viewer_demo", "viewer", "Viewer-Demo#2026!")]
        people = [("Avery Johnson", "avery.johnson@example.com", "214-555-0101", "4821", "checking", 0, "active"),
                  ("Maria Gonzalez", "maria.gonzalez@example.com", "469-555-0142", "7730", "credit", 15000, "active"),
                  ("Derek Okafor", "derek.okafor@example.com", "972-555-0187", "1096", "loan", 0, "active"),
                  ("Priya Natarajan", "priya.n@example.com", "817-555-0123", "5562", "savings", 0, "active"),
                  ("Tom Whitfield", "tom.whitfield@example.com", "682-555-0166", "9314", "credit", 5000, "frozen"),
                  ("Lena Fischer", "lena.fischer@example.com", "903-555-0119", "2207", "checking", 0, "closed")]
        db.execute("BEGIN")
        for n, r, p in demo:
            db.execute("INSERT INTO users (username,password_hash,role,created_at) VALUES (?,?,?,?)", (n, ph.hash(p), r, ts()))
        for p in people:
            db.execute("INSERT INTO customers (full_name,email,phone,ssn_last4,account_type,credit_limit,status,created_at)"
                       " VALUES (?,?,?,?,?,?,?,?)", (*p, ts()))
        db.execute("COMMIT")
        with app.test_request_context():
            g.db = db
            log_event("SYSTEM_SEED", "system", None, {"users": len(demo), "customers": len(people)}, actor=(None, "system", "system"))
    db.close()


init_db()

if __name__ == "__main__":
    app.run(debug=False, port=int(os.environ.get("PORT", 5000)))
