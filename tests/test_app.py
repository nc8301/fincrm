import os, re, sqlite3, sys, tempfile
os.environ["APP_ENV"] = "development"
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app as A

PW = {"admin_demo": "Admin-Demo#2026!", "manager_demo": "Manager-Demo#2026!",
      "analyst_demo": "Analyst-Demo#2026!", "viewer_demo": "Viewer-Demo#2026!"}
CUST = dict(full_name="Test Person", email="t@example.com", phone="214-555-0000", ssn_last4="1234",
            account_type="checking", credit_limit="0", status="active")


def client():
    return A.app.test_client()


def login(c, user, pw=None):
    page = c.get("/login").get_data(as_text=True)
    tok = re.search(r'name="lcsrf" value="([^"]+)"', page).group(1)
    return c.post("/login", data={"username": user, "password": pw or PW.get(user, ""), "lcsrf": tok})


def csrf(c):
    page = c.get("/customers").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


def test_login_and_logout_invalidate_session():
    c = client()
    assert login(c, "manager_demo").status_code == 302
    assert c.get("/customers").status_code == 200
    tok = csrf(c)
    cookie = c.get_cookie("fincrm_session").value
    assert c.post("/logout", data={"csrf_token": tok}).status_code == 302
    c2 = client(); c2.set_cookie("fincrm_session", cookie)          # replay stolen cookie
    assert c2.get("/customers").status_code == 302                    # server-side session is gone


def test_bad_login_generic_and_lockout():
    c = client()
    for _ in range(5):
        r = login(c, "viewer_demo", "wrong-password-1")
        assert r.status_code == 401 and b"Invalid username or password." in r.data
    assert login(c, "viewer_demo").status_code == 401                 # locked even with correct password
    assert login(client(), "nobody", "x").status_code == 401
    db = sqlite3.connect(A.DB_PATH); db.execute("UPDATE users SET locked_until=NULL, failed_attempts=0"); db.commit()  # reset for other tests


def test_csrf_blocks_post_without_token():
    c = client(); login(c, "manager_demo")
    assert c.post("/customers/new", data=CUST).status_code == 400


def test_rbac_matrix():
    v = client(); login(v, "viewer_demo")
    assert v.get("/customers").status_code == 200
    assert "4821" not in v.get("/customers/1").get_data(as_text=True)  # masked
    assert v.get("/customers/new").status_code == 403
    assert v.get("/audit").status_code == 403 and v.get("/users").status_code == 403
    a = client(); login(a, "admin_demo")
    assert a.get("/customers/new").status_code == 403                  # segregation of duties
    assert a.get("/audit").status_code == 200 and a.get("/users").status_code == 200
    m = client(); login(m, "manager_demo")
    assert "4821" in m.get("/customers/1").get_data(as_text=True)
    assert m.get("/users").status_code == 403


def test_analyst_cannot_change_credit_limit_and_is_logged():
    c = client(); login(c, "analyst_demo"); t = csrf(c)
    r = c.post("/customers/1/edit", data={**CUST, "csrf_token": t, "credit_limit": "99999"})
    assert r.status_code == 403
    r = c.post("/customers/1/edit", data={**CUST, "csrf_token": t, "full_name": "Avery J. Johnson", "credit_limit": "0"})
    assert r.status_code == 302
    db = sqlite3.connect(A.DB_PATH)
    assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='ACCESS_DENIED'").fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='CUSTOMER_UPDATE' AND details LIKE '%Avery J. Johnson%'").fetchone()[0] == 1


def test_manager_credit_change_logged_with_before_after():
    c = client(); login(c, "manager_demo"); t = csrf(c)
    assert c.post("/customers/2/edit", data={**CUST, "csrf_token": t, "credit_limit": "20000"}).status_code == 302
    db = sqlite3.connect(A.DB_PATH)
    d = db.execute("SELECT details FROM audit_log WHERE action='CUSTOMER_CREDIT_LIMIT_CHANGE'").fetchone()[0]
    assert '"from": 15000' in d and '"to": 20000' in d


def test_validation_rejects_bad_input():
    c = client(); login(c, "manager_demo"); t = csrf(c)
    r = c.post("/customers/new", data={**CUST, "csrf_token": t, "email": "nope", "ssn_last4": "123456789"})
    assert r.status_code == 400 and b"valid email" in r.data


def test_audit_chain_verifies_then_detects_tamper_and_blocks_edits():
    m = client(); login(m, "manager_demo")
    assert b"PASS" in m.get("/audit/verify").data
    db = sqlite3.connect(A.DB_PATH)
    try:
        db.execute("UPDATE audit_log SET actor_username='evil' WHERE id=2"); raised = False
    except sqlite3.DatabaseError:
        raised = True
    assert raised                                                       # trigger blocks UPDATE
    db.execute("DROP TRIGGER audit_no_update")                          # privileged attacker
    db.execute("UPDATE audit_log SET actor_username='evil' WHERE id=2"); db.commit()
    assert b"FAIL" in m.get("/audit/verify").data                       # chain catches it


def test_security_headers():
    r = client().get("/login")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store" and r.headers["X-Frame-Options"] == "DENY"


def test_https_redirect_in_prod(monkeypatch=None):
    A.SECURE = True
    try:
        r = client().get("/login", base_url="http://example.com")
        assert r.status_code == 301 and r.headers["Location"].startswith("https://")
        r = client().get("/login", base_url="http://example.com", headers={"X-Forwarded-Proto": "https"})
        assert r.status_code == 200 and "Strict-Transport-Security" in r.headers
    finally:
        A.SECURE = False
