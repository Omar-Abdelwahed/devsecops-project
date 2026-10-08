from app.app import app


def test_health():
    r = app.test_client().get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_register_login_notes():
    c = app.test_client()
    assert c.post("/register", data={"username": "sam", "password": "pw"}).status_code == 201
    assert c.post("/login", data={"username": "sam", "password": "pw"}).status_code == 302
    assert c.post("/notes", data={"content": "hello"}).status_code == 200
    assert b"hello" in c.get("/notes").data


def test_login_rejects_bad_password():
    c = app.test_client()
    c.post("/register", data={"username": "bob", "password": "pw"})
    assert c.post("/login", data={"username": "bob", "password": "x"}).status_code == 401


def test_sqli_blocked():
    """SQL injection attempt in login must be rejected (not bypass auth)."""
    c = app.test_client()
    # Register a real user first
    c.post("/register", data={"username": "admin", "password": "realpassword"})
    # Classic SQLi bypass attempt — must NOT return 302 (redirect = login success)
    r = c.post("/login", data={"username": "admin' --", "password": "anything"})
    assert r.status_code == 401


def test_search_xss_escaped():
    """Reflected XSS payload in /search must be escaped, not rendered raw."""
    c = app.test_client()
    r = c.get("/search?q=<script>alert(1)</script>")
    body = r.data.decode()
    assert "<script>" not in body          # raw tag must not appear
    assert "&lt;script&gt;" in body        # must be HTML-escaped


def test_security_headers():
    """After-request hook must set all three security headers."""
    c = app.test_client()
    r = c.get("/health")
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
