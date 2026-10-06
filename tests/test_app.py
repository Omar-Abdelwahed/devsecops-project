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
