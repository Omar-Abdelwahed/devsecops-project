"""Remediated Flask app (DevSecOps training)."""
import os
import sqlite3

from flask import Flask, redirect, request, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]  # injected at runtime, never committed
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB_PATH = os.environ.get("DB_PATH", "app.db")


def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, content TEXT)")
    conn.commit()
    conn.close()


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/")
def home():
    user = escape(session.get("user") or "guest")
    return f"<h1>Notes App</h1><p>Hello {user}</p><a href='/notes'>Notes</a>"


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form["username"], request.form["password"]
    conn = db()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, generate_password_hash(p)))
        conn.commit()
    except sqlite3.IntegrityError:
        return "username taken", 409
    finally:
        conn.close()
    return "registered", 201


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    conn = db()
    row = conn.execute("SELECT password FROM users WHERE username = ?", (u,)).fetchone()  # parameterized
    conn.close()
    if row and check_password_hash(row[0], p):
        session["user"] = u
        return redirect("/")
    return "invalid credentials", 401


@app.route("/notes", methods=["GET", "POST"])
def notes():
    user = session.get("user")
    if not user:
        return "login required", 401
    conn = db()
    if request.method == "POST":
        conn.execute("INSERT INTO notes (owner, content) VALUES (?, ?)", (user, request.form["content"]))
        conn.commit()
    rows = conn.execute("SELECT content FROM notes WHERE owner = ?", (user,)).fetchall()
    conn.close()
    return "".join(f"<li>{escape(r[0])}</li>" for r in rows) or "no notes"


@app.route("/search")
def search():
    return f"<h2>Results for {escape(request.args.get('q', ''))}</h2>"


# /ping removed: command injection surface with no business need.

init_db()

# Dev entry point only (production uses gunicorn, see Dockerfile).
# Bandit B104 on this line is an accepted false positive: see bandit.yaml and exemption-process.md.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
