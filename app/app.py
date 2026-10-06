"""Intentionally vulnerable Flask app, for DevSecOps training only. DO NOT deploy."""
import hashlib
import os
import sqlite3

from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = "super-secret-key-123"              # VULN: hardcoded secret key
GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # VULN: fake token for Gitleaks
DB_PATH = os.environ.get("DB_PATH", "app.db")


def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = db()
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, content TEXT)")
    conn.commit()
    conn.close()


def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()      # VULN: weak hash, no salt


@app.route("/")
def home():
    user = session.get("user")
    return f"<h1>Notes App</h1><p>Hello {user or 'guest'}</p><a href='/notes'>Notes</a>"


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form["username"], request.form["password"]
    conn = db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, hash_pw(p)))
    conn.commit()
    conn.close()
    return "registered", 201


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    conn = db()
    # VULN: SQL injection (try username = admin' --)
    row = conn.execute(
        f"SELECT * FROM users WHERE username = '{u}' AND password = '{hash_pw(p)}'"
    ).fetchone()
    conn.close()
    if row:
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
    # VULN: stored XSS (content rendered unescaped)
    return "".join(f"<li>{r[0]}</li>" for r in rows) or "no notes"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: reflected XSS + server-side template injection
    return render_template_string(f"<h2>Results for {q}</h2>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN: command injection
    return f"<pre>{os.popen('ping -c 1 ' + host).read()}</pre>"


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # VULN: debug mode, binds all interfaces
