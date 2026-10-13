"""
DELIBERATELY VULNERABLE APPLICATION - FOR SAST / TRAINING USE ONLY
===================================================================
DO NOT deploy this anywhere reachable from a network. Run only in an
isolated lab/container. Purpose: give SAST tools (Semgrep, Bandit,
CodeQL, SonarQube, etc.) realistic findings to detect.

OWASP Top 10 (2021) coverage map
--------------------------------
A01 Broken Access Control ........ IDOR, missing authz, path traversal
A02 Cryptographic Failures ....... MD5 passwords, hardcoded secrets, weak RNG
A03 Injection .................... SQLi, OS command injection, XSS, SSTI
A04 Insecure Design .............. no rate limit, predictable reset tokens
A05 Security Misconfiguration .... debug=True, XXE, permissive CORS, 0.0.0.0
A06 Vulnerable Components ........ see requirements.txt (old pinned versions)
A07 Identification/Auth Failures . weak session handling, default creds
A08 Software/Data Integrity ...... pickle / yaml.load deserialization
A09 Logging/Monitoring Failures .. logs secrets, no failed-login logging
A10 SSRF ......................... unvalidated server-side URL fetch
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import base64
import logging

import requests
import yaml
from flask import Flask, request, jsonify, session, render_template_string, send_file, make_response
from lxml import etree

app = Flask(__name__)

# ---------------------------------------------------------------------------
# A02: Hardcoded secrets / A05: Security misconfiguration
# ---------------------------------------------------------------------------
app.secret_key = "super-secret-key-123"              # hardcoded secret key
DB_PASSWORD = "admin123"                              # hardcoded credential
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE/wJalrXUtnFEMI/K7MDENG"  # fake key, hardcoded
ADMIN_DEFAULT_USER = "admin"
ADMIN_DEFAULT_PASS = "admin"                          # A07: default credentials

DB_PATH = "app.db"
UPLOAD_DIR = "./uploads"

# A09: logging configured with no structure; sensitive data will be logged
logging.basicConfig(filename="app.log", level=logging.DEBUG)


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT, password TEXT,
            email TEXT, role TEXT, credit_card TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY, user_id INTEGER, item TEXT, total REAL
        );
        """
    )
    # A02: MD5, unsalted
    db.execute(
        "INSERT OR IGNORE INTO users VALUES (1,'admin',?,?,?,?)",
        (hashlib.md5(b"admin").hexdigest(), "admin@example.com", "admin", "4111111111111111"),
    )
    db.commit()


# ---------------------------------------------------------------------------
# A05: Permissive CORS + missing security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    # No CSP, X-Frame-Options, HSTS, X-Content-Type-Options
    return resp


# ---------------------------------------------------------------------------
# A07 + A02 + A03(SQLi) + A09: Registration / Login
# ---------------------------------------------------------------------------
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]           # A07: no password policy
    email = request.form["email"]

    # A02: weak hash (MD5, no salt)
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # A03: SQL injection via string formatting
    db.execute(
        "INSERT INTO users (username, password, email, role) VALUES ('%s','%s','%s','user')"
        % (username, pw_hash, email)
    )
    db.commit()
    logging.info("New user registered: %s password=%s", username, password)  # A09: logs password
    return jsonify(status="ok")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    pw_hash = hashlib.md5(password.encode()).hexdigest()

    db = get_db()
    # A03: SQL injection (auth bypass: ' OR '1'='1)
    query = f"SELECT id, role FROM users WHERE username='{username}' AND password='{pw_hash}'"
    row = db.execute(query).fetchone()

    if row:
        session["user_id"] = row[0]
        session["role"] = row[1]                   # A04/A01: role trusted from session only
        resp = make_response(jsonify(status="logged in"))
        # A07: insecure cookie flags (no Secure / HttpOnly / SameSite), predictable value
        resp.set_cookie("auth", base64.b64encode(username.encode()).decode())
        return resp

    # A09: failed logins are not logged; no lockout / rate limiting (A04/A07)
    return jsonify(status="invalid credentials"), 401


# ---------------------------------------------------------------------------
# A01: Broken Access Control - IDOR & missing authorization
# ---------------------------------------------------------------------------
@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    # No authentication or ownership check -> IDOR
    db = get_db()
    row = db.execute("SELECT id, username, email, credit_card FROM users WHERE id=?", (user_id,)).fetchone()
    return jsonify(row)


@app.route("/admin/delete_user", methods=["POST"])
def delete_user():
    # No authz check at all (relies on UI hiding the button)
    uid = request.form["id"]
    db = get_db()
    db.execute("DELETE FROM users WHERE id = " + uid)   # also SQLi
    db.commit()
    return jsonify(status="deleted")


@app.route("/download")
def download():
    # A01: Path traversal
    filename = request.args.get("file")
    return send_file(os.path.join(UPLOAD_DIR, filename))


# ---------------------------------------------------------------------------
# A03: Injection - XSS, SSTI, OS command injection
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # A03: Reflected XSS (unescaped output)
    return "<h1>Results for: " + q + "</h1>"


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # A03: Server-Side Template Injection
    template = "<p>Hello " + name + "</p>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # A03: OS command injection (shell=True with user input)
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


@app.route("/eval")
def calc():
    expr = request.args.get("expr", "1+1")
    # A03: Code injection via eval
    return str(eval(expr))


# ---------------------------------------------------------------------------
# A04: Insecure Design - predictable tokens, no rate limit, business logic flaws
# ---------------------------------------------------------------------------
@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
    # A02/A04: weak PRNG, 4-digit token, never expires, no rate limit
    token = str(random.randint(1000, 9999))
    db = get_db()
    db.execute("UPDATE users SET password=? WHERE email=?", (hashlib.md5(token.encode()).hexdigest(), email))
    db.commit()
    return jsonify(status="reset token sent", debug_token=token)   # leaks token in response


@app.route("/checkout", methods=["POST"])
def checkout():
    # A04: client controls price and quantity (negative values allowed)
    item = request.form["item"]
    price = float(request.form["price"])
    qty = int(request.form["qty"])
    total = price * qty
    db = get_db()
    db.execute("INSERT INTO orders (user_id, item, total) VALUES (?,?,?)", (session.get("user_id"), item, total))
    db.commit()
    return jsonify(total=total)


# ---------------------------------------------------------------------------
# A05: Security Misconfiguration - XXE, verbose errors
# ---------------------------------------------------------------------------
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    # A05: XXE - entity resolution and network access enabled
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    doc = etree.fromstring(request.data, parser)
    return etree.tostring(doc)


@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    # A05: leaks stack traces to the client
    return "<pre>" + traceback.format_exc() + "</pre>", 500


# ---------------------------------------------------------------------------
# A08: Software and Data Integrity Failures - insecure deserialization
# ---------------------------------------------------------------------------
@app.route("/load_session", methods=["POST"])
def load_session():
    data = base64.b64decode(request.form["data"])
    # A08: pickle.loads on untrusted data -> RCE
    obj = pickle.loads(data)
    return jsonify(loaded=str(obj))


@app.route("/load_config", methods=["POST"])
def load_config():
    # A08: yaml.load without SafeLoader
    cfg = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(cfg)


@app.route("/update_check")
def update_check():
    # A08: downloads and executes code without integrity/signature verification
    code = requests.get("http://updates.example.com/latest.py", verify=False).text   # A02: TLS verify off
    exec(code)
    return "updated"


# ---------------------------------------------------------------------------
# A10: Server-Side Request Forgery
# ---------------------------------------------------------------------------
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    # A10: no allow-list, no private-IP/metadata blocking, follows redirects
    r = requests.get(url, allow_redirects=True, timeout=5)
    return r.text


# ---------------------------------------------------------------------------
# A09: Logging & Monitoring Failures
# ---------------------------------------------------------------------------
@app.route("/payment", methods=["POST"])
def payment():
    card = request.form["card_number"]
    cvv = request.form["cvv"]
    # A09: sensitive data (PAN, CVV) written to logs
    logging.debug("Processing payment card=%s cvv=%s", card, cvv)
    try:
        pass  # payment logic
    except Exception:
        pass  # A09: swallowed exception, no alerting
    return jsonify(status="processed")


# ---------------------------------------------------------------------------
# A01: Unrestricted file upload (also A04/A05)
# ---------------------------------------------------------------------------
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    # No extension/MIME check, user-controlled filename (path traversal)
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return jsonify(saved=f.filename)


# ---------------------------------------------------------------------------
# A03: Open redirect
# ---------------------------------------------------------------------------
@app.route("/redirect")
def open_redirect():
    from flask import redirect
    return redirect(request.args.get("next", "/"))


if __name__ == "__main__":
    init_db()
    # A05: debug mode (Werkzeug debugger = RCE) and binding to all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
