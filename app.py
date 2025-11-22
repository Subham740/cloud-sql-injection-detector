import os
import re
import sqlite3
import datetime
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash
)

APP_DB = "app.db"

app = Flask(__name__)
app.secret_key = "change_this_secret_key"  # production me change karna


# -----------------------------
# Database helpers
# -----------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(APP_DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    cur = db.cursor()

    # users table (demo purpose)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        """
    )

    # security_logs table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            username TEXT,
            input TEXT,
            query TEXT,
            severity TEXT NOT NULL
        );
        """
    )

    db.commit()


# -----------------------------
# SQL Injection & Data Leak Detection
# -----------------------------

# Regex-based SQL injection patterns
attack_patterns = [
    # Basic tautologies
    r" or 1=1",
    r"' or '1'='1",
    r"\" or \"1\"=\"1",
    r"' or 'x'='x",
    r" or 'a'='a",
    r" or 1=1--",
    r" or 1=1#",

    # UNION based
    r" union select",
    r" union all select",
    r" union distinct select",

    # Comment/end of query tricks
    r"--",
    r";--",
    r"#",
    r"/\*.*\*/",

    # Stacked queries (multiple statements)
    r";\s*drop\s+table",
    r";\s*insert\s+into",
    r";\s*update\s+",
    r";\s*delete\s+from",

    # Information schema access (data leak style)
    r"from\s+information_schema",
    r"information_schema\.tables",
    r"information_schema\.columns",

    # Function calls often used in attacks
    r"sleep\(",
    r"benchmark\(",
    r"load_file\(",
    r"xp_cmdshell",
]

# Expanded sensitive tables/columns list
sensitive_tables = [
    "users",
    "payments",
    "cards",
    "accounts",
    "transactions",
    "employees",
    "salary",
    "customer",
    "bank_details",
]

sensitive_columns = [
    "password",
    "pass",
    "hash",
    "card_number",
    "cardno",
    "cvv",
    "pin",
    "aadhar",
    "aadhaar",
    "pan",
    "ssn",
    "salary",
    "credit_limit",
    "phone",
    "mobile",
    "email",
]


def is_sql_injection(user_input: str) -> bool:
    """Signature + heuristic based SQLi detection on raw user input."""
    if not user_input:
        return False

    text = user_input.lower()

    # 1. Signature-based (regex) check
    for pattern in attack_patterns:
        if re.search(pattern, text):
            return True

    # 2. Heuristic: special characters + SQL keywords
    special_chars = ["'", "\"", ";", "=", "(", ")", "--"]
    special_count = sum(text.count(ch) for ch in special_chars)

    sql_keywords = ["select", "insert", "update", "delete", "union", "drop", "where", "from"]
    keyword_count = sum(1 for kw in sql_keywords if kw in text)

    # Agar input chhota hai lekin bahut special chars + kuch SQL keywords hai → suspicious
    if len(text) < 100 and (special_count >= 3 and keyword_count >= 1):
        return True

    return False


def is_data_leak(query: str) -> bool:
    """Detects if a query is likely targeting sensitive data (tables/columns)."""
    if not query:
        return False

    q = query.lower()

    if "select" not in q:
        return False

    table_hit = any(t in q for t in sensitive_tables)
    column_hit = any(c in q for c in sensitive_columns)

    # Agar select ke saath sensitive table ya column hai to data leak risk high
    if table_hit or column_hit:
        return True

    # Extra: information_schema ka access bhi data leak category me
    if "information_schema" in q:
        return True

    return False


def log_event(user_input, query, severity):
    """Logs security events to the security_logs table."""
    db = get_db()
    cur = db.cursor()

    timestamp = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    ip = request.remote_addr or "unknown"
    username = session.get("user_email", "anonymous")

    cur.execute(
        """
        INSERT INTO security_logs (timestamp, ip, username, input, query, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, ip, username, user_input, query, severity),
    )
    db.commit()


# -----------------------------
# Routes
# -----------------------------
@app.route("/initdb")
def initdb_route():
    init_db()
    return "Database initialized."


@app.route("/")
def index():
    return render_template("index.html")


# --------- Register ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not name or not email or not password:
            flash("All fields are required.")
            return redirect(url_for("register"))

        db = get_db()
        cur = db.cursor()

        try:
            # Parameterized query (safe)
            cur.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, password),
            )
            db.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists!")
            return redirect(url_for("register"))

    return render_template("register.html")


# --------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        db = get_db()
        cur = db.cursor()
        # Parameterized query (safe)
        cur.execute(
            "SELECT * FROM users WHERE email = ? AND password = ?",
            (email, password),
        )
        user = cur.fetchone()

        if user:
            session["user_email"] = user["email"]
            session["user_name"] = user["name"]
            flash("Login successful.")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))


# --------- Search (Detection Demo) ----------
@app.route("/search", methods=["GET", "POST"])
def search():
    results = None
    built_query = None
    message = None

    if request.method == "POST":
        term = request.form.get("term", "")

        # Vulnerable-style query STRING (for demonstration only)
        built_query = f"SELECT id, name, email, password FROM users WHERE name = '{term}'"

        # SQL injection detection based on raw user input
        if is_sql_injection(term):
            # Default severity
            severity = "MEDIUM – SQL Injection Attempt"
            # Agar vulnerable query sensitive data target kar rahi ho
            if is_data_leak(built_query):
                severity = "HIGH – Data Leak via SQL Injection"

            log_event(term, built_query, severity)
            message = f"Suspicious activity detected and blocked! ({severity})"
            return render_template(
                "search.html",
                results=None,
                built_query=built_query,
                message=message,
            )

        # If not suspicious, execute a SAFE parameterized query
        db = get_db()
        cur = db.cursor()
        # Using LIKE for partial search
        cur.execute(
            "SELECT id, name, email FROM users WHERE name LIKE ?",
            (f"%{term}%",),
        )
        results = cur.fetchall()
        message = "Search executed successfully."

    return render_template(
        "search.html",
        results=results,
        built_query=built_query,
        message=message,
    )


# --------- Admin logs ----------
@app.route("/admin/logs", methods=["GET", "POST"])
def admin_logs():
    # Simple admin check (hardcoded password for demo)
    if request.method == "POST":
        admin_pass = request.form.get("admin_pass", "")
        if admin_pass == "admin123":  # demo password
            session["is_admin"] = True
        else:
            flash("Wrong admin password.")
            return redirect(url_for("admin_logs"))

    if not session.get("is_admin"):
        return render_template("logs.html", logs=None, need_password=True)

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, timestamp, ip, username, input, query, severity "
        "FROM security_logs ORDER BY id DESC"
    )
    logs = cur.fetchall()
    return render_template("logs.html", logs=logs, need_password=False)


if __name__ == "__main__":
    # Initialize DB if not exists
    if not os.path.exists(APP_DB):
        with app.app_context():
            init_db()
    app.run(debug=True)
