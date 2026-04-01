from __future__ import annotations

import logging
import sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.core.models import ScanRequest, ScanResult
from app.core.plugin_manager import PluginManager
from app.plugins.nmap_tool import NmapTool

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("cadmux-security")

app = Flask(__name__)
app.config["SECRET_KEY"] = "cadmux-security-local-key"
app.config["DATABASE"] = Path(__file__).resolve().parent / "cadmux_security.db"
plugins = PluginManager()
plugins.register(NmapTool())
recent_scans: deque[ScanResult] = deque(maxlen=30)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db() -> None:
    db = sqlite3.connect(app.config["DATABASE"])
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()
    db.close()


@app.before_request
def load_user() -> None:
    g.user = None
    user_id = session.get("user_id")
    if user_id is None:
        return

    row = get_db().execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    g.user = row


@app.teardown_appcontext
def close_db(_exception: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.get("/")
def root() -> str:
    if g.user:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.get("/register")
def register_page() -> str:
    return render_template("register.html")


@app.post("/register")
def register() -> str:
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not email or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("register_page"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("register_page"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, email, generate_password_hash(password), datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
        flash("Registration successful. Please sign in.", "success")
    except sqlite3.IntegrityError:
        flash("Email already registered. Please login.", "error")
        return redirect(url_for("register_page"))

    return redirect(url_for("login"))


@app.get("/login")
def login() -> str:
    return render_template("login.html")


@app.post("/login")
def login_submit() -> str:
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = get_db().execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    session.clear()
    session["user_id"] = user["id"]
    flash(f"Welcome back, {user['name']}!", "success")
    return redirect(url_for("home"))


@app.get("/forgot-password")
def forgot_password_page() -> str:
    return render_template("forgot_password.html")


@app.post("/forgot-password")
def forgot_password_submit() -> str:
    email = request.form.get("email", "").strip().lower()
    new_password = request.form.get("new_password", "")

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("forgot_password_page"))

    db = get_db()
    row = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

    if row is None:
        flash("No account found with that email.", "error")
        return redirect(url_for("forgot_password_page"))

    db.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (generate_password_hash(new_password), email),
    )
    db.commit()
    flash("Password reset successful. Please login.", "success")
    return redirect(url_for("login"))


@app.post("/logout")
def logout() -> str:
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.get("/dashboard")
def home() -> str:
    if g.user is None:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        tool_options=plugins.list_tools(),
        scan_options=sorted(NmapTool.SCAN_TYPES.keys()),
        recent_scans=list(recent_scans),
        now=datetime.now(timezone.utc),
        user=g.user,
    )


@app.post("/scan")
def run_scan() -> str:
    if g.user is None:
        flash("Please login first.", "error")
        return redirect(url_for("login"))

    tool_name = request.form.get("tool", "nmap")
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "quick").strip()
    extra = request.form.get("extra_args", "").strip()
    extra_args = [a for a in extra.split() if a]

    try:
        plugin = plugins.get(tool_name)
        scan_request = ScanRequest(target=target, scan_type=scan_type, extra_args=extra_args)
        result = plugin.scan(scan_request)
        recent_scans.appendleft(result)
        logger.info("scan completed status=%s target=%s", result.status, target)
    except Exception as exc:
        logger.exception("scan failed")
        failure = ScanResult(
            tool=tool_name,
            target=target,
            command="",
            status="error",
            error=str(exc),
        )
        failure.finished_at = datetime.now(timezone.utc)
        recent_scans.appendleft(failure)

    return render_template(
        "index.html",
        tool_options=plugins.list_tools(),
        scan_options=sorted(NmapTool.SCAN_TYPES.keys()),
        recent_scans=list(recent_scans),
        now=datetime.now(timezone.utc),
        user=g.user,
    )


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
