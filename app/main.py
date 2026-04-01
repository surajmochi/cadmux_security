from __future__ import annotations

import logging
import os
import smtplib
import sqlite3
from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from itsdangerous import URLSafeTimedSerializer
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
app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST")
app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", "587"))
app.config["SMTP_USER"] = os.environ.get("SMTP_USER")
app.config["SMTP_PASS"] = os.environ.get("SMTP_PASS")
app.config["MAIL_SENDER"] = os.environ.get("MAIL_SENDER", "no-reply@cadmux.local")
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
            is_verified INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )

    columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "is_verified" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER NOT NULL DEFAULT 0")

    db.commit()
    db.close()


def serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


def build_token(email: str, purpose: str) -> str:
    return serializer().dumps(email, salt=f"cadmux-{purpose}")


def read_token(token: str, purpose: str, max_age_seconds: int = 3600) -> str | None:
    try:
        return serializer().loads(token, salt=f"cadmux-{purpose}", max_age=max_age_seconds)
    except Exception:
        return None


def send_email(to_email: str, subject: str, body: str) -> None:
    host = app.config["SMTP_HOST"]
    user = app.config["SMTP_USER"]
    password = app.config["SMTP_PASS"]
    sender = app.config["MAIL_SENDER"]

    if not host:
        logger.warning("SMTP not configured. Email to %s\nSubject: %s\n%s", to_email, subject, body)
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP(host, app.config["SMTP_PORT"], timeout=15) as smtp:
        smtp.starttls()
        if user and password:
            smtp.login(user, password)
        smtp.send_message(msg)


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
            "INSERT INTO users (name, email, password_hash, is_verified, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash(password), 0, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        flash("Email already registered. Please login.", "error")
        return redirect(url_for("register_page"))

    token = build_token(email, "verify")
    verify_url = url_for("verify_registration", token=token, _external=True)
    send_email(
        email,
        "Verify your Cadmux Security account",
        (
            f"Hi {name},\n\n"
            "Thank you for registering with Cadmux Security.\n"
            f"Click this link to verify your account: {verify_url}\n\n"
            "If you did not create this account, you can ignore this email."
        ),
    )
    flash("Registration created. Please verify through the email we sent before logging in.", "success")
    return redirect(url_for("login"))


@app.get("/verify-registration/<token>")
def verify_registration(token: str) -> str:
    email = read_token(token, "verify", max_age_seconds=86400)
    if not email:
        flash("Verification link is invalid or expired. Please register again.", "error")
        return redirect(url_for("register_page"))

    db = get_db()
    user = db.execute("SELECT id, is_verified FROM users WHERE email = ?", (email,)).fetchone()
    if user is None:
        flash("Account not found for this verification link.", "error")
        return redirect(url_for("register_page"))

    if user["is_verified"]:
        flash("Your account is already verified. Please login.", "success")
        return redirect(url_for("login"))

    db.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
    db.commit()
    flash("Email verification successful. Please sign in.", "success")
    return redirect(url_for("login"))


@app.get("/login")
def login() -> str:
    return render_template("login.html")


@app.post("/login")
def login_submit() -> str:
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    user = get_db().execute(
        "SELECT id, name, email, password_hash, is_verified FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password.", "error")
        return redirect(url_for("login"))

    if not user["is_verified"]:
        flash("Please verify your email before signing in.", "error")
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

    db = get_db()
    row = db.execute("SELECT id, name FROM users WHERE email = ?", (email,)).fetchone()

    if row is None:
        flash("No account found with that email.", "error")
        return redirect(url_for("forgot_password_page"))

    token = build_token(email, "reset")
    reset_url = url_for("reset_password_page", token=token, _external=True)
    send_email(
        email,
        "Cadmux Security password reset verification",
        (
            f"Hi {row['name']},\n\n"
            "We received a password reset request for your account.\n"
            f"Verify the request and continue by opening this link: {reset_url}\n\n"
            "If this was not you, ignore this email."
        ),
    )
    flash("A verification email has been sent with your password reset link.", "success")
    return redirect(url_for("login"))


@app.get("/reset-password/<token>")
def reset_password_page(token: str) -> str:
    email = read_token(token, "reset", max_age_seconds=3600)
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password_page"))

    return render_template("reset_password.html", token=token, email=email)


@app.post("/reset-password/<token>")
def reset_password_submit(token: str) -> str:
    email = read_token(token, "reset", max_age_seconds=3600)
    if not email:
        flash("Reset link is invalid or expired.", "error")
        return redirect(url_for("forgot_password_page"))

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("reset_password_page", token=token))

    db = get_db()
    user = db.execute(
        "SELECT password_hash FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    if user is None:
        flash("No account found with that email.", "error")
        return redirect(url_for("forgot_password_page"))

    if not check_password_hash(user["password_hash"], old_password):
        flash("Old password is incorrect.", "error")
        return redirect(url_for("reset_password_page", token=token))

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
