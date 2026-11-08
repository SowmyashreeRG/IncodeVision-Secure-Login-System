import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Set it before starting the application."
    )


DATABASE = "users.db"
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5


# Database connection
def get_db():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


# Initialize database
def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )
        """)


# Login required decorator
def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in to access that page.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view


# Home page
@app.route("/")
def home():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# User registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not 3 <= len(username) <= 30:
            flash("Username must contain 3–30 characters.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Unable to create this account. Try another username.", "error")

        except sqlite3.Error:
            app.logger.exception("Database error during registration.")
            flash("Registration could not be completed.", "error")

    return render_template("register.html")


# User login
@app.route("/login", methods=["GET", "POST"])
def login():
    print("LOGIN PAGE ROUTE ACCESSED")
    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:

            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user is None:
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            now = datetime.now(timezone.utc)

            # Check account lockout
            if user["locked_until"]:

                locked_until = datetime.fromisoformat(
                    user["locked_until"]
                )

                if now < locked_until:
                    flash(
                        "Account temporarily locked. Please try again later.",
                        "error"
                    )
                    return render_template("login.html")

                db.execute(
                    "UPDATE users SET failed_attempts = 0, "
                    "locked_until = NULL WHERE id = ?",
                    (user["id"],)
                )

                user = db.execute(
                    "SELECT * FROM users WHERE id = ?",
                    (user["id"],)
                ).fetchone()

            # Check password
            if check_password_hash(user["password_hash"], password):

                db.execute(
                    "UPDATE users SET failed_attempts = 0, "
                    "locked_until = NULL WHERE id = ?",
                    (user["id"],)
                )

                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                flash("Login successful!", "success")
                return redirect(url_for("dashboard"))

            # Handle failed login attempts
            attempts = user["failed_attempts"] + 1

            if attempts >= MAX_ATTEMPTS:

                lock_until = now + timedelta(
                    minutes=LOCKOUT_MINUTES
                )

                db.execute(
                    "UPDATE users SET failed_attempts = ?, "
                    "locked_until = ? WHERE id = ?",
                    (attempts, lock_until.isoformat(), user["id"])
                )

                flash(
                    "Too many failed attempts. Account locked for 5 minutes.",
                    "error"
                )

            else:

                db.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (attempts, user["id"])
                )

                remaining = MAX_ATTEMPTS - attempts

                flash(
                    f"Invalid username or password. "
                    f"{remaining} attempt(s) remaining.",
                    "error"
                )

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        username=session.get("username")
    )


# Logout
@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


# Start application
with app.app_context():
    init_db()

if __name__ == "__main__":
    print("Starting Secure Login System...")
    print("Templates folder:", app.template_folder)
    print("Application location:", app.root_path)
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)