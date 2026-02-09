import os
import socket
import sqlite3
import secrets
import time
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash


# =========================================================
# Flask App Configuration
# =========================================================

app = Flask(__name__)

# In production, set this from environment variable
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# SQLite database file (use DATABASE env for Docker volume persistence)
app.config["DATABASE"] = os.environ.get(
    "DATABASE",
    os.path.join(os.path.dirname(__file__), "secure_auth.db"),
)

# Secure session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# For real HTTPS deployment, keep this True. For local http testing, you can set to False.
app.config["SESSION_COOKIE_SECURE"] = False  # change to True when using HTTPS

# Simple brute-force protection settings
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME_SECONDS = 5 * 60  # 5 minutes

# Store login attempts in-memory (per IP)
login_attempts = {}  # key: identifier, value: {"count": int, "lock_until": timestamp}


# =========================================================
# Database Helpers
# =========================================================


def get_db():
    """Get a connection to the SQLite database (one per request)."""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row  # return dict-like rows
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database and create default admin user."""
    db = get_db()
    # Create users table (if not exists)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
        )
        """
    )
    db.commit()

    # Create a default admin user if not exists
    cur = db.execute("SELECT id FROM users WHERE username = ?", ("admin",))
    if cur.fetchone() is None:
        # Demo password – explain in viva that this must be changed in production
        admin_password = "Admin@123"
        password_hash = generate_password_hash(
            admin_password, method="pbkdf2:sha256", salt_length=16
        )
        db.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            ("admin", "admin@example.com", password_hash, "admin"),
        )
        db.commit()
        print("Created default admin user:")
        print("  username: admin")
        print("  password: Admin@123")


# =========================================================
# CSRF Protection
# =========================================================


def generate_csrf_token():
    """Generate a CSRF token and store it in the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(token_from_form):
    """Validate CSRF token sent with the form."""
    session_token = session.get("csrf_token", None)
    if not session_token or not token_from_form:
        return False
    return secrets.compare_digest(session_token, token_from_form)


@app.before_request
def set_csrf_token():
    """Ensure a CSRF token exists for the session before handling any request."""
    generate_csrf_token()


# Make csrf_token available in all templates
app.jinja_env.globals["csrf_token"] = generate_csrf_token


# =========================================================
# Security Headers
# =========================================================


@app.after_request
def set_security_headers(response):
    """Set basic security headers on all responses."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' https://cdn.tailwindcss.com; "
        "img-src 'self' data:;"
    )
    return response


# =========================================================
# Authentication & Authorization Helpers
# =========================================================


def login_required(view_func):
    """Decorator to require a logged-in user."""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def role_required(required_role):
    """Decorator to require a specific user role (e.g., admin)."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for("login"))

            if session.get("role") != required_role:
                flash("You are not authorized to access this page.", "error")
                return redirect(url_for("user_dashboard"))
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator


def get_current_user():
    """Return the current logged-in user record, or None."""
    if "user_id" not in session:
        return None
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    return cur.fetchone()


# =========================================================
# Brute-Force Protection Helpers
# =========================================================


def get_identifier():
    """
    Identifier for login attempts (IP for simplicity).
    """
    return request.remote_addr or "unknown"


def is_locked_out(identifier):
    info = login_attempts.get(identifier)
    if not info:
        return False
    if info.get("lock_until", 0) > time.time():
        return True
    return False


def register_failed_attempt(identifier):
    now = time.time()
    info = login_attempts.get(identifier, {"count": 0, "lock_until": 0})
    if info.get("lock_until", 0) > now:
        # Already locked
        login_attempts[identifier] = info
        return
    info["count"] += 1
    if info["count"] >= MAX_LOGIN_ATTEMPTS:
        info["lock_until"] = now + LOCKOUT_TIME_SECONDS
        info["count"] = 0  # reset after locking
    login_attempts[identifier] = info


def reset_attempts(identifier):
    if identifier in login_attempts:
        del login_attempts[identifier]


# =========================================================
# Simple Input Validation
# =========================================================


def is_valid_username(username):
    """Allow basic alphanumeric usernames with _, -, . and length between 3 and 30."""
    if not username:
        return False
    if len(username) < 3 or len(username) > 30:
        return False
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    return all(c in allowed_chars for c in username)


def is_valid_email(email):
    """Very basic email validation for demo purposes."""
    if not email or "@" not in email or "." not in email:
        return False
    return True


def is_strong_password(password):
    """Password strength check: min 8 chars, upper, lower, and digit required."""
    if not password or len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_upper and has_lower and has_digit


# =========================================================
# Routes
# =========================================================


@app.route("/logo.png")
def serve_logo():
    """Explicitly serve logo (ensures it loads regardless of static config)."""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    path = os.path.join(static_dir, "logo.png")
    if os.path.exists(path):
        return send_from_directory(static_dir, "logo.png", mimetype="image/png")
    return "", 404


@app.route("/")
def index():
    """Home redirects based on authentication status."""
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration page."""
    if request.method == "POST":
        # CSRF check
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("Invalid CSRF token. Please try again.", "error")
            return redirect(url_for("register"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Input validation
        if not is_valid_username(username):
            flash("Invalid username. Use 3-30 letters, numbers, _ , - , .", "error")
            return render_template("register.html")
        if not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")
        if not is_strong_password(password):
            flash(
                "Password must be at least 8 characters with uppercase, lowercase, and a number.",
                "error",
            )
            return render_template("register.html")
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        db = get_db()

        # Check if username or email already exists (parameterized query)
        cur = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email),
        )
        if cur.fetchone() is not None:
            flash("An account with this username or email already exists.", "error")
            return render_template("register.html")

        # Hash the password using Werkzeug PBKDF2 + SHA-256
        password_hash = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=16
        )

        # Insert new user with "user" role
        db.execute(
            """
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            """,
            (username, email, password_hash, "user"),
        )
        db.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page with brute-force protection."""
    if request.method == "POST":
        # CSRF check
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("Invalid CSRF token. Please try again.", "error")
            return redirect(url_for("login"))

        identifier = get_identifier()
        if is_locked_out(identifier):
            flash(
                "Too many failed login attempts. Please try again after some time.",
                "error",
            )
            return render_template("login.html")

        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        # Use parameterized query to prevent SQL injection
        cur = db.execute(
            """
            SELECT * FROM users
            WHERE username = ? OR email = ?
            """,
            (username_or_email, username_or_email),
        )
        user = cur.fetchone()

        # Generic error message
        generic_error = "Invalid username/email or password."

        if user is None or not check_password_hash(user["password_hash"], password):
            register_failed_attempt(identifier)
            flash(generic_error, "error")
            return render_template("login.html")

        # Successful login: reset brute-force attempts
        reset_attempts(identifier)

        # Set session data
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        flash("Logged in successfully.", "success")
        if user["role"] == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("user_dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    """Log the user out and clear the session (POST only to prevent accidental logouts)."""
    if not validate_csrf_token(request.form.get("csrf_token")):
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("index"))
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/user/dashboard")
@login_required
def user_dashboard():
    """Dashboard for regular users."""
    user = get_current_user()
    if user is None:
        flash("Session is invalid. Please log in again.", "error")
        return redirect(url_for("login"))
    if user["role"] != "user":
        # Redirect admins to admin dashboard
        return redirect(url_for("admin_dashboard"))
    return render_template("user_dashboard.html", user=user)


@app.route("/admin/dashboard")
@role_required("admin")
def admin_dashboard():
    """Dashboard only for admin users."""
    db = get_db()
    cur = db.execute(
        "SELECT id, username, email, role FROM users ORDER BY id ASC"
    )
    users = cur.fetchall()
    admin_count = sum(1 for u in users if u["role"] == "admin")
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=len(users),
        admin_count=admin_count,
    )


@app.route("/admin/user/create", methods=["GET", "POST"])
@role_required("admin")
def admin_create_user():
    """Admin creates a new user."""
    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("Invalid request. Please try again.", "error")
            return redirect(url_for("admin_dashboard"))

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "user")

        if role not in ("admin", "user"):
            role = "user"

        if not is_valid_username(username):
            flash("Invalid username. Use 3-30 letters, numbers, _ , - , .", "error")
            return redirect(url_for("admin_dashboard"))
        if not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for("admin_dashboard"))
        if not is_strong_password(password):
            flash("Password must be 8+ chars with upper, lower, and number.", "error")
            return redirect(url_for("admin_dashboard"))

        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cur.fetchone():
            flash("Username or email already exists.", "error")
            return redirect(url_for("admin_dashboard"))

        password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
        db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role),
        )
        db.commit()
        flash(f"User {username} created successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(user_id):
    """Admin deletes a user. Cannot delete self."""
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin_dashboard"))

    if not validate_csrf_token(request.form.get("csrf_token")):
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    db = get_db()
    cur = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash(f"User {user['username']} has been deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def admin_change_role(user_id):
    """Admin toggles user role (admin/user). Cannot change own role."""
    if user_id == session.get("user_id"):
        flash("You cannot change your own role.", "error")
        return redirect(url_for("admin_dashboard"))

    if not validate_csrf_token(request.form.get("csrf_token")):
        flash("Invalid request. Please try again.", "error")
        return redirect(url_for("admin_dashboard"))

    new_role = request.form.get("role", "user")
    if new_role not in ("admin", "user"):
        new_role = "user"

    db = get_db()
    cur = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    db.commit()
    flash(f"{user['username']} is now {new_role}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """User profile: view and edit email, change password."""
    user = get_current_user()
    if not user:
        flash("Session invalid. Please log in again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        if not validate_csrf_token(request.form.get("csrf_token")):
            flash("Invalid request. Please try again.", "error")
            return redirect(url_for("profile"))

        db = get_db()
        email = request.form.get("email", "").strip().lower()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not is_valid_email(email):
            flash("Invalid email address.", "error")
            return redirect(url_for("profile"))

        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("profile"))

        updates = []
        params = []

        if email != user["email"]:
            cur = db.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, user["id"]))
            if cur.fetchone():
                flash("Email already in use.", "error")
                return redirect(url_for("profile"))
            updates.append("email = ?")
            params.append(email)

        if new_password:
            if not is_strong_password(new_password):
                flash("New password must be 8+ chars with upper, lower, and number.", "error")
                return redirect(url_for("profile"))
            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return redirect(url_for("profile"))
            updates.append("password_hash = ?")
            params.append(generate_password_hash(new_password, method="pbkdf2:sha256", salt_length=16))

        if updates:
            params.append(user["id"])
            db.execute("UPDATE users SET " + ", ".join(updates) + " WHERE id = ?", params)
            db.commit()
            flash("Profile updated successfully.", "success")
        else:
            flash("No changes made.", "info")

        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


# =========================================================
# CLI Helper to initialize DB if run directly
# =========================================================


@app.cli.command("init-db")
def init_db_command():
    """Flask CLI command: `flask init-db`."""
    init_db()
    print("Initialized the database.")


# =========================================================
# Run the application
# =========================================================

if __name__ == "__main__":
    # Initialize DB on first run
    if not os.path.exists(app.config["DATABASE"]):
        with app.app_context():
            init_db()
    # Run server: use 0.0.0.0 to allow classmates on same network to connect
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "localhost"
    print("\n" + "=" * 50)
    print("  Secure Cloud Auth is running!")
    print("  Local:   http://127.0.0.1:{}".format(port))
    print("  Network: http://{}:{}".format(local_ip, port))
    print("  Share the Network URL with classmates on same WiFi")
    print("=" * 50 + "\n")
    app.run(host=host, port=port, debug=False)

