import os
import re
import sqlite3
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from db import close_db, get_db, init_db

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    DATABASE=os.path.join(app.root_path, "app.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false") == "true",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5 MB (lo usaremos en la subida)
)

CSRFProtect(app)
app.teardown_appcontext(close_db)

with app.app_context():
    init_db()

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not EMAIL_RE.match(email) or len(email) > 254:
            flash("Correo no válido.")
        elif len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, generate_password_hash(password)),
                )
                db.commit()
                flash("Cuenta creada. Ya puedes iniciar sesión.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("No se pudo crear la cuenta con esos datos.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("history"))
        flash("Correo o contraseña incorrectos.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/history")
@login_required
def history():
    rows = get_db().execute(
        "SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("history.html", analyses=rows)


@app.route("/health")
def health():
    get_db().execute("SELECT 1")
    return "ok", 200


if __name__ == "__main__":
    app.run(debug=True)  # solo local; en Render usaremos gunicorn