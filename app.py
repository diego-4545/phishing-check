import io
import json
import os
import re
import sqlite3
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFProtect
from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from analyzer import AnalysisError, analyze_image
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

Image.MAX_IMAGE_PIXELS = 25_000_000  # evita imágenes "bomba" de descompresión
MAX_IMAGE_BYTES = 5 * 1024 * 1024


def read_valid_image(file_storage):
    """Devuelve (bytes, mime) si es PNG o JPEG real; si no, lanza ValueError."""
    data = file_storage.read(MAX_IMAGE_BYTES + 1)
    if not data or len(data) > MAX_IMAGE_BYTES:
        raise ValueError("tamaño")
    try:
        img = Image.open(io.BytesIO(data))
        img.verify()
        fmt = img.format
    except Exception:
        raise ValueError("no es imagen")
    if fmt == "PNG":
        return data, "image/png"
    if fmt == "JPEG":
        return data, "image/jpeg"
    raise ValueError("formato")


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

@app.errorhandler(413)
def too_large(e):
    flash("La imagen supera los 5 MB.")
    return render_template("analyze.html"), 413


@app.route("/analyze", methods=["GET", "POST"])
@login_required
def analyze():
    if request.method == "POST":
        file = request.files.get("image")
        if not file or not file.filename:
            flash("Selecciona una imagen.")
            return render_template("analyze.html")

        try:
            data, mime = read_valid_image(file)
        except ValueError:
            flash("Archivo no válido. Sube una imagen PNG o JPG de hasta 5 MB.")
            return render_template("analyze.html")

        try:
            result = analyze_image(data, mime, file.filename)
        except AnalysisError:
            flash("No se pudo analizar la imagen. Intenta de nuevo.")
            return render_template("analyze.html")

        if result["veredicto"] == "no_es_correo":
            flash("La imagen no parece ser la captura de un correo. "
                  "Sube una captura del correo completo, con remitente y asunto visibles.")
            return render_template("analyze.html")

        db = get_db()
        cur = db.execute(
            "INSERT INTO analyses (user_id, filename, verdict, confidence, "
            "signals, recommendation) VALUES (?, ?, ?, ?, ?, ?)",
            (
                session["user_id"],
                secure_filename(file.filename)[:100] or "imagen",
                result["veredicto"],
                result["confianza"],
                json.dumps(result["senales"], ensure_ascii=False),
                result["recomendacion"],
            ),
        )
        db.commit()
        return redirect(url_for("analysis_detail", analysis_id=cur.lastrowid))
    return render_template("analyze.html")


@app.route("/analysis/<int:analysis_id>")
@login_required
def analysis_detail(analysis_id):
    row = get_db().execute(
        "SELECT * FROM analyses WHERE id = ? AND user_id = ?",
        (analysis_id, session["user_id"]),
    ).fetchone()
    if row is None:
        abort(404)
    return render_template("result.html", a=row, signals=json.loads(row["signals"]))

@app.route("/health")
def health():
    get_db().execute("SELECT 1")
    return "ok", 200


if __name__ == "__main__":
    app.run(debug=True)  # solo local; en Render usaremos gunicorn