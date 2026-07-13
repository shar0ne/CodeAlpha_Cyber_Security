"""
VulnBank - Version CORRIGÉE (Secure Coding Review - CodeAlpha)
==================================================================
Ce fichier reprend l'application vulnerable_app/app.py et corrige
chaque vulnérabilité identifiée dans SECURITY_REVIEW_REPORT.md.
Chaque correction est annotée [FIX-xx] pour correspondre au [VULN-xx]
d'origine.
"""

import os
import sqlite3
import secrets
import ipaddress
import subprocess
import json
from functools import wraps
from flask import Flask, request, render_template_string, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# [FIX-01] La clé secrète vient d'une variable d'environnement, jamais codée en dur.
#          En dev, on génère une clé aléatoire si elle est absente (à ne pas faire en prod).
app.secret_key = os.environ.get("VULNBANK_SECRET_KEY") or secrets.token_hex(32)

# [FIX-09] Cookies de session durcis contre le vol de session / CSRF basique
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,   # nécessite HTTPS en production
)

DB_PATH = "vulnbank_fixed.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    balance REAL)""")
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # [FIX-02] Hash de mot de passe fort et salé (PBKDF2 via Werkzeug, remplaçable par bcrypt/argon2)
        demo_users = [
            ("admin", generate_password_hash("Adm1n#StrongPass!"), 50000.0),
            ("alice", generate_password_hash("Alice#2024Secure"), 1200.0),
            ("bob", generate_password_hash("B0b$SecurePass"), 340.0),
        ]
        c.executemany(
            "INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)",
            demo_users,
        )
    conn.commit()
    conn.close()


def login_required(view):
    """[FIX-05] Décorateur qui impose une session valide avant d'accéder à une route protégée."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def csrf_protect(view):
    """[FIX-09] Vérifie un token CSRF sur toutes les requêtes qui modifient l'état."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            abort(403, description="Invalid or missing CSRF token")
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    return "<h2>VulnBank (Secure Edition)</h2><p><a href='/login'>Login</a></p>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # [FIX-03] Requête paramétrée - plus aucune concaténation de chaîne (empêche l'injection SQL)
        c.execute("SELECT id, username, password_hash, balance FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        # [FIX-02] Vérification du mot de passe via un hash salé + comparaison à temps constant
        if user and check_password_hash(user[2], password):
            session.clear()
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(f"/account/{user[0]}")

        # [FIX-04] Message d'erreur générique, ne révèle pas si le compte existe ou non
        return "Invalid username or password.", 401

    csrf_token = generate_csrf_token()
    return f"""
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <input type="submit" value="Login">
        </form>
    """


@app.route("/account/<int:user_id>")
@login_required
def account(user_id):
    # [FIX-05] Contrôle d'accès : un utilisateur ne peut consulter que SON PROPRE compte (anti-IDOR)
    if session["user_id"] != user_id:
        abort(403, description="You are not allowed to view this account.")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        return "User not found", 404
    return f"<h3>Account of {user[0]}</h3><p>Balance: ${user[1]:.2f}</p>"


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    # [FIX-06] Utilisation du moteur de template Jinja2 avec {{ }} : l'échappement HTML
    # automatique neutralise les tentatives de XSS (contrairement au f-string précédent).
    template = "<h3>Search results for: {{ q }}</h3><p>No results found.</p>"
    return render_template_string(template, q=query)


@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    host = request.values.get("host", "127.0.0.1")
    # [FIX-07] Validation stricte de l'entrée (doit être une IP valide) + appel sans shell
    # (shell=False, liste d'arguments) : élimine l'injection de commande.
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return "Invalid IP address", 400

    result = subprocess.run(
        ["ping", "-c", "1", str(ip_obj)],
        capture_output=True, text=True, timeout=5, shell=False
    )
    return f"<pre>{result.stdout}</pre>"


@app.route("/load_profile", methods=["POST"])
@login_required
def load_profile():
    # [FIX-08] Remplacement de pickle (exécution de code arbitraire) par JSON
    # (format de données pur, sans exécution de code possible).
    raw = request.form.get("data", "")
    try:
        profile = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return "Invalid profile data", 400
    return f"Profile loaded: {profile}"


@app.route("/transfer", methods=["POST"])
@login_required
@csrf_protect
def transfer():
    to_id = request.form.get("to_id")
    amount = request.form.get("amount")

    # Validation des entrées (type + valeur positive)
    try:
        to_id = int(to_id)
        amount = float(amount)
        if amount <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return "Invalid transfer parameters", 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # [FIX-03] Requête paramétrée également ici
    c.execute("SELECT balance FROM users WHERE id = ?", (session["user_id"],))
    sender = c.fetchone()
    if not sender or sender[0] < amount:
        conn.close()
        return "Insufficient funds", 400

    c.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, session["user_id"]))
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    conn.commit()
    conn.close()
    return "Transfer completed"


if __name__ == "__main__":
    init_db()
    # [FIX-10] Mode debug désactivé, contrôlé par une variable d'environnement pour le dev local uniquement.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
