"""
VulnBank - Mini application bancaire de démonstration
========================================================
ATTENTION : Cette application contient des vulnérabilités INTENTIONNELLES.
Elle sert uniquement de support pédagogique pour la tâche
"Secure Coding Review" (CodeAlpha - Cyber Security Internship).
NE JAMAIS déployer ce code en production.

Chaque vulnérabilité est signalée par un commentaire [VULN-xx]
qui correspond à une entrée du rapport SECURITY_REVIEW_REPORT.md
"""

import sqlite3
import os
import pickle
import hashlib
import base64
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# [VULN-01] Secret key codée en dur dans le code source (CWE-798: Use of Hard-coded Credentials)
app.secret_key = "supersecret123"

DB_PATH = "vulnbank.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    password TEXT,
                    balance REAL)""")
    # [VULN-02] Mots de passe stockés avec un hash faible et sans sel (CWE-916: Use of Weak Hash)
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        demo_users = [
            ("admin", hashlib.md5("admin123".encode()).hexdigest(), 50000.0),
            ("alice", hashlib.md5("alice2024".encode()).hexdigest(), 1200.0),
            ("bob", hashlib.md5("bobpass".encode()).hexdigest(), 340.0),
        ]
        c.executemany("INSERT INTO users (username, password, balance) VALUES (?, ?, ?)", demo_users)
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return "<h2>VulnBank</h2><p><a href='/login'>Login</a></p>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        password_hash = hashlib.md5(password.encode()).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # [VULN-03] Injection SQL - concaténation directe de l'entrée utilisateur (CWE-89)
        query = f"SELECT id, username, balance FROM users WHERE username = '{username}' AND password = '{password_hash}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(f"/account/{user[0]}")
        else:
            # [VULN-04] Message d'erreur trop détaillé (CWE-209: Information Exposure Through an Error Message)
            return f"Login failed for user '{username}'. Check credentials and try again."

    return """
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit" value="Login">
        </form>
    """


@app.route("/account/<user_id>")
def account(user_id):
    # [VULN-05] Contrôle d'accès défaillant / IDOR (CWE-639: Authorization Bypass Through User-Controlled Key)
    # N'importe quel utilisateur connecté (ou pas) peut consulter le solde de n'importe quel compte
    # simplement en changeant l'ID dans l'URL, sans vérification que user_id == session["user_id"].
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, balance FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    if not user:
        return "User not found", 404
    return f"<h3>Account of {user[0]}</h3><p>Balance: ${user[1]}</p>"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # [VULN-06] Cross-Site Scripting (XSS) réfléchi - l'entrée utilisateur est injectée
    # directement dans le HTML sans échappement (CWE-79)
    template = f"<h3>Search results for: {query}</h3><p>No results found.</p>"
    return render_template_string(template)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    host = request.values.get("host", "127.0.0.1")
    # [VULN-07] Injection de commande OS - l'entrée utilisateur est passée directement
    # au shell système (CWE-78: OS Command Injection)
    result = os.popen(f"ping -c 1 {host}").read()
    return f"<pre>{result}</pre>"


@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.form.get("data", "")
    # [VULN-08] Désérialisation non sécurisée - pickle.loads sur une donnée fournie
    # par l'utilisateur permet l'exécution de code arbitraire (CWE-502)
    decoded = base64.b64decode(data)
    profile = pickle.loads(decoded)
    return f"Profile loaded: {profile}"


@app.route("/transfer", methods=["POST"])
def transfer():
    # [VULN-09] Absence de protection CSRF sur une action sensible qui modifie l'état
    # (transfert d'argent) — pas de token CSRF vérifié (CWE-352)
    to_id = request.form.get("to_id")
    amount = request.form.get("amount")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    conn.commit()
    conn.close()
    return "Transfer completed"


if __name__ == "__main__":
    init_db()
    # [VULN-10] Mode debug activé - expose le débogueur interactif Werkzeug qui permet
    # l'exécution de code arbitraire si un attaquant atteint une page d'erreur (CWE-215)
    app.run(host="0.0.0.0", port=5000, debug=True)
