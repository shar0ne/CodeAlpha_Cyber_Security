# Secure Coding Review — VulnBank (Flask Application)
**CodeAlpha Cyber Security Internship — Task 3**

**Auditeur :** [Ton nom]
**Date :** Juillet 2026
**Application auditée :** VulnBank — mini-application bancaire Python/Flask (usage pédagogique)
**Langage :** Python 3 / Flask
**Méthodologie :** Revue manuelle du code source (SAST manuel) + preuves de concept (PoC) dynamiques

---

## 1. Résumé exécutif

L'application `VulnBank` a été auditée ligne par ligne afin d'identifier les vulnérabilités
introduites lors du développement. **10 vulnérabilités** ont été identifiées, dont **4 critiques**
et **3 élevées**, couvrant notamment l'injection SQL, l'exécution de commande arbitraire, la
désérialisation non sécurisée et un contrôle d'accès défaillant (IDOR). Toutes les failles ont
été corrigées dans `fixed_app/app.py` et validées par des tests automatisés reproduisant les
attaques d'origine.

| Sévérité | Nombre |
|---|---|
| 🔴 Critique | 4 |
| 🟠 Élevée | 3 |
| 🟡 Moyenne | 2 |
| 🔵 Faible | 1 |

## 2. Méthodologie

1. **Revue manuelle** du code source, fichier par fichier, à la recherche des patterns à risque
   (concaténation de requêtes SQL, `os.system`/`os.popen`, `pickle.loads`, `eval`, secrets en dur, etc.)
2. **Analyse statique complémentaire recommandée** : `bandit -r vulnerable_app/` (outil standard
   pour Python) — exécution non disponible dans cet environnement sandboxé, mais chaque finding
   ci-dessous est mappé sur son identifiant Bandit équivalent quand applicable.
3. **Preuves de concept dynamiques** : chaque vulnérabilité critique/élevée a été reproduite avec
   le client de test Flask pour confirmer son exploitabilité réelle (voir section 4).
4. **Remédiation** : chaque faille a été corrigée dans `fixed_app/app.py`, puis re-testée pour
   confirmer que l'attaque échoue désormais.

## 3. Tableau des vulnérabilités

| ID | Vulnérabilité | CWE | Sévérité | Localisation | Outil Bandit |
|---|---|---|---|---|---|
| VULN-01 | Secret key codée en dur | CWE-798 | 🟠 Élevée | `app.py:19` | B105 |
| VULN-02 | Hash de mot de passe faible (MD5, sans sel) | CWE-916 | 🟠 Élevée | `app.py:29-33` | B324 |
| VULN-03 | Injection SQL (login) | CWE-89 | 🔴 Critique | `app.py:58` | B608 |
| VULN-04 | Fuite d'information via message d'erreur | CWE-209 | 🔵 Faible | `app.py:66` | — |
| VULN-05 | Contrôle d'accès défaillant / IDOR | CWE-639 | 🔴 Critique | `app.py:75-84` | — |
| VULN-06 | Cross-Site Scripting (XSS) réfléchi | CWE-79 | 🟠 Élevée | `app.py:90-95` | — |
| VULN-07 | Injection de commande OS | CWE-78 | 🔴 Critique | `app.py:101-105` | B605/B607 |
| VULN-08 | Désérialisation non sécurisée (`pickle`) | CWE-502 | 🔴 Critique | `app.py:111-117` | B301 |
| VULN-09 | Absence de protection CSRF | CWE-352 | 🟡 Moyenne | `app.py:121-130` | — |
| VULN-10 | Mode debug activé | CWE-215 | 🟡 Moyenne | `app.py:140` | B201 |

## 4. Détail des vulnérabilités

### 🔴 VULN-03 — Injection SQL (Critique)
**Localisation :** route `/login`
**Description :** Le nom d'utilisateur et le mot de passe sont insérés directement dans la
requête SQL par concaténation de chaînes.
**Preuve de concept validée :** en soumettant `username = admin' -- ` (avec un mot de passe
quelconque), la clause `WHERE` devient `WHERE username = 'admin' -- AND password = '...'` : le
`--` commente le reste de la requête et l'authentification est contournée. **Testé et confirmé** :
connexion réussie au compte admin sans connaître le mot de passe.
**Recommandation :** utiliser systématiquement des requêtes paramétrées (`?` + tuple de valeurs),
jamais de f-string/concaténation avec une entrée utilisateur.
**Statut :** ✅ Corrigé (`fixed_app/app.py`, requête paramétrée + `check_password_hash`).

### 🔴 VULN-05 — Contrôle d'accès défaillant / IDOR (Critique)
**Localisation :** route `/account/<user_id>`
**Description :** N'importe qui (même non authentifié) peut consulter le solde de n'importe quel
compte en changeant l'identifiant dans l'URL.
**Preuve de concept validée :** requête anonyme sur `/account/1` → renvoie le solde complet du
compte admin ($50 000), sans aucune session.
**Recommandation :** exiger une authentification (`@login_required`) et vérifier que
`session["user_id"] == user_id` avant de renvoyer les données.
**Statut :** ✅ Corrigé (décorateur `login_required` + vérification stricte de propriété).

### 🔴 VULN-07 — Injection de commande OS (Critique)
**Localisation :** route `/ping`
**Description :** Le paramètre `host` est injecté directement dans une commande shell via
`os.popen()`. Un attaquant peut envoyer `127.0.0.1; cat /etc/passwd` pour exécuter des commandes
arbitraires sur le serveur.
**Recommandation :** valider strictement l'entrée (ex. avec le module `ipaddress`) et exécuter la
commande sans shell (`subprocess.run([...], shell=False)`).
**Statut :** ✅ Corrigé.

### 🔴 VULN-08 — Désérialisation non sécurisée (Critique)
**Localisation :** route `/load_profile`
**Description :** `pickle.loads()` est appelé sur une donnée fournie par l'utilisateur. Le format
pickle permet l'exécution de code arbitraire lors de la désérialisation d'un objet malveillant
(ex. via `__reduce__`).
**Recommandation :** ne jamais désérialiser du pickle provenant d'une source non fiable ; utiliser
un format de données pur comme JSON.
**Statut :** ✅ Corrigé (remplacement par `json.loads`).

### 🟠 VULN-01 — Secret key codée en dur (Élevée)
La clé de session Flask (`secret_key`) est visible dans le code source. Si le dépôt est exposé
(GitHub public par erreur), un attaquant peut forger des cookies de session valides.
**Statut :** ✅ Corrigé (lecture depuis une variable d'environnement).

### 🟠 VULN-02 — Hash de mot de passe faible (Élevée)
MD5 est rapide à calculer et ne sale pas les mots de passe : il est cassable par table arc-en-ciel
en quelques secondes pour des mots de passe courants.
**Statut :** ✅ Corrigé (PBKDF2 salé via `werkzeug.security`, recommandation future : bcrypt/argon2).

### 🟠 VULN-06 — XSS réfléchi (Élevée)
Le paramètre `q` de `/search` est injecté tel quel dans le HTML retourné.
**Preuve de concept validée :** `/search?q=<script>alert(1)</script>` renvoie le script tel quel
dans le HTML.
**Statut :** ✅ Corrigé (passage à `render_template_string` avec `{{ q }}`, échappement
automatique Jinja2 confirmé par test : `<script>` devient `&lt;script&gt;`).

### 🟡 VULN-09 — Absence de protection CSRF (Moyenne)
La route `/transfer` modifie l'état (transfert d'argent) sans vérifier de jeton CSRF : un site
malveillant pourrait forcer le navigateur d'une victime connectée à effectuer un virement à son insu.
**Statut :** ✅ Corrigé (jeton CSRF généré par session, vérifié à chaque soumission).

### 🟡 VULN-10 — Mode debug activé (Moyenne)
`debug=True` expose le débogueur interactif Werkzeug, qui permet l'exécution de code arbitraire
si un attaquant atteint une page d'erreur en production.
**Statut :** ✅ Corrigé (contrôlé par variable d'environnement, désactivé par défaut).

### 🔵 VULN-04 — Fuite d'information (Faible)
Le message d'erreur de connexion renvoie le nom d'utilisateur saisi, ce qui aide un attaquant à
énumérer les comptes existants.
**Statut :** ✅ Corrigé (message générique "Invalid username or password").

## 5. Recommandations générales

1. Adopter un **linter de sécurité automatisé** (Bandit pour Python, `npm audit`/Semgrep pour
   d'autres langages) intégré en CI/CD.
2. Ne **jamais** committer de secrets dans le code — utiliser un gestionnaire de secrets ou des
   variables d'environnement (`.env` + `.gitignore`).
3. Appliquer le principe du **moindre privilège** sur tout contrôle d'accès (vérifier l'appartenance
   des ressources, pas seulement l'authentification).
4. Toujours utiliser des **requêtes paramétrées** pour toute interaction avec une base de données.
5. Mettre en place des **tests de sécurité automatisés** (comme ceux réalisés dans ce rapport) dans
   la suite de tests du projet, pour éviter les régressions.

## 6. Comment reproduire cet audit

```bash
# Installer les dépendances
pip install -r vulnerable_app/requirements.txt

# Lancer l'app vulnérable
cd vulnerable_app && python3 app.py

# Dans un autre terminal, tester l'injection SQL :
curl -X POST http://127.0.0.1:5000/login -d "username=admin' -- &password=x"

# Comparer avec la version corrigée (fixed_app/) : la même requête renvoie 401.
```

---
*Rapport rédigé dans le cadre du stage Cyber Security CodeAlpha — Tâche 3 : Secure Coding Review.*
