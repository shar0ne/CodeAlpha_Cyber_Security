# CodeAlpha_SecureCodingReview

Projet réalisé dans le cadre du stage **Cyber Security — CodeAlpha** (Task 3 : Secure Coding Review).

## 📁 Structure du projet

```
CodeAlpha_SecureCodingReview/
├── vulnerable_app/app.py     # Application volontairement vulnérable (support de l'audit)
├── fixed_app/app.py          # Version corrigée après remédiation
├── SECURITY_REVIEW_REPORT.md # Rapport d'audit complet (10 vulnérabilités, CWE, PoC, correctifs)
└── README.md
```

## 🎯 Objectif

Auditer une application Python/Flask pour identifier des vulnérabilités de sécurité, produire un
rapport détaillé (sévérité, CWE, preuve de concept, recommandation) et livrer une version corrigée
du code.

## 🔍 Vulnérabilités identifiées

10 vulnérabilités couvrant l'OWASP Top 10 : injection SQL, XSS, injection de commande,
désérialisation non sécurisée, IDOR, CSRF, secrets codés en dur, hash faible, fuite d'information,
mode debug actif. Détail complet dans [`SECURITY_REVIEW_REPORT.md`](./SECURITY_REVIEW_REPORT.md).

## ▶️ Lancer l'application

```bash
pip install -r vulnerable_app/requirements.txt

# Version vulnérable (à des fins pédagogiques uniquement, ne jamais exposer sur internet)
cd vulnerable_app && python3 app.py

# Version corrigée
cd fixed_app && python3 app.py
```

## ⚠️ Avertissement

Le dossier `vulnerable_app/` contient du code intentionnellement non sécurisé. Il ne doit être
exécuté que dans un environnement local isolé, jamais déployé publiquement.

## 🛠️ Outils recommandés en complément

- [Bandit](https://bandit.readthedocs.io/) — analyse statique de sécurité pour Python
- [OWASP ZAP](https://www.zaproxy.org/) — test dynamique (DAST)
- [Semgrep](https://semgrep.dev/) — analyse statique multi-langage
