# CodeAlpha_NetworkIDS

Projet réalisé dans le cadre du stage **Cyber Security — CodeAlpha** (Task 4 : Network Intrusion
Detection System).

## 📁 Structure du projet

```
CodeAlpha_NetworkIDS/
├── ids_demo/
│   ├── traffic_generator.py   # Génère un trafic réseau simulé (normal + 4 attaques)
│   ├── ids_engine.py          # Moteur de détection signature-based
│   ├── rules.json             # Règles de détection (façon Snort)
│   ├── dashboard.py           # Génère les graphiques d'analyse des alertes
│   └── requirements.txt
├── snort_setup/
│   └── SNORT_INSTALLATION_GUIDE.md   # Guide d'installation Snort + Suricata (production)
├── dashboard_output/          # Graphiques générés (PNG)
├── SUBMISSION_REPORT.md       # Rapport complet de soumission
└── README.md
```

## 🎯 Objectif

Détecter des activités réseau suspectes (scan de ports, flood ICMP, brute-force, injections
SQL/XSS, IP malveillantes) et visualiser les résultats.

## ▶️ Exécution rapide

```bash
cd ids_demo
pip install -r requirements.txt
python3 traffic_generator.py
python3 ids_engine.py
python3 dashboard.py
```

Résultat : `alerts.json`, `alerts.csv` et 4 graphiques dans `dashboard_output/`.

## 🛡️ Déploiement en production

Voir [`snort_setup/SNORT_INSTALLATION_GUIDE.md`](./snort_setup/SNORT_INSTALLATION_GUIDE.md) pour
installer et configurer un vrai IDS (Snort ou Suricata) avec des règles équivalentes à celles de
la démo Python.

## 📊 Rapport complet

Voir [`SUBMISSION_REPORT.md`](./SUBMISSION_REPORT.md) pour l'architecture détaillée, les règles
de détection, les résultats obtenus et les limites du projet.
