# Network Intrusion Detection System — Rapport de soumission
**CodeAlpha Cyber Security Internship — Task 4**

**Auteur :** [Ton nom]
**Date :** Juillet 2026

## 1. Objectif

Mettre en place un système de détection d'intrusion réseau (IDS) capable de :
1. Surveiller le trafic réseau en continu
2. Détecter des activités suspectes ou malveillantes via des règles/signatures
3. Générer des alertes
4. Visualiser les attaques détectées sous forme de graphiques/dashboard

## 2. Approche retenue

Le projet a été réalisé en deux volets complémentaires :

1. **Démo fonctionnelle en Python** (`ids_demo/`) : un moteur IDS signature-based complet,
   fonctionnel de bout en bout, ne nécessitant ni droits root ni accès réseau (idéal pour du
   développement, des tests automatisés ou une démonstration rapide).
2. **Guide d'installation Snort/Suricata** (`snort_setup/`) : la configuration d'un véritable
   IDS de production, avec des règles strictement équivalentes à celles de la démo Python, pour
   un déploiement réel sur un réseau.

## 3. Architecture de la démo Python

```
traffic_generator.py  →  traffic_log.json  →  ids_engine.py  →  alerts.json / alerts.csv
                                                     ↑                    ↓
                                                 rules.json          dashboard.py
                                                                          ↓
                                                              dashboard_output/*.png
```

1. **`traffic_generator.py`** simule une capture réseau réaliste : trafic normal (HTTP, DNS)
   mélangé à 4 scénarios d'attaque (port scan, ICMP flood, brute-force login, payloads
   malveillants SQLi/XSS/path traversal/webshell).
2. **`rules.json`** définit les règles de détection de façon déclarative (seuils, fenêtres
   temporelles, signatures regex), sur le même principe que les règles `.rules` de Snort.
3. **`ids_engine.py`** lit le trafic paquet par paquet (comme le ferait `scapy.sniff()` en
   direct) et applique les règles avec des fenêtres glissantes par IP source.
4. **`dashboard.py`** transforme les alertes en 4 visualisations (types, sévérités, chronologie,
   top attaquants).

## 4. Règles de détection implémentées

| Règle | Logique | Sévérité |
|---|---|---|
| Port scan | ≥ 20 ports distincts contactés par une IP en 10s | HIGH |
| ICMP flood | ≥ 50 paquets ICMP d'une même IP en 5s | MEDIUM |
| Brute-force login | ≥ 8 tentatives POST /login d'une même IP en 15s | HIGH |
| Signature SQLi | Pattern `' OR '1'='1`, `UNION SELECT`, etc. | CRITICAL |
| Signature XSS | Pattern `<script>`, `onerror=`, `javascript:` | CRITICAL |
| Signature Path Traversal | Pattern `../../`, `etc/passwd` | CRITICAL |
| Signature Webshell Upload | Upload de fichier `.php`/`.jsp`/`.asp` | CRITICAL |
| IP blacklistée | Correspondance avec une liste noire (threat intel statique) | CRITICAL |

## 5. Résultats obtenus

Sur un jeu de trafic simulé de 649 paquets (dont 4 scénarios d'attaque injectés), le moteur a
détecté **25 alertes** correctement réparties :

| Type d'alerte | Occurrences |
|---|---|
| PORT_SCAN | 7 |
| ICMP_FLOOD | 6 |
| BLACKLISTED_IP | 4 |
| BRUTEFORCE_LOGIN | 3 |
| SIGNATURE_SQL_INJECTION | 2 |
| SIGNATURE_XSS | 1 |
| SIGNATURE_PATH_TRAVERSAL | 1 |
| SIGNATURE_WEBSHELL_UPLOAD | 1 |

**Aucun faux positif** n'a été généré sur le trafic normal (navigation web, requêtes DNS), grâce
aux seuils calibrés et à l'utilisation d'un cooldown pour les IP blacklistées (évite le spam
d'alertes redondantes).

Les visualisations générées (`dashboard_output/`) montrent clairement :
- la répartition des alertes par type et par sévérité,
- la chronologie précise des 4 vagues d'attaque,
- l'IP `45.83.12.7` comme principale source d'activité malveillante.

## 6. Mécanisme de réponse

Dans cette démo, la "réponse" consiste en la génération d'alertes structurées (JSON/CSV),
exploitables par un SOC (Security Operations Center) ou une automatisation (SOAR). Dans une
implémentation Snort/Suricata en production (voir `snort_setup/`), une réponse active peut être
ajoutée via :
- `iptables`/`nftables` (blocage automatique de l'IP source après une alerte critique),
- l'intégration avec un pare-feu ou un WAF,
- l'envoi d'alertes vers Slack/e-mail/SIEM pour une intervention humaine.

## 7. Comment reproduire

```bash
cd ids_demo
pip install -r requirements.txt
python3 traffic_generator.py   # génère le trafic simulé
python3 ids_engine.py          # détecte et génère les alertes
python3 dashboard.py           # génère les graphiques
```

Pour un déploiement réel, suivre `snort_setup/SNORT_INSTALLATION_GUIDE.md`.

## 8. Limites et améliorations possibles

- La démo traite un journal statique plutôt qu'un flux live (limitation liée à l'environnement de
  développement sans accès réseau bas niveau) — en production, `scapy.sniff()` ou Snort/Suricata
  directement sur l'interface réseau permettent une détection temps réel.
- Les règles sont volontairement simples (seuils fixes) ; une version avancée pourrait intégrer
  de la détection par anomalie statistique (machine learning) en complément du signature-based.
- La liste noire d'IP est statique ; elle pourrait être enrichie via un flux de threat intelligence
  (ex. AbuseIPDB, AlienVault OTX).
