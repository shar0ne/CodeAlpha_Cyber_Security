# Guide d'installation et de configuration — Snort & Suricata
**CodeAlpha Cyber Security Internship — Task 4 (Network Intrusion Detection System)**

Ce guide couvre l'installation d'un véritable IDS réseau (Snort ou Suricata) sur une machine
Linux (Ubuntu/Debian), en complément de la démo Python (`ids_demo/`) qui simule le même
comportement sans nécessiter de droits root ni d'accès réseau bas niveau.

---

## Partie 1 — Snort

### 1.1 Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y snort
```

Pendant l'installation, un assistant demande :
- **le réseau local à surveiller** (HOME_NET), ex : `192.168.1.0/24`
- **l'interface réseau** à écouter, ex : `eth0` ou `wlan0` (vérifier avec `ip a`)

Pour reconfigurer plus tard :
```bash
sudo dpkg-reconfigure snort
```

### 1.2 Structure de configuration

| Fichier | Rôle |
|---|---|
| `/etc/snort/snort.conf` | Fichier de configuration principal |
| `/etc/snort/rules/local.rules` | Règles personnalisées (c'est ici qu'on écrit nos détections) |
| `/var/log/snort/` | Journaux et alertes générés |

### 1.3 Écrire des règles personnalisées

Éditer `/etc/snort/rules/local.rules` :

```
# Détection d'un scan de ports (ICMP + tentative de connexion rapprochée)
alert tcp any any -> $HOME_NET any (msg:"Possible Port Scan Detected"; flags:S; \
  threshold: type threshold, track by_src, count 20, seconds 10; sid:1000001; rev:1;)

# Détection d'un flood ICMP (ping flood)
alert icmp any any -> $HOME_NET any (msg:"ICMP Flood Detected"; \
  threshold: type threshold, track by_src, count 50, seconds 5; sid:1000002; rev:1;)

# Détection d'une tentative d'injection SQL dans une requête HTTP
alert tcp any any -> $HOME_NET 80 (msg:"Possible SQL Injection Attempt"; \
  content:"' OR '1'='1"; nocase; sid:1000003; rev:1;)

# Détection d'une tentative de XSS
alert tcp any any -> $HOME_NET 80 (msg:"Possible XSS Attempt"; \
  content:"<script>"; nocase; sid:1000004; rev:1;)

# Détection d'un accès à un fichier sensible via path traversal
alert tcp any any -> $HOME_NET 80 (msg:"Path Traversal Attempt"; \
  content:"../../../../etc/passwd"; nocase; sid:1000005; rev:1;)
```

> Ces 5 règles correspondent exactement aux 4 signatures + à la détection de scan implémentées
> dans `ids_demo/ids_engine.py`, pour montrer l'équivalence entre la démo Python et un vrai
> moteur IDS de production.

Puis inclure ce fichier dans `snort.conf` (généralement déjà fait par défaut) :
```
include $RULE_PATH/local.rules
```

### 1.4 Lancer Snort

Mode test (vérifier que la config est valide) :
```bash
sudo snort -T -c /etc/snort/snort.conf
```

Mode NIDS (détection en direct, avec logs et alertes) :
```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

Les alertes s'affichent en direct dans la console et sont aussi journalisées dans
`/var/log/snort/alert`.

### 1.5 Tester une détection

Depuis une autre machine du réseau, simuler un scan de ports avec `nmap` :
```bash
nmap -sS 192.168.1.100
```
Snort doit générer une alerte "Possible Port Scan Detected" dans `/var/log/snort/alert`.

---

## Partie 2 — Suricata (alternative moderne, plus performante en multi-thread)

### 2.1 Installation

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```

### 2.2 Configuration

Fichier principal : `/etc/suricata/suricata.yaml`
- Définir `HOME_NET` (le réseau à protéger)
- Définir l'interface d'écoute sous `af-packet:`

Règles personnalisées : `/etc/suricata/rules/local.rules` (même syntaxe que Snort, compatible) :
```
alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; \
  threshold: type threshold, track by_src, count 20, seconds 10; sid:2000001; rev:1;)
```

Inclure le fichier dans `suricata.yaml` :
```yaml
rule-files:
  - local.rules
```

### 2.3 Lancer Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

Les alertes sont journalisées au format JSON dans `/var/log/suricata/eve.json`, ce qui les rend
faciles à parser avec un script Python (même logique que `dashboard.py` de la démo) ou à envoyer
vers un outil de visualisation comme **EveBox** ou une stack **ELK (Elasticsearch/Logstash/Kibana)**.

### 2.4 Visualiser les alertes (optionnel)

```bash
# Installer EveBox pour une interface web dédiée aux alertes Suricata
sudo apt install -y evebox
evebox oneshot --input /var/log/suricata/eve.json
```

---

## Partie 3 — Équivalence avec la démo Python (`ids_demo/`)

| Concept Snort/Suricata | Équivalent dans `ids_demo/ids_engine.py` |
|---|---|
| Règle `.rules` (`alert tcp ...`) | Entrée dans `rules.json` |
| `threshold: track by_src, count, seconds` | Fenêtre glissante (`window_seconds`, `threshold`) par IP source |
| `content:"..."` (pattern matching) | Expressions régulières dans `payload_signatures` |
| `/var/log/snort/alert` ou `eve.json` | `alerts.json` / `alerts.csv` |
| Dashboard EveBox / Kibana | `dashboard.py` (graphiques matplotlib) |

Cette démo permet de comprendre et tester la **logique de détection** sans nécessiter de
privilèges root, d'accès réseau bas niveau, ni d'installation de Snort — utile pour le
développement, les tests unitaires, et la démonstration dans un environnement contraint
(ex. sandbox, CI/CD, machine sans droits admin).

---

## Références

- Documentation officielle Snort : https://docs.snort.org/
- Documentation officielle Suricata : https://docs.suricata.io/
- Snort Rules Syntax : https://www.snort.org/documents
