"""
Traffic Generator — CodeAlpha Network IDS (Task 4)
=====================================================
Génère un journal de paquets simulé (traffic_log.json) qui reproduit :
  - du trafic réseau normal (HTTP, DNS, ICMP occasionnel)
  - une attaque de scan de ports (port scan)
  - une attaque ICMP flood
  - une tentative de brute-force sur un service SSH/HTTP
  - des payloads HTTP contenant des signatures d'attaque (SQLi, XSS)

Dans un vrai déploiement, ces paquets proviendraient d'une capture live
(scapy `sniff()`) ou d'un fichier .pcap (scapy `rdpcap()`). Ce générateur
permet de tester le moteur de détection (ids_engine.py) de façon
reproductible, sans nécessiter d'accès réseau ou de privilèges root.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)

OUTPUT_FILE = "traffic_log.json"

NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.15"]
SERVER_IP = "192.168.1.100"
ATTACKER_IP = "45.83.12.7"
BRUTEFORCE_IP = "185.220.101.4"

packets = []
t0 = datetime(2026, 7, 9, 10, 0, 0)


def add_packet(offset_seconds, src, dst, sport, dport, proto, flags="", payload="", length=64):
    packets.append({
        "timestamp": (t0 + timedelta(seconds=offset_seconds)).isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "protocol": proto,   # TCP, UDP, ICMP
        "flags": flags,      # SYN, ACK, SYN-ACK, etc. (TCP only)
        "length": length,
        "payload": payload,
    })


# ---------- 1) Trafic normal (navigation web, DNS) ----------
t = 0
for _ in range(60):
    src = random.choice(NORMAL_IPS)
    t += random.uniform(0.5, 4)
    if random.random() < 0.7:
        add_packet(t, src, SERVER_IP, random.randint(40000, 60000), 80, "TCP", "SYN", length=60)
        add_packet(t + 0.05, SERVER_IP, src, 80, random.randint(40000, 60000), "TCP", "SYN-ACK", length=60)
        add_packet(t + 0.1, src, SERVER_IP, random.randint(40000, 60000), 80, "TCP", "ACK",
                   payload="GET /index.html HTTP/1.1", length=300)
    else:
        add_packet(t, src, "8.8.8.8", random.randint(40000, 60000), 53, "UDP", payload="DNS query", length=64)

# ---------- 2) Attaque : Port scan (un seul attaquant, beaucoup de ports différents, très vite) ----------
scan_start = 200
for i, port in enumerate(range(20, 1040, 7)):  # ~145 ports scannés
    add_packet(scan_start + i * 0.02, ATTACKER_IP, SERVER_IP,
               random.randint(50000, 60000), port, "TCP", "SYN", length=40)

# ---------- 3) Attaque : ICMP flood ----------
flood_start = 260
for i in range(300):
    add_packet(flood_start + i * 0.01, ATTACKER_IP, SERVER_IP, None, None, "ICMP", length=64)

# ---------- 4) Attaque : Brute-force sur formulaire de login HTTP ----------
bf_start = 320
common_passwords = ["123456", "password", "admin123", "letmein", "qwerty", "admin", "root123",
                     "welcome1", "iloveyou", "P@ssw0rd"]
for i, pwd in enumerate(common_passwords * 3):
    add_packet(bf_start + i * 0.3, BRUTEFORCE_IP, SERVER_IP,
               random.randint(50000, 60000), 80, "TCP", "ACK",
               payload=f"POST /login HTTP/1.1 username=admin&password={pwd}", length=180)

# ---------- 5) Attaque : payloads applicatifs malveillants (SQLi / XSS / traversal) ----------
malicious_payloads = [
    "GET /product?id=1' OR '1'='1 HTTP/1.1",
    "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1",
    "GET /users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
    "GET /file?path=../../../../etc/passwd HTTP/1.1",
    "POST /upload HTTP/1.1 filename=shell.php",
]
mp_start = 420
for i, payload in enumerate(malicious_payloads):
    add_packet(mp_start + i * 5, ATTACKER_IP, SERVER_IP,
               random.randint(50000, 60000), 80, "TCP", "ACK", payload=payload, length=220)

# ---------- 6) Un peu plus de trafic normal après les attaques ----------
t = 460
for _ in range(20):
    src = random.choice(NORMAL_IPS)
    t += random.uniform(1, 3)
    add_packet(t, src, SERVER_IP, random.randint(40000, 60000), 80, "TCP", "ACK",
               payload="GET /about.html HTTP/1.1", length=300)

packets.sort(key=lambda p: p["timestamp"])

with open(OUTPUT_FILE, "w") as f:
    json.dump(packets, f, indent=2)

print(f"{len(packets)} paquets générés dans {OUTPUT_FILE}")
print("Contient : trafic normal + port scan + ICMP flood + brute-force + payloads malveillants (SQLi/XSS/traversal)")
