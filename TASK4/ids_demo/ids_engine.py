"""
IDS Engine — CodeAlpha Network Intrusion Detection System (Task 4)
=====================================================================
Moteur de détection d'intrusion basé sur signatures (signature-based IDS),
inspiré du fonctionnement de Snort/Suricata mais implémenté en Python pur.

Entrée  : traffic_log.json (généré par traffic_generator.py, ou une vraie
          capture réseau convertie au même format — voir README).
Sortie  : alerts.json + alerts.csv + résumé console

Règles implémentées (voir rules.json) :
  1. Port scan            : trop de ports distincts contactés par une IP en peu de temps
  2. ICMP flood            : trop de paquets ICMP depuis une même IP
  3. Brute-force login     : trop de tentatives POST /login depuis une même IP
  4. Signatures de payload : SQLi, XSS, path traversal, upload de webshell
  5. IP blacklistées       : correspondance avec une liste noire statique

Pour une capture RÉELLE (nécessite root + libpcap) :
    from scapy.all import sniff
    sniff(prn=process_packet, filter="ip", store=False)
Cette fonctionnalité est documentée mais non activée ici (environnement sandboxé
sans accès réseau). La logique de détection reste identique.
"""

import json
import re
import csv
from collections import defaultdict
from datetime import datetime

TRAFFIC_LOG = "traffic_log.json"
RULES_FILE = "rules.json"
ALERTS_JSON = "alerts.json"
ALERTS_CSV = "alerts.csv"


def load_json(path):
    with open(path) as f:
        return json.load(f)


def parse_ts(ts):
    return datetime.fromisoformat(ts)


class IDSEngine:
    def __init__(self, rules):
        self.rules = rules
        self.alerts = []
        # état glissant par IP source
        self.port_scan_state = defaultdict(list)     # ip -> [(ts, port), ...]
        self.icmp_state = defaultdict(list)           # ip -> [ts, ...]
        self.bruteforce_state = defaultdict(list)     # ip -> [ts, ...]
        self.blacklist_last_alert = {}                 # ip -> datetime dernière alerte (cooldown)
        self.signature_regexes = self._compile_signatures()

    def _compile_signatures(self):
        compiled = []
        cfg = self.rules.get("payload_signatures", {})
        if not cfg.get("enabled"):
            return compiled
        for sig in cfg.get("signatures", []):
            flags = re.IGNORECASE if "i" in sig.get("flags", "") else 0
            compiled.append((sig["name"], re.compile(sig["pattern"], flags)))
        return compiled

    def _raise_alert(self, alert_type, severity, src, dst, ts, description, extra=None):
        alert = {
            "timestamp": ts,
            "type": alert_type,
            "severity": severity,
            "src_ip": src,
            "dst_ip": dst,
            "description": description,
        }
        if extra:
            alert.update(extra)
        self.alerts.append(alert)

    def process_packet(self, pkt):
        ts = parse_ts(pkt["timestamp"])
        src, dst = pkt["src_ip"], pkt["dst_ip"]

        # ---- Règle : IP blacklistée (avec cooldown pour éviter une alerte par paquet) ----
        bl = self.rules.get("blacklisted_ips", {})
        if bl.get("enabled") and src in bl.get("ip_list", []):
            last = self.blacklist_last_alert.get(src)
            cooldown = bl.get("cooldown_seconds", 30)
            if last is None or (ts - last).total_seconds() >= cooldown:
                self._raise_alert("BLACKLISTED_IP", bl["severity"], src, dst, pkt["timestamp"],
                                   f"Trafic provenant d'une IP source blacklistée ({src})")
                self.blacklist_last_alert[src] = ts

        # ---- Règle : Port scan ----
        ps = self.rules.get("port_scan", {})
        if ps.get("enabled") and pkt["protocol"] == "TCP" and pkt.get("dst_port"):
            state = self.port_scan_state[src]
            state.append((ts, pkt["dst_port"]))
            window = ps["window_seconds"]
            state[:] = [(t, p) for t, p in state if (ts - t).total_seconds() <= window]
            distinct_ports = {p for _, p in state}
            if len(distinct_ports) >= ps["distinct_ports_threshold"]:
                self._raise_alert("PORT_SCAN", ps["severity"], src, dst, pkt["timestamp"],
                                   f"{len(distinct_ports)} ports distincts contactés par {src} "
                                   f"en moins de {window}s (seuil: {ps['distinct_ports_threshold']})")
                state.clear()  # évite de spammer une alerte par paquet

        # ---- Règle : ICMP flood ----
        icmp = self.rules.get("icmp_flood", {})
        if icmp.get("enabled") and pkt["protocol"] == "ICMP":
            state = self.icmp_state[src]
            state.append(ts)
            window = icmp["window_seconds"]
            state[:] = [t for t in state if (ts - t).total_seconds() <= window]
            if len(state) >= icmp["packet_count_threshold"]:
                self._raise_alert("ICMP_FLOOD", icmp["severity"], src, dst, pkt["timestamp"],
                                   f"{len(state)} paquets ICMP reçus de {src} en moins de {window}s "
                                   f"(seuil: {icmp['packet_count_threshold']})")
                state.clear()

        # ---- Règle : Brute-force login ----
        bf = self.rules.get("bruteforce_login", {})
        payload = pkt.get("payload", "") or ""
        if bf.get("enabled") and pkt.get("dst_port") == bf["target_port"] and "/login" in payload:
            state = self.bruteforce_state[src]
            state.append(ts)
            window = bf["window_seconds"]
            state[:] = [t for t in state if (ts - t).total_seconds() <= window]
            if len(state) >= bf["attempt_threshold"]:
                self._raise_alert("BRUTEFORCE_LOGIN", bf["severity"], src, dst, pkt["timestamp"],
                                   f"{len(state)} tentatives de connexion depuis {src} en moins de "
                                   f"{window}s (seuil: {bf['attempt_threshold']})")
                state.clear()

        # ---- Règle : signatures de payload (SQLi, XSS, traversal, webshell) ----
        if payload:
            for name, regex in self.signature_regexes:
                if regex.search(payload):
                    self._raise_alert(f"SIGNATURE_{name}", self.rules["payload_signatures"]["severity"],
                                       src, dst, pkt["timestamp"],
                                       f"Signature '{name}' détectée dans le payload : {payload[:80]}")

    def run(self, packets):
        for pkt in packets:
            self.process_packet(pkt)
        return self.alerts


def main():
    rules = load_json(RULES_FILE)
    packets = load_json(TRAFFIC_LOG)

    engine = IDSEngine(rules)
    alerts = engine.run(packets)

    with open(ALERTS_JSON, "w") as f:
        json.dump(alerts, f, indent=2)

    if alerts:
        with open(ALERTS_CSV, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["timestamp", "type", "severity", "src_ip", "dst_ip", "description"])
            writer.writeheader()
            for a in alerts:
                writer.writerow({k: a.get(k, "") for k in writer.fieldnames})

    print(f"Analyse terminée : {len(packets)} paquets traités, {len(alerts)} alertes générées.")
    print(f"→ {ALERTS_JSON} et {ALERTS_CSV} écrits.\n")

    by_type = defaultdict(int)
    for a in alerts:
        by_type[a["type"]] += 1
    print("Résumé par type d'alerte :")
    for t, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  - {t}: {count}")


if __name__ == "__main__":
    main()
