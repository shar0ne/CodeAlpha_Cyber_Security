"""
Dashboard — CodeAlpha Network IDS (Task 4)
=============================================
Génère des visualisations à partir de alerts.json produit par ids_engine.py :
  1. Nombre d'alertes par type
  2. Nombre d'alertes par sévérité
  3. Chronologie des alertes (timeline)
  4. Top des IP sources à l'origine des alertes

Les graphiques sont enregistrés en PNG dans ../dashboard_output/
"""

import json
import os
from collections import Counter
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ALERTS_FILE = "alerts.json"
OUTPUT_DIR = "../dashboard_output"

SEVERITY_COLORS = {
    "CRITICAL": "#B22222",
    "HIGH": "#E67E22",
    "MEDIUM": "#F1C40F",
    "LOW": "#3498DB",
}

os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(ALERTS_FILE) as f:
    alerts = json.load(f)

if not alerts:
    print("Aucune alerte à afficher. Lance d'abord traffic_generator.py puis ids_engine.py.")
    raise SystemExit(0)

# ---------- 1. Alertes par type ----------
type_counts = Counter(a["type"] for a in alerts)
plt.figure(figsize=(9, 5))
types = list(type_counts.keys())
counts = [type_counts[t] for t in types]
bars = plt.barh(types, counts, color="#1B2A4A")
plt.xlabel("Nombre d'alertes")
plt.title("Alertes IDS par type de détection")
for bar, c in zip(bars, counts):
    plt.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, str(c), va="center", fontsize=9)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/alerts_by_type.png", dpi=130)
plt.close()

# ---------- 2. Alertes par sévérité ----------
sev_counts = Counter(a["severity"] for a in alerts)
sev_order = [s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if s in sev_counts]
plt.figure(figsize=(6, 6))
plt.pie(
    [sev_counts[s] for s in sev_order],
    labels=[f"{s} ({sev_counts[s]})" for s in sev_order],
    colors=[SEVERITY_COLORS.get(s, "#888888") for s in sev_order],
    autopct="%1.0f%%",
    startangle=90,
)
plt.title("Répartition des alertes par sévérité")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/alerts_by_severity.png", dpi=130)
plt.close()

# ---------- 3. Chronologie des alertes ----------
timestamps = sorted(datetime.fromisoformat(a["timestamp"]) for a in alerts)
t0 = timestamps[0]
offsets = [(t - t0).total_seconds() for t in timestamps]
plt.figure(figsize=(10, 4))
plt.eventplot(offsets, colors="#C9972C", lineoffsets=1, linelengths=0.8)
plt.xlabel("Secondes depuis le début de la capture")
plt.yticks([])
plt.title("Chronologie des alertes détectées")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/alerts_timeline.png", dpi=130)
plt.close()

# ---------- 4. Top IP sources ----------
ip_counts = Counter(a["src_ip"] for a in alerts)
top_ips = ip_counts.most_common(10)
plt.figure(figsize=(8, 5))
plt.bar([ip for ip, _ in top_ips], [c for _, c in top_ips], color="#8B0000")
plt.ylabel("Nombre d'alertes générées")
plt.title("Top IP sources à l'origine des alertes")
plt.xticks(rotation=30, ha="right")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/top_source_ips.png", dpi=130)
plt.close()

print(f"4 graphiques générés dans {OUTPUT_DIR}/ :")
print("  - alerts_by_type.png")
print("  - alerts_by_severity.png")
print("  - alerts_timeline.png")
print("  - top_source_ips.png")
