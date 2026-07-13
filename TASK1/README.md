# 🔌 TASK 1 : Basic Network Sniffer

## 🎯 Objectif
Développer un programme en Python capable de capturer, décoder et analyser le trafic réseau en temps réel afin de comprendre la structure des protocoles et le flux de données circulant sur une interface réseau[cite: 2].

## 📂 Contenu du dossier
*   `sniffer.py` : Script Python principal de capture et d'analyse des paquets[cite: 2].
*   `README.md` : Documentation de la tâche.

## 🛠️ Technologies & Librairies
*   **Python 3**
*   **Scapy** (ou la bibliothèque native `socket`) pour la capture de paquets à bas niveau[cite: 2].

## 🔍 Fonctionnalités Implémentées
*   Capture des paquets réseau à la volée[cite: 2].
*   Extraction et affichage clair des informations clés :
    *   Adresses IP Sources et Destinations[cite: 2].
    *   Protocoles réseau (TCP, UDP, ICMP, etc.)[cite: 2].
    *   Contenu brut des données (Payloads)[cite: 2].

---

## ▶️ Comment exécuter l'outil

> ⚠️ **Important :** La capture de paquets réseau nécessite des privilèges d'administrateur (`root`/`sudo`) sur votre système Linux.

1. Installez la dépendance requise (Scapy) :
   ```bash
   pip install scapy