from scapy.all import *
def analyse_paquet(paquet):
    if IP in paquet:
        print(f"\n--- [ NOUVEAU PAQUET IP ] ---")
        print(f"Source : {paquet[IP].src}")
        print(f"Destination : {paquet[IP].dst}")
        
        if TCP in paquet:
            print("Protocole : TCP")
            print(f"Port Source : {paquet[TCP].sport}")
            print(f"Port Destination : {paquet[TCP].dport}")
        elif UDP in paquet:
            print("Protocole : UDP")
            print(f"Port Source : {paquet[UDP].sport}")
            print(f"Port Destination : {paquet[UDP].dport}")
        elif ICMP in paquet:
            print("Protocole : ICMP (Ping)")
            
        if Raw in paquet:
            data = paquet[Raw].load
            try:
                texte = data.decode('utf-8', errors='ignore')
                print(f"Données (Texte) : {texte}")
            except:
                hex_data = data.hex()
                print(f"Données (Hex) : {hex_data}")
if __name__ == "__main__":
    print("[+] Démarrage du sniffer réseau")
    sniff(prn=analyse_paquet, store=False, count=10)