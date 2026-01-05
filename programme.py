import tkinter as tk
from tkinter import filedialog
import csv
import re
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

chemin_fichier = ""
liste_event = []

def parse_tcpdump_line(line):
    result = {}
    line = line.split("0x")[0].strip()

    # Timestamp (8 premiers caractères)
    ts_match = line[:8]
    if ts_match:
        result["Timestamp"] = ts_match

    # Protocole
    proto_match = re.search(r"\s(DNS|IP|ARP|ICMP)\s", line)
    if proto_match:
        result["Protocol"] = proto_match.group(1)

    # Source et destination
    src_dst_match = re.search(r"\s(\S+)\s>\s(\S+):", line)
    if src_dst_match:
        src = src_dst_match.group(1)
        dst = src_dst_match.group(2)
        if "." in src:
            ip_src, port_src = src.rsplit(".", 1)
            result["Source IP"] = ip_src
            result["Source Port"] = port_src
        else:
            result["Source"] = src
        if "." in dst:
            ip_dst, port_dst = dst.rsplit(".", 1)
            result["Destination IP"] = ip_dst
            result["Destination Port"] = port_dst
        else:
            result["Destination"] = dst

    # Flags
    flags_match = re.search(r"Flags\s\[(.*?)\]", line)
    if flags_match:
        result["Flags"] = flags_match.group(1)

    # Longueur
    length_match = re.search(r"length\s(\d+)", line)
    if length_match:
        result["Length"] = length_match.group(1)
    
    # Numéro de séquence
    seq_match = re.search(r"seq\s(\d+)", line)
    if seq_match:
        result["Seq"] = int(seq_match.group(1))

    # Numéro d'acquittement
    ack_match = re.search(r"ack\s(\d+)", line)
    if ack_match:
        result["Ack"] = int(ack_match.group(1))

    return result


# --- UI ---
def choisir_fichier():
    global chemin_fichier
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier",
        filetypes=[("Texte", "*.txt"), ("Tous fichiers", "*.*")]
    )
    if chemin_fichier:
        label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
    else:
        label_chemin.config(text="Aucun fichier sélectionné")

def quitter():
    fenetre.destroy()

fenetre = tk.Tk()
fenetre.title("Sélectionner un fichier")
fenetre.geometry("400x200")

btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier", command=choisir_fichier)
btn_choisir_fichier.pack(pady=20)

label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné")
label_chemin.pack(pady=20)

btn_quitter = tk.Button(fenetre, text="Validé", command=quitter)
btn_quitter.pack(pady=20)

fenetre.mainloop()


# --- Traitement du fichier ---
if not chemin_fichier:
    print("Aucun fichier sélectionné.")
else:
    liste_event = []
    with open(chemin_fichier, "r", encoding="utf-8", errors="ignore") as fichier:
        for ligne in fichier:
            ligne = ligne.strip()
            if ligne.startswith("0x"):
                continue
            if ligne:
                event = parse_tcpdump_line(ligne)
                if event:
                    liste_event.append(event)
    # --- Détection d'incohérences TCP ---
    flux_state = {}  # (src, dst, sport, dport) -> dernier seq/ack

    # --- Export CSV ---
    if liste_event:
        entetes = list(liste_event[0].keys())
        with open("monFichier.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(entetes)
            for ev in liste_event:
                writer.writerow([ev.get(cle, "") for cle in entetes])

        print("Export terminé : monFichier.csv")
    else:
        print("Aucun en-tête trouvé dans le fichier.")


# --- Création des graphiques ---
if liste_event:
    # 1. Flags : proportion SYN vs autres (avec regroupement < 5%)
    flags = [ev.get("Flags", "Unknown") for ev in liste_event if ev.get("Flags")]

    # Compter les occurrences
    flag_counts = Counter(flags)
    total = sum(flag_counts.values())

    # Regrouper les flags < 5% dans "Autres"
    aggregated = {}
    others_count = 0
    for flag, count in flag_counts.items():
        proportion = (count / total) * 100
        if proportion < 5:
            others_count += count
        else:
            aggregated[flag] = count

    if others_count > 0:
        aggregated["Autres"] = others_count

    # Création du camembert
    plt.figure(figsize=(7,7))
    plt.pie(
        aggregated.values(),
        labels=aggregated.keys(),
        autopct='%1.1f%%',
        startangle=90,
        colors=plt.cm.tab20.colors  # palette sympa
    )
    plt.title("Répartition des Flags TCP (SYN et autres)")
    plt.savefig("flags.png")
    plt.close()

    # 2. Flags S par Source IP (top 5)
    syn_by_src = Counter(ev.get("Source IP") for ev in liste_event if ev.get("Flags") and "S" in ev["Flags"])
    if syn_by_src:
        top5_src = syn_by_src.most_common(5)  # top 5
        ips, counts = zip(*top5_src)
        plt.figure(figsize=(8,5))
        plt.bar(ips, counts, color="blue")
        plt.title("Top 5 Sources IP en SYN")
        plt.xlabel("Source IP")
        plt.ylabel("Nombre de SYN")
        plt.xticks(rotation=45)
        plt.savefig("flags_by_src.png")
        plt.close()

    # 3. Flags S en fonction du temps (top 5)
    syn_by_time = Counter(ev.get("Timestamp") for ev in liste_event if ev.get("Flags") and "S" in ev["Flags"])
    if syn_by_time:
        top5_time = syn_by_time.most_common(5)  # top 5
        times, counts = zip(*top5_time)
        plt.figure(figsize=(8,5))
        plt.bar(times, counts, color="green")
        plt.title("Top 5 pics d'activité SYN")
        plt.xlabel("Timestamp")
        plt.ylabel("Nombre de SYN")
        plt.xticks(rotation=45)
        plt.savefig("flags_time.png")
        plt.close()

       # 4. Top 5 Sources IP en requêtes DNS
    dns_sources = Counter(ev.get("Source IP") for ev in liste_event if ev.get("Protocol") == "DNS")
    if dns_sources:
        top5_dns = dns_sources.most_common(5)
        ips, counts = zip(*top5_dns)
        plt.figure(figsize=(8,5))
        plt.bar(ips, counts, color="purple")
        plt.title("Top 5 Sources IP en requêtes DNS")
        plt.xlabel("Source IP")
        plt.ylabel("Nombre de requêtes DNS")
        plt.xticks(rotation=45)
        plt.savefig("dns_attack.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucun DNS"], [0], color="grey")
        plt.title("Top 5 Sources IP en requêtes DNS")
        plt.savefig("dns_attack.png")
        plt.close()

    # 5. Histogramme des longueurs DNS
    dns_lengths = [int(ev.get("Length", 0)) for ev in liste_event if ev.get("Protocol") == "DNS" and ev.get("Length")]
    if dns_lengths:
        plt.figure(figsize=(8,5))
        plt.hist(dns_lengths, bins=20, color="orange", edgecolor="black")
        plt.title("Distribution des longueurs de paquets DNS")
        plt.xlabel("Longueur")
        plt.ylabel("Nombre de paquets DNS")
        plt.savefig("dns_lengths.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucun DNS"], [0], color="grey")
        plt.title("Distribution des longueurs de paquets DNS")
        plt.savefig("dns_lengths.png")
        plt.close()

    # 6. DNS par timestamp (top 5)
    dns_time = Counter(ev.get("Timestamp") for ev in liste_event if ev.get("Protocol") == "DNS")
    if dns_time:
        top5_time = dns_time.most_common(5)
        times, counts = zip(*top5_time)
        plt.figure(figsize=(8,5))
        plt.bar(times, counts, color="cyan")
        plt.title("Top 5 pics d'activité DNS")
        plt.xlabel("Timestamp")
        plt.ylabel("Nombre de requêtes DNS")
        plt.xticks(rotation=45)
        plt.savefig("dns_time.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucun DNS"], [0], color="grey")
        plt.title("Top 5 pics d'activité DNS")
        plt.savefig("dns_time.png")
        plt.close()
    html_content = """
    <html>
    <head><title>Analyse Tcpdump</title></head>
    <body>
        <h1>Analyse Tcpdump</h1>
        <h2>Répartition des Protocoles</h2>
        <img src="protocols.png" alt="Protocol Pie Chart"><br>

        <h2>Distribution des longueurs de paquets</h2>
        <img src="lengths.png" alt="Packet Length Histogram"><br>

        <h2>Top 10 Ports Sources</h2>
        <img src="ports.png" alt="Top Ports Bar Chart"><br>

        <h2>Flags SYN vs autres</h2>
        <img src="flags.png" alt="Flags SYN vs autres"><br>

        <h2>Flags SYN par Source IP</h2>
        <img src="flags_by_src.png" alt="Flags SYN par Source"><br>

        <h2>Évolution des Flags SYN dans le temps</h2>
        <img src="flags_time.png" alt="Flags SYN dans le temps"><br>

        <h2>Top 5 Sources IP en requêtes DNS</h2>
        <img src="dns_attack.png" alt="DNS Sources"><br>

        <h2>Distribution des longueurs de paquets DNS</h2>
        <img src="dns_lengths.png" alt="DNS Lengths"><br>

        <h2>Top 5 pics d'activité DNS</h2>
        <img src="dns_time.png" alt="DNS Time"><br>
    </body>
    </html>
    """

    with open("rapport.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print("Page HTML générée : rapport.html")