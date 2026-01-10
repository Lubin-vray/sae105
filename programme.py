import tkinter as tk
from tkinter import filedialog
import csv
import re
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

chemin_fichier = ""
liste_event = []
def detect_sql_injection(line):
    # Patterns SQLi classiques
    patterns = [
        r"' OR 1=1", r"\" OR 1=1",
        r"UNION SELECT", r"UNION ALL SELECT",
        r"information_schema", r"table_schema",
        r"sleep\(", r"benchmark\(",
        r"extractvalue", r"updatexml",
        r"or 'a'='a", r"or 1=1 --",
        r"DROP TABLE", r"INSERT INTO", r"DELETE FROM",
        r"sqlmap", r"python-requests"
    ]

    for p in patterns:
        if re.search(p, line, re.IGNORECASE):
            return True
    return False

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
     # Détection SQL Injection dans le payload
    if detect_sql_injection(line):
        result["SQLi"] = "YES"
    else:
        result["SQLi"] = "NO"


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
        plt.tight_layout()
        plt.savefig("flags_by_src.png")
        plt.close()

           # 3. Évolution des Flags S dans le temps pour la Source IP la plus active (diagramme bâton)
    syn_by_src = Counter(
        ev.get("Source IP") for ev in liste_event
        if ev.get("Flags") and "S" in ev["Flags"] and ev.get("Source IP")
    )

    if syn_by_src:
        top_src_ip, _ = syn_by_src.most_common(1)[0]

        syn_time_top_src = Counter(
            ev.get("Timestamp") for ev in liste_event
            if ev.get("Flags") and "S" in ev["Flags"]
            and ev.get("Source IP") == top_src_ip
            and ev.get("Timestamp")
        )

        if syn_time_top_src:
            times = sorted(syn_time_top_src.keys())
            counts = [syn_time_top_src[t] for t in times]

            plt.figure(figsize=(8, 5))
            plt.bar(times, counts, color="green")
            plt.title(f"Évolution des SYN dans le temps pour {top_src_ip}")
            plt.xlabel("Timestamp")
            plt.ylabel("Nombre de SYN")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig("flags_time_top_src.png")
            plt.close()
        # Camembert : répartition des paquets SYN par port de destination
    # pour l'adresse source qui en envoie le plus

    # 1) Source IP avec le plus de SYN
    syn_by_src = Counter(
        ev.get("Source IP") for ev in liste_event
        if ev.get("Flags") and "S" in ev["Flags"] and ev.get("Source IP")
    )

    if syn_by_src:
        top_src_ip, _ = syn_by_src.most_common(1)[0]

        # 2) Nombre de SYN par port de destination pour cette IP
        syn_by_dport = Counter(
            ev.get("Destination Port") for ev in liste_event
            if ev.get("Flags") and "S" in ev["Flags"]
            and ev.get("Source IP") == top_src_ip
            and ev.get("Destination Port")
        )

        if syn_by_dport:
            labels = list(syn_by_dport.keys())
            sizes = list(syn_by_dport.values())

            plt.figure(figsize=(7, 7))
            plt.pie(
                sizes,
                labels=labels,
                autopct='%1.1f%%',
                startangle=90
            )
            plt.title(f"Part des paquets SYN par port pour {top_src_ip}")
            plt.tight_layout()
            plt.savefig("syn_ports_top_src.png")
            plt.close()


    # ============================
    # 7. Détection DDoS TCP (SYN / ACK / RST)
    # ============================
    syn_by_dst = Counter(ev.get("Destination IP") for ev in liste_event if ev.get("Flags") and "S" in ev["Flags"])
    ack_by_dst = Counter(ev.get("Destination IP") for ev in liste_event if ev.get("Flags") == ".")
    rst_by_dst = Counter(ev.get("Destination IP") for ev in liste_event if ev.get("Flags") and "R" in ev["Flags"])

    top_ddos = syn_by_dst.most_common(5)
    if top_ddos:
        dst_ips = [ip for ip, _ in top_ddos]
        syn_counts = [syn_by_dst[ip] for ip in dst_ips]
        ack_counts = [ack_by_dst.get(ip, 0) for ip in dst_ips]
        rst_counts = [rst_by_dst.get(ip, 0) for ip in dst_ips]

        x = range(len(dst_ips))
        plt.figure(figsize=(9,5))
        plt.bar(x, syn_counts, width=0.3, label="SYN", color="red")
        plt.bar([i+0.3 for i in x], ack_counts, width=0.3, label="ACK", color="blue")
        plt.bar([i+0.6 for i in x], rst_counts, width=0.3, label="RST", color="purple")
        plt.xticks([i+0.3 for i in x], dst_ips, rotation=45)
        plt.title("Potentiel attaque DDoS TCP (SYN / ACK / RST)")
        plt.xlabel("Destination IP")
        plt.ylabel("Nombre de paquets")
        plt.legend()
        plt.tight_layout()
        plt.savefig("ddos_tcp_dest.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucune donnée"], [0], color="grey")
        plt.title("Potentiel DDoS TCP")
        plt.savefig("ddos_tcp_dest.png")
        plt.close()
        # ============================
    # 7. Détection DDoS TCP (SYN / ACK / RST) - TOP 5 SOURCE IP
    # ============================

    syn_by_src = Counter(
        ev.get("Source IP")
        for ev in liste_event
        if ev.get("Flags") and "S" in ev["Flags"] and ev.get("Source IP")
    )

    ack_by_src = Counter(
        ev.get("Source IP")
        for ev in liste_event
        if ev.get("Flags") == "." and ev.get("Source IP")
    )

    rst_by_src = Counter(
        ev.get("Source IP")
        for ev in liste_event
        if ev.get("Flags") and "R" in ev["Flags"] and ev.get("Source IP")
    )

    # TOP 5 sources qui envoient le plus de SYN
    top5_sources = syn_by_src.most_common(5)

    if top5_sources:
        src_ips = [ip for ip, _ in top5_sources]
        syn_counts = [syn_by_src[ip] for ip in src_ips]
        ack_counts = [ack_by_src.get(ip, 0) for ip in src_ips]
        rst_counts = [rst_by_src.get(ip, 0) for ip in src_ips]

        x = range(len(src_ips))
        plt.figure(figsize=(10,5))

        plt.bar(x, syn_counts, width=0.3, label="SYN", color="red")
        plt.bar([i+0.3 for i in x], ack_counts, width=0.3, label="ACK", color="blue")
        plt.bar([i+0.6 for i in x], rst_counts, width=0.3, label="RST", color="purple")

        plt.xticks([i+0.3 for i in x], src_ips, rotation=45)
        plt.title("Potentiel attaque DDoS TCP – Top 5 Sources (SYN / ACK / RST)")
        plt.xlabel("Source IP")
        plt.ylabel("Nombre de paquets")
        plt.legend()
        plt.tight_layout()
        plt.savefig("ddos_tcp.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucune donnée"], [0], color="grey")
        plt.title("Potentiel attaque DDoS TCP")
        plt.savefig("ddos_tcp.png")
        plt.close()

# ============================
# 8bis. Nombre de ports de destination utilisés par IP source (TOP 10)
# ============================

ports_dest_by_src = defaultdict(set)

for ev in liste_event:
    src = ev.get("Source IP")
    dport = ev.get("Destination Port")
    if src and dport:
        ports_dest_by_src[src].add(dport)

# Nombre de ports de destination DISTINCTS par IP source
ports_count_by_src = {
    src: len(ports)
    for src, ports in ports_dest_by_src.items()
}

# TOP 10 IP sources utilisant le plus de ports de destination
top10_src_ports = sorted(
    ports_count_by_src.items(),
    key=lambda x: x[1],
    reverse=True
)[:10]

if top10_src_ports:
    src_ips, port_counts = zip(*top10_src_ports)

    plt.figure(figsize=(10,5))
    plt.bar(src_ips, port_counts, color="darkorange")
    plt.title("Top 10 IP sources par nombre de ports de destination utilisés")
    plt.xlabel("IP source")
    plt.ylabel("Nombre de ports de destination distincts")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("dst_ports_by_src.png")
    plt.close()
else:
    plt.figure(figsize=(6,5))
    plt.bar(["Aucune donnée"], [0], color="grey")
    plt.title("Aucun port de destination détecté")
    plt.savefig("dst_ports_by_src.png")
    plt.close()



    # ============================
    # 9. Détection SQL Injection
    # ============================
    sqli_count = Counter(ev.get("SQLi", "NO") for ev in liste_event)
    plt.figure(figsize=(6,6))
    plt.pie(sqli_count.values(), labels=sqli_count.keys(), autopct='%1.1f%%')
    plt.title("Potentiel SQL Injection")
    plt.savefig("sqli.png")
    plt.close()

    # ============================
    # 10. Détection Brute-force (RST répétés)
    # ============================
    brute_force_counter = Counter()
    for ev in liste_event:
        if ev.get("Flags") and "R" in ev["Flags"]:
            src = ev.get("Source IP")
            dst = ev.get("Destination IP")
            dport = ev.get("Destination Port")
            if src and dst and dport:
                brute_force_counter[f"{src} -> {dst}:{dport}"] += 1

    if brute_force_counter:
        top_bruteforce = brute_force_counter.most_common(5)
        flows, counts = zip(*top_bruteforce)
        plt.figure(figsize=(10,5))
        plt.bar(flows, counts, color="crimson")
        plt.title("Potentiel Brute-force (RST répétés)")
        plt.xlabel("Flux (Source -> Destination:Port)")
        plt.ylabel("Nombre de RST")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig("bruteforce.png")
        plt.close()
    else:
        plt.figure(figsize=(6,5))
        plt.bar(["Aucun brute-force"], [0], color="grey")
        plt.title("Potentiel Brute-force")
        plt.savefig("bruteforce.png")
        plt.close()
        # Répartition de la longueur des paquets pour la Source IP la plus active (SYN)

    # 1) Source IP avec le plus de paquets SYN
    syn_by_src = Counter(
        ev.get("Source IP") for ev in liste_event
        if ev.get("Flags") and "S" in ev["Flags"] and ev.get("Source IP")
    )

    if syn_by_src:
        top_src_ip, _ = syn_by_src.most_common(1)[0]

        # 2) Récupérer les longueurs des paquets envoyés par cette source (tu peux choisir
        #    soit seulement les SYN, soit tous les paquets ; ici seulement les SYN)
        lengths = [
            int(ev["Length"]) for ev in liste_event
            if ev.get("Source IP") == top_src_ip
            and ev.get("Flags") and "S" in ev["Flags"]
            and ev.get("Length")
        ]

        if lengths:
            plt.figure(figsize=(8, 5))
            plt.hist(lengths, bins=20, edgecolor="black", color="skyblue")
            plt.title(f"Répartition de la longueur des paquets SYN pour {top_src_ip}")
            plt.xlabel("Longueur du paquet (octets)")
            plt.ylabel("Nombre de paquets")
            plt.tight_layout()
            plt.savefig("lengths_top_src.png")
            plt.close()

    html_content = """
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Analyse Tcpdump</title>
        <link href="https://bootswatch.com/5/journal/bootstrap.min.css" rel="stylesheet">
    </head>

    <body>

    <div class="container my-5">

        <h1 class="text-center mb-5">Analyse Tcpdump</h1>

        

        <div class="text-center my-4">
            <h2>Top 10 Ports Sources</h2>
            <img src="ports.png" class="img-fluid rounded" alt="Top Ports Bar Chart">
        </div>

        <div class="text-center my-4">
            <h2>Flags SYN vs autres</h2>
            <img src="flags.png" class="img-fluid rounded" alt="Flags SYN vs autres">
        </div>
        
        <div class="text-center my-4">
            <h2>Potentiel attaque DDoS TCP (SYN / ACK / RST)</h2>
            <img src="ddos_tcp.png" class="img-fluid rounded" alt="DDoS TCP">
        </div>
        <div class="text-center my-4">
            <h2>Potentiel attaque DDoS TCP (SYN / ACK / RST)</h2>
            <img src="ddos_tcp_dest.png" class="img-fluid rounded" alt="DDoS TCP">
        </div>

        <div class="text-center my-4">
            <h2>Flags SYN par Source IP</h2>
            <img src="flags_by_src.png" class="img-fluid rounded" alt="Flags SYN par Source">
        </div>

        <div class="text-center my-4">
            <h2>Répartition des paquets SYN par port (source la plus active)</h2>
            <img src="syn_ports_top_src.png" class="img-fluid rounded" alt="SYN par port">
        </div>

        <div class="text-center my-4">
            <h2>Évolution des Flags SYN dans le temps</h2>
            <img src="flags_time_top_src.png" class="img-fluid rounded" alt="Flags SYN dans le temps">
        </div>
        
        <div class="text-center my-4">
            <h2>Répartition des longueurs de paquets (source la plus active)</h2>
            <img src="lengths_top_src.png" class="img-fluid rounded" alt="Longueurs paquets source top">
        </div>


        <div class="text-center my-4">
            <h2>Top 10 adresses IP par nombre de ports utilisés</h2>
            <img src="ports_used_by_ip.png" class="img-fluid rounded" alt="Ports utilisés par IP">
        </div>



        <div class="text-center my-4">
            <h2>Potentiel SQL Injection</h2>
            <img src="sqli.png" class="img-fluid rounded" alt="SQL Injection">
        </div>

        <div class="text-center my-4">
            <h2>Potentiel Brute-force</h2>
            <img src="bruteforce.png" class="img-fluid rounded" alt="Brute-force">
        </div>

    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>

    </body>
    </html>
    """

    with open("rapport.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print("Page HTML générée : rapport.html")