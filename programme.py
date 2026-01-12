import tkinter as tk
from tkinter import filedialog
import csv
import re
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import markdown



# ============================
# Détection SQL Injection
# ============================


def detect_sql_injection(line):
    patterns = [
        r"' OR 1=1", r"\" OR 1=1",
        r"UNION SELECT", r"UNION ALL SELECT",
        r"information_schema", r"sleep\(", r"benchmark\(",
        r"sqlmap", r"python-requests"
    ]
    return any(re.search(p, line, re.IGNORECASE) for p in patterns)



# ============================
# Parsing d'une ligne tcpdump
# ============================


def parse_tcpdump_line(line: str):
    ev = {}

    # Nettoyage
    line = line.split("0x")[0].strip()
    if not line:
        return None

    # Protocole
    proto_match = re.search(r"\b(IP|ARP|ICMP|DNS|STP)\b", line)
    ev["Protocol"] = proto_match.group(1) if proto_match else "Unknown"

    # Timestamp
    ev["Timestamp"] = line[:8]

    # IP / Ports
    if ev["Protocol"] == "IP":
        m = re.search(r"\s(\S+)\s>\s(\S+):", line)
        if not m:
            return None

        src, dst = m.groups()

        ev["Source IP"], ev["Source Port"] = src.rsplit(".", 1) if "." in src else (src, "")
        ev["Destination IP"], ev["Destination Port"] = dst.rsplit(".", 1) if "." in dst else (dst, "")
    else:
        ev["Source IP"] = ev["Source Port"] = ""
        ev["Destination IP"] = ev["Destination Port"] = ""

    # Flags TCP (TOUS les types entre crochets)
    flags_match = re.search(r"Flags\s*\[([^\]]+)\]", line)
    ev["Flags"] = flags_match.group(1) if flags_match else ""

    # Longueur paquet
    length_match = re.search(r"length\s(\d+)", line)
    ev["Length"] = int(length_match.group(1)) if length_match else None

    # SQLi
    ev["SQLi"] = "YES" if detect_sql_injection(line) else "NO"

    return ev



# ============================
# Interface graphique
# ============================


def choisir_fichier():
    global chemin_fichier
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier tcpdump",
        filetypes=[("Texte", "*.txt"), ("Tous fichiers", "*.*")]
    )
    label.config(text=chemin_fichier if chemin_fichier else "Aucun fichier sélectionné")


fenetre = tk.Tk()
fenetre.title("Analyse Tcpdump")
fenetre.geometry("400x200")

tk.Button(fenetre, text="Choisir un fichier", command=choisir_fichier).pack(pady=20)
label = tk.Label(fenetre, text="Aucun fichier sélectionné")
label.pack()
tk.Button(fenetre, text="Valider", command=fenetre.destroy).pack(pady=20)

chemin_fichier = ""
fenetre.mainloop()

if not chemin_fichier:
    exit()



# ============================
# Chargement des données
# ============================


events = []
with open(chemin_fichier, encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.strip() and not line.lstrip().startswith("0x"):
            ev = parse_tcpdump_line(line)
            if ev:
                events.append(ev)

if not events:
    print("Aucune donnée exploitable")
    exit()



# ============================
# Export CSV
# ============================


with open("analyse_tcpdump.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=events[0].keys(), delimiter=";")
    writer.writeheader()
    writer.writerows(events)



# ============================
# OUTILS GRAPHIQUES
# ============================


def save_pie(data, title, filename):
    if not data:
        return False
    plt.figure(figsize=(6, 6))
    plt.pie(data.values(), labels=data.keys(), autopct="%1.1f%%")
    plt.title(title)
    plt.savefig(filename)
    plt.close()
    return True


def save_bar(labels, values, title, filename):
    if not labels or not values:
        return False
    plt.figure(figsize=(9, 5))
    plt.bar(labels, values)
    plt.title(title)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    return True



# ============================
# ANALYSES
# ============================


protocols = Counter(ev["Protocol"] for ev in events)
flags = Counter(ev["Flags"] for ev in events if ev["Flags"])
sqli = Counter(ev["SQLi"] for ev in events)

syn_s = Counter(ev["Source IP"] for ev in events if "S" in ev["Flags"])
ack_s = Counter(ev["Source IP"] for ev in events if "." in ev["Flags"])
rst_s = Counter(ev["Source IP"] for ev in events if "R" in ev["Flags"])

ports_by_src = defaultdict(set)
for ev in events:
    if ev["Source IP"] and ev["Destination Port"]:
        ports_by_src[ev["Source IP"]].add(ev["Destination Port"])



# ============================
# GÉNÉRATION DES GRAPHIQUES
# ============================


md_sections = {}

md_sections["protocols"] = (
    "![Protocoles](protocols.png)"
    if save_pie(protocols, "Répartition des protocoles", "protocols.png")
    else "*Aucune donnée disponible*"
)

md_sections["flags"] = (
    "![Flags](flags.png)"
    if save_pie(flags, "Répartition des flags TCP", "flags.png")
    else "*Aucune donnée disponible*"
)

top_syn = syn_s.most_common(5)
if top_syn:
    ips = [ip for ip, _ in top_syn]
    syn_vals = [syn_s[ip] for ip in ips]
    ack_vals = [ack_s.get(ip, 0) for ip in ips]
    rst_vals = [rst_s.get(ip, 0) for ip in ips]

    plt.figure(figsize=(10, 5))
    x = range(len(ips))
    plt.bar(x, syn_vals, width=0.3, label="SYN")
    plt.bar([i+0.3 for i in x], ack_vals, width=0.3, label="ACK")
    plt.bar([i+0.6 for i in x], rst_vals, width=0.3, label="RST")
    plt.xticks([i+0.3 for i in x], ips, rotation=45)
    plt.title("DDoS TCP – Sources")
    plt.legend()
    plt.tight_layout()
    plt.savefig("ddos.png")
    plt.close()
    md_sections["ddos"] = "![DDoS](ddos.png)"
else:
    md_sections["ddos"] = "*Aucune donnée disponible*"


ports_sorted = sorted(
    ((ip, len(p)) for ip, p in ports_by_src.items()),
    key=lambda x: x[1],
    reverse=True
)[:10]

md_sections["ports"] = (
    "![Ports](ports.png)"
    if save_bar(
        [ip for ip, _ in ports_sorted],
        [c for _, c in ports_sorted],
        "Ports destination distincts",
        "ports.png"
    )
    else "*Aucune donnée disponible*"
)

md_sections["sqli"] = (
    "![SQLi](sqli.png)"
    if save_pie(sqli, "Potentiel SQL Injection", "sqli.png")
    else "*Aucune donnée disponible*"
)

# ===== Nouveau : graphique brute-force (RST par IP source) =====

top_rst = rst_s.most_common(10)
md_sections["bruteforce"] = (
    "![Brute-force](bruteforce.png)"
    if save_bar(
        [ip for ip, _ in top_rst],
        [c for _, c in top_rst],
        "Potentiel brute-force (RST par IP source)",
        "bruteforce.png"
    )
    else "*Aucune donnée disponible*"
)



# ============================
# RAPPORT MARKDOWN / HTML
# ============================


md = f"""
# Analyse Tcpdump


## Répartition des protocoles
{md_sections["protocols"]}


## Répartition des flags TCP
{md_sections["flags"]}


## DDoS TCP – Sources
{md_sections["ddos"]}


## Ports destination distincts par IP source
{md_sections["ports"]}


## Potentiel SQL Injection
{md_sections["sqli"]}


## Potentiel brute-force (RST par IP source)
{md_sections["bruteforce"]}
"""

with open("rapport.md", "w", encoding="utf-8") as f:
    f.write(md)

html = f"""
<html>
<head>
<meta charset="UTF-8">
<title>Analyse Tcpdump</title>
<link href="https://bootswatch.com/5/journal/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container my-5">
{markdown.markdown(md)}
</div>
</body>
</html>
"""

with open("rapport.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Analyse terminée : CSV, graphiques valides et rapport générés")
