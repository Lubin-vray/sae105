import tkinter as tk
from tkinter import filedialog
import csv
import re
import matplotlib.pyplot as plt
from collections import Counter, defaultdict

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
# Parsing tcpdump
# ============================

def parse_tcpdump_line(line):
    line = line.split("0x")[0].strip()
    ev = {}

    ev["Timestamp"] = line[:8]

    proto = re.search(r"\s(IP|ARP|ICMP|DNS)\s", line)
    ev["Protocol"] = proto.group(1) if proto else "Unknown"

    m = re.search(r"\s(\S+)\s>\s(\S+):", line)
    if not m:
        return None

    src, dst = m.groups()
    if "." in src:
        ev["Source IP"], ev["Source Port"] = src.rsplit(".", 1)
    if "." in dst:
        ev["Destination IP"], ev["Destination Port"] = dst.rsplit(".", 1)

    flags = re.search(r"Flags\s\[(.*?)\]", line)
    ev["Flags"] = flags.group(1) if flags else ""

    length = re.search(r"length\s(\d+)", line)
    ev["Length"] = int(length.group(1)) if length else None

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
# Chargement
# ============================

events = []
with open(chemin_fichier, encoding="utf-8", errors="ignore") as f:
    for line in f:
        if line.strip() and not line.startswith("0x"):
            ev = parse_tcpdump_line(line)
            if ev:
                events.append(ev)

if not events:
    exit()

# ============================
# Export CSV
# ============================

with open("analyse_tcpdump.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=events[0].keys(), delimiter=";")
    writer.writeheader()
    writer.writerows(events)

# ============================
# GRAPHIQUES
# ============================

# 1. Répartition des Protocoles
protocols = Counter(ev["Protocol"] for ev in events)
plt.figure(figsize=(6,6))
plt.pie(protocols.values(), labels=protocols.keys(), autopct="%1.1f%%")
plt.title("Répartition des Protocoles")
plt.savefig("protocols.png")
plt.close()

# 2. Répartition des Flags TCP (<5% = Autres)
flags = Counter(ev["Flags"] for ev in events if ev["Flags"])
total = sum(flags.values())
filtered, others = {}, 0

for flag, count in flags.items():
    if count / total < 0.05:
        others += count
    else:
        filtered[flag] = count
if others:
    filtered["Autres"] = others

plt.figure(figsize=(6,6))
plt.pie(filtered.values(), labels=filtered.keys(), autopct="%1.1f%%")
plt.title("Répartition des Flags TCP")
plt.savefig("flags.png")
plt.close()


# 4. DDoS TCP – Sources
syn_s = Counter(ev["Source IP"] for ev in events if "S" in ev["Flags"])
ack_s = Counter(ev["Source IP"] for ev in events if ev["Flags"] == ".")
rst_s = Counter(ev["Source IP"] for ev in events if "R" in ev["Flags"])

top_src_ddos = syn_s.most_common(5)
if top_src_ddos:
    ips = [ip for ip, _ in top_src_ddos]
    x = range(len(ips))

    plt.figure(figsize=(9,5))
    plt.bar(x, [syn_s[ip] for ip in ips], width=0.3, label="SYN")
    plt.bar([i+0.3 for i in x], [ack_s.get(ip,0) for ip in ips], width=0.3, label="ACK")
    plt.bar([i+0.6 for i in x], [rst_s.get(ip,0) for ip in ips], width=0.3, label="RST")
    plt.xticks([i+0.3 for i in x], ips, rotation=45)
    plt.title("DDoS TCP – Sources")
    plt.legend()
    plt.tight_layout()
    plt.savefig("ddos_src.png")
    plt.close()

# 5. Longueurs paquets – source SYN la plus active
top_syn_src = syn_s.most_common(1)[0][0]
lengths = [
    ev.get("Length") for ev in events
    if ev.get("Source IP") == top_syn_src
    and "S" in ev.get("Flags", "")
    and ev.get("Length") is not None
]


if lengths:
    plt.figure(figsize=(8,5))
    plt.hist(lengths, bins=20, edgecolor="black")
    plt.title(f"Longueur des paquets SYN – {top_syn_src}")
    plt.xlabel("Octets")
    plt.ylabel("Paquets")
    plt.tight_layout()
    plt.savefig("lengths.png")
    plt.close()

# 6. Ports destination distincts par IP source
ports_by_src = defaultdict(set)
for ev in events:
    if ev.get("Source IP") and ev.get("Destination Port"):
        ports_by_src[ev["Source IP"]].add(ev["Destination Port"])

top_ports = sorted(
    ((ip, len(p)) for ip, p in ports_by_src.items()),
    key=lambda x: x[1],
    reverse=True
)[:10]

if top_ports:
    ips, counts = zip(*top_ports)
    plt.figure(figsize=(10,5))
    plt.bar(ips, counts)
    plt.title("Ports destination distincts par IP source")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("ports_scan.png")
    plt.close()

# 7. SQL Injection
sqli = Counter(ev["SQLi"] for ev in events)
plt.figure(figsize=(6,6))
plt.pie(sqli.values(), labels=sqli.keys(), autopct="%1.1f%%")
plt.title("Potentiel SQL Injection")
plt.savefig("sqli.png")
plt.close()

# 8. Brute-force (RST)
rst_flows = Counter(
    f'{ev["Source IP"]}->{ev["Destination IP"]}:{ev["Destination Port"]}'
    for ev in events if "R" in ev["Flags"]
)

top_bf = rst_flows.most_common(5)
if top_bf:
    flows, counts = zip(*top_bf)
    plt.figure(figsize=(10,5))
    plt.bar(flows, counts)
    plt.title("Potentiel Brute-force (RST)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("bruteforce.png")
    plt.close()

# ============================
# HTML
# ============================

html = """
<html>
<head>
<meta charset="UTF-8">
<title>Analyse Tcpdump</title>
<link href="https://bootswatch.com/5/journal/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container my-5">

<h1 class="text-center mb-5">Analyse Tcpdump</h1>

<img src="protocols.png" class="img-fluid my-4">
<img src="flags.png" class="img-fluid my-4">
<img src="ddos_src.png" class="img-fluid my-4">
<img src="lengths.png" class="img-fluid my-4">
<img src="ports_scan.png" class="img-fluid my-4">
<img src="sqli.png" class="img-fluid my-4">
<img src="bruteforce.png" class="img-fluid my-4">

</div>
</body>
</html>
"""

with open("rapport.html", "w", encoding="utf-8") as f:
    f.write(html)

print("Analyse terminée : CSV, graphiques et rapport.html générés")
