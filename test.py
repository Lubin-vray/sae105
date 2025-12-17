import tkinter as tk
from tkinter import filedialog
import csv
import re

chemin_fichier = ""
liste_event = []

def parse_tcpdump_line(line):
    """
    Parse uniquement l'entête tcpdump (avant le dump hexadécimal).
    Retourne un dictionnaire avec les champs extraits.
    """
    result = {}

    # On coupe la ligne avant le premier "0x" (pour ignorer l'hexadécimal)
    line = line.split("0x")[0].strip()

    # Timestamp
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
        # Séparer IP et port
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

    # Séquence
    seq_match = re.search(r"seq\s(\d+:\d+)", line)
    if seq_match:
        result["Seq"] = seq_match.group(1)

    # Ack
    ack_match = re.search(r"ack\s(\d+)", line)
    if ack_match:
        result["Ack"] = ack_match.group(1)

    # Fenêtre
    win_match = re.search(r"win\s(\d+)", line)
    if win_match:
        result["Win"] = win_match.group(1)

    # Options
    options_match = re.search(r"options\s\[(.*?)\]", line)
    if options_match:
        result["Options"] = options_match.group(1)

    # Longueur
    length_match = re.search(r"length\s(\d+)", line)
    if length_match:
        result["Length"] = length_match.group(1)

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
            if ligne.startswith("0x"):  # ignorer les lignes hexadécimales
                continue
            if ligne:
                event = parse_tcpdump_line(ligne)
                if event:
                    liste_event.append(event)

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