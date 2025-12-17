import tkinter as tk
from tkinter import filedialog, ttk
import csv
liste_event = []
event = {}
chemin_fichier = ""
def choisir_fichier():
    global chemin_fichier
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier",
        filetypes=[("Tous fichiers", "*.*"), ("Calendrier ICS", "*.ics"), ("Texte", "*.txt")]
    )
    if chemin_fichier:
        label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
    else:
        label_chemin.config(text="Aucun fichier sélectionné")

def quitter():
    fenetre.destroy()

# UI
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

# ---- Pas de second mainloop ici ----

if not chemin_fichier:
    print("Aucun fichier sélectionné.")
else:
    liste_event = []
    event = {}
    flag_event = 0

    # Ouvre le fichier avec encodage UTF-8
    with open(chemin_fichier, "r", encoding="utf-8", errors="ignore") as fichier:
        flag_envent = 1
        
        for ligne in fichier:   
            ligne = ligne.strip()
            if flag_envent == 1 :  
                if "seq" in ligne:
                    apres_seq = ligne.split("seq", 1)[1]
                    valeur_sec = apres_seq.split(",", 1)[0]
                    event["Séquence"] = valeur_sec
                if "IP" in ligne:
                    avant_port_source = ligne.split(">", 1)[0]
                    valeur_port_source = avant_port_source.split(".", -1)[1]
                    event["Port source"] = valeur_port_source
                    apres_source = ligne.split("IP", 1)[1]
                    valeur_source = apres_source.split(valeur_port_source, 1)[0]
                    event["Source"] = valeur_source
                if "ack" in ligne:
                    apres_ack = ligne.split("ack", 1)[1]
                    valeur_ack = apres_ack.split(",", 1)[0]
                    event["Aquitement"] = valeur_ack
                if "length" in ligne:
                    flag_envent = 0
            if flag_envent == 0 :
                liste_event.append(event)
                event = {}
                flag_envent = 1

print(liste_event)
entetes = list(liste_event[0].keys())  
valeurs = [] 

for ev in liste_event:
    ligne_valeurs = []
    for cle in entetes:
        ligne_valeurs.append(ev.get(cle, "")) 
    valeurs.append(ligne_valeurs)

f = open('monFichier.csv', 'w')
ligneEntete = ";".join(entetes) + "\n"
f.write(ligneEntete)
for valeur in valeurs:
     ligne = ";".join(valeur) + "\n"
     f.write(ligne)

f.close()
