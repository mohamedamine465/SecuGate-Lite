from src.contrat import Signal, Verdict

def est_deja_vu(sig: Signal, vus: set) -> bool:
    # On crée la clé avec le tuple exact demandé dans le tableau
    cle = (sig.timestamp, sig.source, sig.ip, sig.cible, sig.type, sig.message)
    
    if cle in vus:
        return True
    
    vus.add(cle)
    return False

def compter_echecs(sig: Signal, compteur: dict) -> int:
    # Règle : Si le type est LOGIN_ECHEC, on ajoute 1 au compteur de son IP
    if sig.type == "LOGIN_ECHEC":
        compteur[sig.ip] = compteur.get(sig.ip, 0) + 1
        return compteur[sig.ip]
    
    # Règle : Sinon on renvoie sans toucher au compteur
    return compteur.get(sig.ip, 0)

def chercher_procedures(sig: Signal, base: dict) -> list:
    trouvees = []
    message_minuscule = sig.message.lower()
    
    # Parcours de la base pour chercher les mots-clés dans le message
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message_minuscule:
            trouvees.append(procedure)
            
    return trouvees

def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    if sig.type == "LOGIN_ECHEC":
        if nb_echecs >= 5:
            return "CRITIQUE"
        return "MOYENNE"
        
    return sig.gravite

def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    niveau = evaluer(sig, nb_echecs)
    
    # Explication
    procedures = chercher_procedures(sig, base)
    if procedures:
        explication = "\n".join(procedures)
    else:
        explication = "Cause inconnue analyse manuelle requise"
        
    # Action
    if sig.type == "LOGIN_ECHEC" and niveau == "CRITIQUE":
        action = f"Bloquer l'IP {sig.ip}"
    elif sig.type == "FAILLE":
        action = f"Corriger la faille dans {sig.cible}"
    else:
        action = "Surveiller"
        
    # Sensible (vrai si ELEVEE ou CRITIQUE)
    sensible = niveau in ["ELEVEE", "CRITIQUE"]
    
    # Mise à jour du statut du signal
    sig.statut = "ANALYSE"
    
    return Verdict(sig.id, niveau, explication, action, sensible, [sig.source])