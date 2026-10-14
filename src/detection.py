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
    raise NotImplementedError

def evaluer(sig: Signal, nb_echecs: int = 0) -> str:
    raise NotImplementedError

def analyser(sig: Signal, base: dict, nb_echecs: int = 0) -> Verdict:
    raise NotImplementedError