import re
from src.contrat import Signal

def masquer_ip(ip: str) -> str:
    parties = ip.split('.')
    if len(parties) != 4:
        raise ValueError("L'adresse IP doit avoir 4 parties séparées par des points.")
    return f"{parties[0]}.{parties[1]}.{parties[2]}.x"

def masquer_parametres(chemin: str) -> str:
    # Remplace les valeurs de token, password, session et key (insensible à la casse)
    return re.sub(
        r'(?i)(token|password|session|key)=[^&\s]+', 
        r'\1=[MASQUE]', 
        chemin
    )

def normaliser_acces(ligne: str, numero: int, cible: str = "web-app") -> Signal:
    champs = ligne.split()
    if len(champs) < 6:
        raise ValueError("La ligne doit contenir au moins 6 champs.")
    
    date, heure, ip, methode, chemin, statut = champs[:6]
    
    # Formatage de l'ID et du timestamp
    sig_id = f"SIG-{numero:05d}"
    timestamp = f"{date}T{heure}Z"
    
    # Détermination du type
    chemin_base = chemin.split('?')[0]
    if chemin_base == "/login" and statut in ["401", "403"]:
        type_sig = "LOGIN_ECHEC"
    else:
        type_sig = "ACCES"
        
    # Détermination de la gravité
    if statut.startswith('5'):
        gravite = "ELEVEE"
    elif statut.startswith('4'):
        gravite = "MOYENNE"
    else:
        gravite = "FAIBLE"
        
    # Formatage du message
    chemin_masque = masquer_parametres(chemin)
    ip_masquee = masquer_ip(ip)
    message = f"{methode} {chemin_masque} -> {statut} depuis {ip_masquee}"
    
    return Signal(
        id=sig_id, timestamp=timestamp, source="ACCES", ip=ip, 
        cible=cible, type=type_sig, gravite=gravite, message=message
    )

def normaliser_scan(rapport: dict, numero: int) -> Signal:
    cles_requises = {"rule", "component", "severity", "message", "date"}
    if not cles_requises.issubset(rapport.keys()):
        raise ValueError("Il manque une ou plusieurs clés dans le rapport de scan.")
        
    sig_id = f"SIG-{numero:05d}"
    
    # Détermination de la gravité
    severite = rapport["severity"].lower()
    if severite == "blocker":
        gravite = "CRITIQUE"
    elif severite == "critical":
        gravite = "ELEVEE"
    elif severite == "major":
        gravite = "MOYENNE"
    elif severite == "minor":
        gravite = "FAIBLE"
    else:
        gravite = "FAIBLE"
        
    message = f"Faille {rapport['rule']} {rapport['message']}"
    
    return Signal(
        id=sig_id, timestamp=rapport["date"], source="SCAN", ip="", 
        cible=rapport["component"], type="FAILLE", gravite=gravite, message=message
    )