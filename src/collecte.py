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
 raise NotImplementedError
def normaliser_scan(rapport: dict, numero: int) -> Signal:
 raise NotImplementedError
