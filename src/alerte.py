from src.contrat import Alerte, Signal, Verdict

def choisir_canal(niveau: str) -> str:
    canaux = {
        "CRITIQUE": "TELEPHONE",
        "ELEVEE": "SLACK",
        "MOYENNE": "EMAIL",
        "FAIBLE": "TABLEAU"
    }
    if niveau not in canaux:
        raise ValueError(f"Niveau inconnu : {niveau}")
    return canaux[niveau]

def rediger(sig: Signal, verdict: Verdict) -> str:
    sources_jointes = ", ".join(verdict.sources)
    return f"[{verdict.niveau}] Cible: {sig.cible}\n" \
           f"Signal: {sig.message}\n" \
           f"Explication: {verdict.explication}\n" \
           f"Action proposee: {verdict.action}\n" \
           f"Sources: {sources_jointes}"

def alerter(sig: Signal, verdict: Verdict, journal: list) -> Alerte:
    canal = choisir_canal(verdict.niveau)
    texte = rediger(sig, verdict)
    
    # Création de l'Alerte
    nouvelle_alerte = Alerte(
        signal_id=sig.id,
        canal=canal,
        destinataire="equipe-secu",
        texte=texte
    )
    
    # Historisation et mise à jour du statut
    journal.append(nouvelle_alerte)
    sig.statut = "ALERTE"
    
    return nouvelle_alerte

def valider_action(verdict: Verdict, reponse: str) -> bool:
    if not verdict.sensible:
        return True
        
    # Nettoyage de la réponse (sans espaces, en minuscules)
    rep_nettoyee = reponse.strip().lower()
    
    return rep_nettoyee in ["o", "oui", "ok", "yes"]