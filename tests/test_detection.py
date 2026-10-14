import unittest
from src.contrat import PROCEDURES, Signal
from src.detection import analyser, compter_echecs, est_deja_vu, evaluer

def sig(type_="ACCES", gravite="FAIBLE", message="GET /home -> 200", ip="10.0.0.5"):
    return Signal("SIG-00001", "2026-10-05T10:00:00Z", "ACCES", ip, "web-app", type_, gravite, message)

class TestDetection(unittest.TestCase):
    def test_est_deja_vu(self):
        vus = set()
        # Premier passage : renvoie False car la clé n'est pas dans l'ensemble
        self.assertFalse(est_deja_vu(sig(), vus))
        # Deuxième passage : renvoie True car la clé a été ajoutée
        self.assertTrue(est_deja_vu(sig(), vus))

    def test_compter_echecs(self):
        compteur = {}
        # Test 1 : C'est un LOGIN_ECHEC, ça doit incrémenter
        echec = sig(type_="LOGIN_ECHEC", ip="192.168.1.15")
        self.assertEqual(compter_echecs(echec, compteur), 1)
        self.assertEqual(compter_echecs(echec, compteur), 2)
        
        # Test 2 : Ce n'est pas un LOGIN_ECHEC, on ne touche pas au compteur
        acces = sig(type_="ACCES", ip="10.0.0.5")
        self.assertEqual(compter_echecs(acces, compteur), 0)

if __name__ == "__main__":
    unittest.main()

    def test_chercher_procedures(self):
        # On simule une base avec deux procédures
        base = {"login": "Bloquer IP", "faille": "Corriger système"}
        
        # Test de la recherche (insensible à la casse)
        s1 = sig(message="Une alerte de LoGin suspect")
        self.assertEqual(chercher_procedures(s1, base), ["Bloquer IP"])
        
        s2 = sig(message="Rien à signaler")
        self.assertEqual(chercher_procedures(s2, base), [])

    def test_evaluer(self):
        # Règle : LOGIN_ECHEC avec 5 échecs ou plus -> CRITIQUE, sinon MOYENNE
        e = sig(type_="LOGIN_ECHEC", gravite="FAIBLE")
        self.assertEqual(evaluer(e, 5), "CRITIQUE")
        self.assertEqual(evaluer(e, 4), "MOYENNE")
        
        # Règle : Autre type -> Conserve sa gravité d'origine
        a = sig(type_="ACCES", gravite="ELEVEE")
        self.assertEqual(evaluer(a, 10), "ELEVEE")

    def test_analyser(self):
        base = {"login": "Bloquer IP"}
        s = sig(type_="LOGIN_ECHEC", ip="192.168.1.15", message="Echec login")
        
        # On teste l'analyse complète (avec 5 échecs pour déclencher CRITIQUE)
        v = analyser(s, base, 5)
        
        self.assertEqual(v.niveau, "CRITIQUE")
        self.assertEqual(v.explication, "Bloquer IP")
        self.assertEqual(v.action, "Bloquer l'IP 192.168.1.15")
        self.assertTrue(v.sensible)
        self.assertEqual(s.statut, "ANALYSE") # Le statut du signal doit changer