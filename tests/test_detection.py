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