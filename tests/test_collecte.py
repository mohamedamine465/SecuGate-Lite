import unittest
from src.collecte import masquer_ip, masquer_parametres, normaliser_acces

LIGNE_ECHEC = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"
LIGNE_SUCCES = "2026-10-05 10:03:00 10.0.0.7 GET /api/users?id=3&token=abc123 200"

class TestCollecte(unittest.TestCase):
    
    def test_masquer_ip(self):
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")

    def test_masquer_parametres(self):
        self.assertEqual(
            masquer_parametres("/api?id=3&token=abc123"), 
            "/api?id=3&token=[MASQUE]"
        )

    def test_normaliser_acces_echec(self):
        # Vérifie le cas d'une erreur 401 sur /login
        sig = normaliser_acces(LIGNE_ECHEC, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")
        self.assertEqual(sig.message, "POST /login -> 401 depuis 192.168.1.x")

    def test_normaliser_acces_succes(self):
        # Vérifie un accès standard (statut 200)
        sig = normaliser_acces(LIGNE_SUCCES, 7)
        self.assertEqual(sig.type, "ACCES")
        self.assertEqual(sig.gravite, "FAIBLE")
        self.assertEqual(sig.message, "GET /api/users?id=3&token=[MASQUE] -> 200 depuis 10.0.0.x")
        
    def test_normaliser_acces_erreur(self):
        # Vérifie la levée de ValueError pour moins de 6 champs
        ligne_invalide = "2026-10-05 10:01:10 192.168.1.15 POST /login" 
        with self.assertRaises(ValueError):
            normaliser_acces(ligne_invalide, 1)

if __name__ == "__main__":
    unittest.main()