import unittest
from src.collecte import masquer_ip, masquer_parametres, normaliser_acces, normaliser_scan

LIGNE_ECHEC = "2026-10-05 10:01:10 192.168.1.15 POST /login 401"
LIGNE_SUCCES = "2026-10-05 10:03:00 10.0.0.7 GET /api/users?id=3&token=abc123 200"
RAPPORT = {
    "rule": "S3649", 
    "component": "backend", 
    "severity": "blocker",
    "message": "injection SQL possible", 
    "date": "2026-10-05T10:05:00Z"
}

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
        sig = normaliser_acces(LIGNE_ECHEC, 42)
        self.assertEqual(sig.id, "SIG-00042")
        self.assertEqual(sig.timestamp, "2026-10-05T10:01:10Z")
        self.assertEqual(sig.type, "LOGIN_ECHEC")
        self.assertEqual(sig.gravite, "MOYENNE")

    def test_normaliser_acces_succes(self):
        sig = normaliser_acces(LIGNE_SUCCES, 7)
        self.assertEqual(sig.type, "ACCES")
        self.assertEqual(sig.gravite, "FAIBLE")
        
    def test_normaliser_acces_erreur(self):
        ligne_invalide = "2026-10-05 10:01:10 192.168.1.15 POST /login" 
        with self.assertRaises(ValueError):
            normaliser_acces(ligne_invalide, 1)

    def test_normaliser_scan(self):
        # Vérifie le mapping correct d'un rapport complet
        sig = normaliser_scan(RAPPORT, 1)
        self.assertEqual(sig.id, "SIG-00001")
        self.assertEqual(sig.type, "FAILLE")
        self.assertEqual(sig.gravite, "CRITIQUE")
        self.assertEqual(sig.cible, "backend")
        self.assertEqual(sig.message, "Faille S3649 injection SQL possible")

    def test_normaliser_scan_erreur(self):
        # Vérifie la levée d'erreur s'il manque une clé (ex: 'date')
        rapport_incomplet = {
            "rule": "S3649", 
            "component": "backend", 
            "severity": "blocker",
            "message": "injection SQL possible"
        }
        with self.assertRaises(ValueError):
            normaliser_scan(rapport_incomplet, 1)

if __name__ == "__main__":
    unittest.main()