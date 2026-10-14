import unittest
from src.collecte import masquer_ip, masquer_parametres

class TestCollecte(unittest.TestCase):
    
    def test_masquer_ip(self):
        # Vérifie le remplacement correct du dernier nombre
        self.assertEqual(masquer_ip("192.168.1.15"), "192.168.1.x")
        
        # Vérifie que l'erreur est bien levée si le format est incorrect
        with self.assertRaises(ValueError):
            masquer_ip("192.168.1")
            
        with self.assertRaises(ValueError):
            masquer_ip("10.0.0.5.8")

    def test_masquer_parametres(self):
        # Vérifie le masquage simple avec arrêt au &
        self.assertEqual(
            masquer_parametres("/api?id=3&token=abc123"), 
            "/api?id=3&token=[MASQUE]"
        )
        
        # Vérifie l'insensibilité à la casse et la gestion des espaces/multiples paramètres
        self.assertEqual(
            masquer_parametres("/login?SESSION=999&user=admin&Password=sec"), 
            "/login?SESSION=[MASQUE]&user=admin&Password=[MASQUE]"
        )

if __name__ == "__main__":
    unittest.main()