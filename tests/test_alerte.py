import unittest
from src.alerte import alerter, choisir_canal, rediger, valider_action
from src.contrat import Signal, Verdict

def exemple(sensible=True, niveau="CRITIQUE"):
    s = Signal("SIG-00125", "2026-10-05T10:01:31Z", "ACCES", "192.168.1.15",
               "web-app", "LOGIN_ECHEC", "MOYENNE",
               "POST /login -> 401 depuis 192.168.1.x")
    v = Verdict("SIG-00125", niveau, "Echecs de connexion",
                "Bloquer l'IP 192.168.1.15", sensible, ["ACCES"])
    return s, v

class TestAlerte(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITIQUE"), "TELEPHONE")
        self.assertEqual(choisir_canal("ELEVEE"), "SLACK")
        self.assertEqual(choisir_canal("MOYENNE"), "EMAIL")
        self.assertEqual(choisir_canal("FAIBLE"), "TABLEAU")
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_validation(self):
        s, v_sensible = exemple(sensible=True)
        self.assertTrue(valider_action(v_sensible, " OUI "))
        self.assertTrue(valider_action(v_sensible, "o"))
        self.assertTrue(valider_action(v_sensible, "yes"))
        self.assertFalse(valider_action(v_sensible, "n"))
        
        s, v_non_sensible = exemple(sensible=False)
        self.assertTrue(valider_action(v_non_sensible, "non")) # Toujours True si non sensible

    def test_rediger(self):
        s, v = exemple()
        texte = rediger(s, v)
        lignes = texte.split('\n')
        self.assertEqual(len(lignes), 5)
        self.assertEqual(lignes[0], "[CRITIQUE] Cible: web-app")
        self.assertEqual(lignes[1], "Signal: POST /login -> 401 depuis 192.168.1.x")
        self.assertEqual(lignes[2], "Explication: Echecs de connexion")
        self.assertEqual(lignes[3], "Action proposee: Bloquer l'IP 192.168.1.15")
        self.assertEqual(lignes[4], "Sources: ACCES")

    def test_alerter(self):
        s, v = exemple()
        journal = []
        alerte = alerter(s, v, journal)
        self.assertEqual(alerte.signal_id, "SIG-00125")
        self.assertEqual(alerte.canal, "TELEPHONE")
        self.assertEqual(alerte.destinataire, "equipe-secu")
        self.assertEqual(s.statut, "ALERTE")
        self.assertEqual(len(journal), 1)

if __name__ == "__main__":
    unittest.main()