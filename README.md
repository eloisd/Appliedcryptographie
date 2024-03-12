
## README.md - Projet de Cryptographie

**Date limite :** Mercredi 27 mars 2024

**Groupe TD DIA 6 :**

Henri Serano, Sara Thibierge, Eloi Seidlitz

**Exercices :**

**Exercice 1 :**

1. Trouver une chaîne de caractères (contenant vos noms et prénoms) dont le hash SHA256 se termine par le plus de zéros possible (en hexadécimal).
2. Mesurer le temps moyen pour obtenir n et n+1 zéros en fin de chaîne (n = 5) et calculer le rapport Tn+1/Tn.

**Exercice 2 :**

1. Chiffrer un texte d'environ une demi-page (format .txt) avec AES256-CTR-PBKDF2 en utilisant un mot de passe et une valeur de compteur (IV) de 6 à 9 chiffres (sans 0).
2. Constituez un entier N en accolant le mot de passe et l'IV séparés par quatre 0.
3. Chiffrer N avec ElGamal en utilisant les nombres p, g et A fournis.
4. Sauvegarder le fichier chiffré avec l'extension .enc.

**Exercice 3 :**

1. Démonstration de la signature ElGamal ou RSA (avec des nombres différents de ceux du cours).
2. Exemple d'utilisation du RSA, Diffie-Hellman, ElGamal ou de la signature ElGamal dans Python ou openssl (contexte réel).

**Informations complémentaires :**

* Le document doit être clair, concis et bien rédigé.
* Le code doit être commenté clairement.
* Les noms et prénoms des étudiants doivent figurer sur les deux fichiers.
* Le respect des consignes et de la date limite est impératif.

**Ressources utiles :**

* Cours de cryptographie
* Documentation OpenSSL
* Tutoriels Python/OpenSSL
