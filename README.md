# Documentation Technique - SecureCrypt Ultimate

## 1. Vue d'ensemble
SecureCrypt Ultimate est une application de bureau Windows autonome permettant le chiffrement et le déchiffrement sécurisé de fichiers et de dossiers. Elle est développée en Python et compilée en code machine pour une portabilité maximale.

## 2. Architecture Cryptographique

### 2.1 Primitives Utilisées
L'application repose sur des standards cryptographiques robustes et reconnus par l'industrie (NIST, OWASP).

| Composant | Algorithme | Configuration |
| :--- | :--- | :--- |
| **Chiffrement Symétrique** | AES (Advanced Encryption Standard) | **Mode** : GCM (Galois/Counter Mode)<br>**Taille de clé** : 256 bits |
| **Dérivation de Clé (KDF)** | Argon2id | **Temps** : 2 itérations<br>**Mémoire** : 64 MiB (65536 KiB)<br>**Parallélisme** : 4 threads<br>**Longueur du hash** : 32 octets |
| **Génération d'Aléa** | CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) | Via le module `secrets` de Python (appel système OS sécurisé) |

### 2.2 Protocole de Chiffrement (Fichier)
Pour chaque fichier chiffré, le processus suivant est exécuté :
1.  **Génération de Sel** : Un sel aléatoire de 16 octets est généré.
2.  **Génération d'IV** : Un vecteur d'initialisation (IV/Nonce) unique de 12 octets est généré.
3.  **Dérivation de Clé** : Le mot de passe utilisateur et le sel sont passés dans **Argon2id** pour produire une clé AES de 32 octets.
4.  **Chiffrement Authentifié** : Le contenu du fichier est chiffré avec AES-256-GCM. Ce mode génère un "Tag d'authentification" (inclus dans le texte chiffré) qui garantit que les données n'ont pas été altérées.
5.  **Structure du Fichier de Sortie** :
    ```
    [16 octets : Sel (Salt)] + [12 octets : IV] + [Données Chiffrées + Tag GCM]
    ```

### 2.3 Protocole de Déchiffrement
1.  Le fichier est lu. Les 28 premiers octets sont extraits pour récupérer le Sel et l'IV.
2.  La clé est recréée à partir du mot de passe utilisateur et du Sel extrait (via Argon2id).
3.  AES-GCM tente de déchiffrer. Si le mot de passe est faux ou si le fichier a été modifié (bit flip, troncature), la vérification du Tag GCM échoue et une exception est levée, empêchant toute sortie de données corrompues.

### 2.4 Gestion des Dossiers
L'application n'applique pas le chiffrement récursivement fichier par fichier (ce qui laisserait fuiter la structure et les noms de fichiers).
1.  **Archivage** : Le dossier est compressé en mémoire ou en fichier temporaire au format ZIP standard.
2.  **Chiffrement** : L'archive ZIP résultante est traitée comme un fichier binaire unique et chiffrée selon le protocole 2.2.
3.  **Résultat** : Un fichier opaque (ex: `dossier.zip.enc`) qui masque totalement le contenu, les noms de fichiers et l'arborescence.

## 3. Stack Technique

*   **Langage** : Python 3.10+
*   **Interface Graphique (GUI)** : `CustomTkinter` (Wrapper moderne sur Tkinter/Tcl).
    *   Support natif du High-DPI.
    *   Thème sombre intégré.
    *   Exécution asynchrone (Threading) pour ne pas figer l'interface lors des calculs cryptographiques lourds.
*   **Bibliothèques Cryptographiques** : `cryptography` (contrairement aux solutions pure-python, elle utilise OpenSSL en backend pour une sécurité et une performance maximales).
*   **Compilation** : `PyInstaller`.
    *   Mode `onefile` : Tout est regroupé dans un seul `.exe`.
    *   Mode `windowed` : Pas de console noire au démarrage.

## 4. Sécurité Opérationnelle

*   **Pas de Stockage de Clés** : Les clés de chiffrement sont éphémères. Elles existent uniquement en mémoire RAM pendant l'opération et sont détruites ensuite. Elles ne sont jamais écrites sur le disque.
*   **Nettoyage** : Les fichiers temporaires (archives zip non chiffrées) sont supprimés immédiatement après le chiffrement.

---
**Auteur** : Sofiane LAMOUROUX (contact@slamouroux.fr)
**Version** : Ultimate 1.0
