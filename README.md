# Cipherix — Suite Cybersécurité Premium

Application web 100% locale de sécurité et gestion de mots de passe.  
Aucune donnée ne quitte votre appareil. Zéro backend. Zéro cloud.

---

## Démarrage

1. Extraire le ZIP
2. Ouvrir `index.html` dans un navigateur moderne (Chrome, Firefox, Edge, Safari)
3. Créer votre PIN vault au premier lancement
4. Tout est prêt.

> Pour les fonctionnalités PWA (mode offline, installation), servez le dossier via un serveur HTTP local :
> ```bash
> npx serve .   # ou python -m http.server 8080
> ```

---

## Fonctionnalités

| Module | Description |
|--------|-------------|
| **Générateur** | Mots de passe intelligents (basés sur vos données) ou aléatoires ultra-sécurisés |
| **Analyseur** | Score de force, temps de bruteforce, détection de patterns |
| **Cryptographie** | AES-256-GCM, SHA-256, Base64, César, ROT-13 |
| **Vault** | Coffre-fort chiffré protégé par PIN, verrouillage auto |
| **Security Lab** | Terminal de simulation, entropie, comparaisons |
| **Export/Import** | Sauvegarde JSON chiffrée, restauration sécurisée |

---

## Stack technique

- **HTML5 / CSS3 / Vanilla JavaScript** — Aucun framework
- **Web Crypto API** — Toute la cryptographie (AES-256-GCM, PBKDF2, SHA-256)
- **LocalStorage** — Persistance locale uniquement
- **PWA** — Service Worker, manifest, mode offline

---

## Sécurité

- `crypto.getRandomValues()` pour toute génération aléatoire
- AES-256-GCM avec PBKDF2 (100 000 itérations) pour le vault
- PIN haché via SHA-256 avant stockage
- Aucun `eval()`, aucun `innerHTML` dangereux, sanitization complète
- Données jamais transmises à aucun serveur

---

## Structure

```
cipherix/
├── index.html       — Structure HTML complète
├── style.css        — CSS premium (variables, glassmorphism, animations)
├── app.js           — Application JavaScript modulaire
├── manifest.json    — PWA manifest
├── sw.js            — Service Worker (cache offline)
└── assets/
    ├── favicon.svg
    ├── icon-192.svg
    └── icon-512.svg
```

---

**Cipherix v2.1** — Développé avec Web Crypto API native. Production-ready.
