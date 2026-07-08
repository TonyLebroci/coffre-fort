# Coffre-fort

PWA de coffre-fort personnel pour photos de documents d'identité (cartes, passeport,
assurance maladie) et mots de passe, organisés par dossiers. Déverrouillage par
Face ID / Touch ID (WebAuthn). Tout est chiffré (AES-256-GCM) et stocké uniquement
en local dans IndexedDB — rien n'est envoyé sur un serveur ou dans le cloud.

## Lancer l'application

WebAuthn exige un contexte sécurisé : HTTPS, ou `localhost`. Sers le dossier avec
n'importe quel serveur statique, par exemple :

```
npx serve .
# ou
python3 -m http.server 8080
```

Puis ouvre `http://localhost:8080` (ou le port choisi) dans un navigateur compatible
(Safari iOS/macOS récent, Chrome/Edge desktop et Android). Pour l'installer comme
app (icône sur l'écran d'accueil), utilise « Ajouter à l'écran d'accueil » /
« Installer l'application ».

Pour un usage réel sur un iPhone, héberge le dossier sur un service HTTPS
(GitHub Pages, Netlify, Vercel, etc.) — WebAuthn refuse de fonctionner en HTTP
simple (sauf `localhost`).

## Comment ça marche

- **Déverrouillage** : un passkey lié à l'appareil (Face ID / Touch ID / Windows
  Hello) est créé au premier lancement. Si le navigateur supporte l'extension
  WebAuthn **PRF**, un secret dérivé directement de l'authentification biométrique
  sert à chiffrer la clé du coffre — aucun mot de passe n'est nécessaire.
  Si l'appareil ne supporte pas PRF, une phrase secrète complémentaire est
  demandée à la création (en plus de Face ID / Touch ID à chaque ouverture).
- **Chiffrement** : chaque document/mot de passe est chiffré avec AES-256-GCM
  (clé de coffre aléatoire, IV unique par élément). Rien n'est jamais stocké
  en clair, y compris les titres et noms de dossiers.
- **Stockage** : IndexedDB, dans le navigateur, sur cet appareil uniquement.
- **Verrouillage automatique** : après 3 minutes d'inactivité ou dès que l'onglet
  passe en arrière-plan.

## Limites à connaître

- **Aucune sauvegarde/export** : si tu effaces les données du navigateur, changes
  d'appareil, ou perds l'accès au passkey, le contenu du coffre est perdu
  définitivement (il n'y a volontairement aucune copie ailleurs). À garder en tête
  avant d'y stocker des documents importants sans autre copie de secours.
- Le support de l'extension PRF varie selon navigateur/OS ; sur les appareils qui
  ne le supportent pas encore, la phrase secrète de secours est indispensable.

## Structure

```
index.html          Écrans (setup, verrouillage, liste, visionneuse, formulaires)
css/style.css        Interface (clair/sombre automatique)
js/crypto.js         WebAuthn + AES-GCM (aucune dépendance externe)
js/db.js             Accès IndexedDB
js/app.js            Logique applicative et rendu
manifest.webmanifest  Manifeste PWA
sw.js                 Service worker (cache de la coquille applicative hors-ligne)
icons/                Icônes de l'app
```

Aucune dépendance, aucun build : ce sont des fichiers statiques servis tels quels.
