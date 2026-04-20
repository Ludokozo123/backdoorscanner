# HTS Scanner

Scanner de ressources FiveM utilisé par [HebergTonServ](https://hebergtonserv.com)
pour détecter les backdoors connus dans les ressources serveur.

## Fonctionnement

Exécuté automatiquement au démarrage du serveur FiveM. Parcourt le dossier
`resources/` et signale les fichiers suspects. En cas de détection, invite
le client à contacter le support HTS.

## Usage

```bash
node index.js ./resources
node index.js ./resources --json
node index.js --help
```

Le scanner sort toujours en code 0 pour ne pas bloquer le démarrage du serveur.

## Détections

- Loaders XOR type **Blum** (décodeur `String.fromCharCode(a[i] ^ k)` + array d'entiers)
- Signatures **Cipher Panel** (domaines et patterns connus)
- Exports filesystem suspects dans les manifests
- Scripts fortement obfusqués avec accès réseau
- Références DLL .NET malveillantes
- Patterns `globalThis[...]` dynamiques

## Requis

Node.js ≥ 18.

## Licence

Ce projet est distribué sous licence [CC BY-NC 4.0](LICENSE).
Utilisation non commerciale uniquement.

## Crédits

Ce projet est un fork de
[fivem-security-auditor](https://github.com/Sabaariiego/fivem-security-auditor)
créé par **Eric Sabariego** (Sabaariiego), publié sous licence CC BY-NC 4.0.

Modifications apportées par HebergTonServ :
- Ajout du détecteur Blum XOR (signature eval-free)
- Restriction du whitelist webpack aux vrais bundles (vocabulaire ≥3 tokens)
- Suppression de la dépendance Windows-only `winattr` (portabilité Linux)
- Sortie neutre orientée support HTS
- Suppression du mode `--fix` et du mode interactif

Toutes les modifications conservent la licence CC BY-NC 4.0 de l'œuvre originale.
