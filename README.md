# Récupérer ses fonds d'un wallet Yoroi / SecondFi sans phrase de récupération

Deux petits scripts Python pour les personnes dont le wallet **Yoroi (devenu SecondFi)** est arrêté, qui n'ont **pas gardé leur phrase de récupération**, mais dont l'**extension de navigateur est encore installée** et dont le **mot de passe de dépense** est connu.

> ⚠️ **Avertissement.** Ces scripts manipulent des clés privées et envoient de vrais fonds. Ils sont fournis tels quels, sans garantie. Ils ont été écrits pour un cas précis et ont fonctionné pour leur auteur, sur un wallet Yoroi Shelley (extension Firefox). Ils ne sont pas audités. **Lisez le code** (environ 400 lignes, sans dépendance cachée) avant de leur confier quoi que ce soit, et commencez toujours par un envoi de test.

## Le problème

EMURGO a arrêté Yoroi/SecondFi après l'incident de sécurité de juin 2026. L'extension s'ouvre encore et affiche le solde, mais impossible d'envoyer : les serveurs de Yoroi répondent `502` ou `400 invalid API key`, et l'extension ne permet ni de réafficher la phrase de récupération, ni d'exporter la clé privée.

Pourtant, le wallet est toujours là. L'extension stocke dans le navigateur (IndexedDB) la **clé racine chiffrée par votre mot de passe de dépense**. Avec ce mot de passe, on peut la déchiffrer, puis construire et signer soi-même une transaction et la diffuser via un autre service (Koios).

Si vous avez encore votre phrase de récupération, **n'utilisez pas ces scripts** : restaurez-la dans un nouveau wallet. Si votre wallet a été vidé lors de l'incident, ce dépôt ne s'applique pas : suivez l'outil de récupération officiel d'EMURGO/SecondFi.

## Ce qu'il faut

- L'extension Yoroi **toujours installée** dans le navigateur, avec les données du wallet.
- Votre **mot de passe de dépense** (celui demandé pour envoyer des fonds).
- Python 3 (déjà présent sur macOS et la plupart des Linux).
- Un **nouveau wallet** Cardano (autre fournisseur), avec une **nouvelle phrase de récupération notée sur papier**, et son adresse `addr1…`.

## Avant toute chose

1. **Ne désinstallez pas l'extension et ne supprimez pas le wallet.** Cela efface les données chiffrées : sans phrase de récupération, tout serait perdu.
2. **Faites une copie de sauvegarde du profil du navigateur** (fermez-le d'abord). Sous Firefox : `about:support` → « Dossier de profil » → « Ouvrir le dossier », puis copiez-le ailleurs.

## Étape 1 : récupérer la clé chiffrée

Ouvrez l'extension dans un onglet, puis les outils de développement (F12).

- **Firefox :** onglet « Stockage » → IndexedDB → `yoroi-schema` → table **`Key`**.
- **Chrome / Brave :** onglet « Application » → IndexedDB → `yoroi-schema` → table **`Key`**.

Parmi les lignes, prenez celle où **`IsEncrypted` vaut `true`**. Copiez sa valeur **`Hash`** : une chaîne hexadécimale d'environ 312 caractères (sel 32 octets + nonce 12 + tag 16 + clé racine 96). Les autres lignes (non chiffrées, plus courtes) sont des clés publiques.

> Les noms des tables peuvent varier selon la version de l'extension. Si besoin, cherchez la ligne dont le `Hash` est long et chiffré.

## Étape 2 : déchiffrer la clé racine

```bash
python3 -m venv venv && source venv/bin/activate
pip install cryptography
python3 decrypt_yoroi_key.py
```

Collez le `Hash`, puis tapez votre mot de passe (la saisie est masquée). Si le mot de passe est correct, le script affiche la clé racine (96 octets) en hexadécimal et au format `root_xsk1…`. Sinon, il répond « mot de passe incorrect ».

Le format déchiffré est celui d'EMIP-003 : `sel(32) | nonce(12) | tag(16) | texte chiffré`, avec une clé dérivée par PBKDF2-HMAC-SHA512 (19162 itérations) et un chiffrement ChaCha20-Poly1305.

## Étape 3 : envoyer les fonds vers le nouveau wallet

`sweep_yoroi.py` n'a **aucune dépendance** (Python 3 seul). Il dérive les clés (CIP-1852, `m/1852'/1815'/0'`), cherche vos UTXO via [Koios](https://koios.rest), construit et **signe la transaction en local**, puis la diffuse après votre confirmation. Votre clé n'est jamais envoyée sur le réseau.

```bash
# 1) Simulation : ne diffuse rien
python3 sweep_yoroi.py --dest addr1VOTRE_NOUVELLE_ADRESSE --dry-run

# 2) Envoi de test (2 ADA par défaut) : le reste (ADA + tokens) revient sur l'adresse 0 de l'ancien wallet
python3 sweep_yoroi.py --dest addr1VOTRE_NOUVELLE_ADRESSE

# 3) Tout envoyer : ADA + tous les tokens (NIGHT inclus), moins les frais
python3 sweep_yoroi.py --dest addr1VOTRE_NOUVELLE_ADRESSE --all
```

Le script demande la clé (`root_xsk1…` ou 192 caractères hexadécimaux) en saisie masquée, affiche un résumé (UTXO, ADA, tokens, frais, destination, identifiant de la transaction) et ne diffuse qu'après avoir tapé `ENVOYER`.

### Vérifier que la clé est la bonne

Par défaut, le script affiche le hash de votre clé de staking. Pour que le script s'arrête de lui-même si la clé n'est pas la vôtre, passez `--expect-stake-hash` avec le hash de votre clé de staking, c'est-à-dire les 28 octets (56 caractères hex) de votre adresse de récompense, après le premier octet `e1`. Vous pouvez aussi simplement vérifier que le solde et les tokens affichés sont bien les vôtres.

### Options

| Option | Rôle |
|---|---|
| `--dest` | adresse `addr1…` du nouveau wallet (réseau principal, obligatoire) |
| `--all` | envoie tout (sans cette option : envoi de test) |
| `--test-ada` | montant du test en ADA (2 par défaut) |
| `--dry-run` | calcule tout, ne diffuse rien |
| `--expect-stake-hash` | hash de la clé de staking attendu, pour vérifier la clé |
| `--gap` | adresses scannées par chaîne (40 par défaut) |
| `--max-inputs` | nombre maximal d'UTXO par transaction (60 par défaut) |
| `--koios` | URL de l'API Koios |

## Limites

- **Wallets Yoroi Shelley** (clé racine Icarus, `1852'/1815'`, compte 0, adresses de base). Pas les wallets Byron (anciens, 15 mots), pas les comptes multiples, pas les wallets liés à un Ledger ou un Trezor (reconnectez simplement l'appareil à un autre wallet).
- **Les récompenses de staking ne sont pas retirées**, et le dépôt de la clé de staking (2 ADA) n'est pas récupéré. Si vous avez des récompenses, retirez-les avant.
- Les UTXO avec script ou datum sont refusés par sécurité.
- Réseau principal (mainnet) uniquement.
- La limite de 5120 octets par requête de Koios impose des lots de 20 adresses. Si Koios change ses limites ou son format, le script pourra nécessiter une mise à jour.
- Testé hors ligne contre la bibliothèque `pycardano` (dérivation, adresses, signatures, structure de la transaction), et en réel sur un wallet par son auteur. Votre cas peut différer.

## Sécurité

- **La clé racine donne un contrôle total sur le wallet.** Ne la collez jamais dans un site web, un chat, un outil d'IA ou un e-mail. Conservez-la le moins longtemps possible, puis supprimez-la de votre machine.
- Personne n'a besoin de votre clé, de votre mot de passe ou de votre phrase de récupération pour « vous aider ». Les « services de récupération » qui vous contactent en premier sont des arnaques.
- Après le transfert, ne supprimez pas l'ancien wallet de l'extension : il peut encore servir à la procédure de récupération d'EMURGO ou à des claims (par exemple NIGHT).
- Vérifiez l'adresse de destination **caractère par caractère** : une transaction diffusée ne peut pas être annulée.

## Contenu

- `decrypt_yoroi_key.py` : déchiffre la clé racine EMIP-003 avec le mot de passe de dépense.
- `sweep_yoroi.py` : dérive les clés, construit, signe et diffuse la transaction (Koios).
