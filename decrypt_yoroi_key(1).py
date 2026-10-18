#!/usr/bin/env python3
"""
Déchiffre la clé racine d'un wallet Yoroi (format EMIP-003) avec le mot de
passe de dépense. Fonctionne 100 % en local, hors ligne.

Prérequis :  pip install cryptography
Usage    :  python3 decrypt_yoroi_key.py
            (le script demande le texte chiffré, puis le mot de passe)

Format EMIP-003 : salt(32) | nonce(12) | tag(16) | ciphertext
  - clé = PBKDF2-HMAC-SHA512(mot de passe, salt, 19162 itérations, 32 octets)
  - chiffrement = ChaCha20-Poly1305, sans données associées
Résultat attendu : 96 octets = clé racine étendue BIP32-Ed25519 (64) + chain code (32).
"""
import getpass
import hashlib
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ITERATIONS = 19162
SALT_LEN, NONCE_LEN, TAG_LEN = 32, 12, 16


def decrypt_emip3(blob: bytes, password: str) -> bytes:
    if len(blob) < SALT_LEN + NONCE_LEN + TAG_LEN + 1:
        raise ValueError("Texte chiffré trop court : mauvais champ copié ?")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    tag = blob[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN + TAG_LEN:]
    key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, ITERATIONS, 32)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, None)


# --- encodage bech32 (pour obtenir root_xsk1..., lisible par cardano-address) ---
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    d5 = _convertbits(data, 8, 5)
    pm = _polymod(_hrp_expand(hrp) + d5 + [0] * 6) ^ 1
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[x] for x in d5 + checksum)


def main():
    print("Collez le texte chiffré (chaîne hexadécimale), puis Entrée :")
    raw = sys.stdin.readline().strip().strip('"').strip("'")
    try:
        blob = bytes.fromhex(raw)
    except ValueError:
        sys.exit("Ce n'est pas de l'hexadécimal. Vérifiez le champ copié.")
    password = getpass.getpass("Mot de passe de dépense (invisible à la saisie) : ")
    try:
        plain = decrypt_emip3(blob, password)
    except InvalidTag:
        sys.exit("Échec : mot de passe incorrect, ou ce champ n'est pas la clé chiffrée.")
    except ValueError as e:
        sys.exit(str(e))
    print(f"\nDéchiffrement réussi : {len(plain)} octets.")
    if len(plain) == 96:
        print("\nClé racine (hex) :\n" + plain.hex())
        print("\nClé racine (bech32) :\n" + bech32_encode("root_xsk", plain))
    else:
        print("\nContenu (hex) :\n" + plain.hex())
    print("\nCette clé donne un contrôle TOTAL sur le wallet. Ne la copiez nulle part en ligne,")
    print("ne l'envoyez à personne, et effacez le terminal après usage.")


if __name__ == "__main__":
    main()
