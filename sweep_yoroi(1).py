#!/usr/bin/env python3
"""
Envoie TOUT le contenu d'un wallet Cardano (ADA + tokens, dont NIGHT) vers une
autre adresse, à partir de la clé racine (root_xsk) et SANS passer par les
serveurs de Yoroi. Aucune dépendance : Python 3 seul.

Étapes : dérive les clés (CIP-1852), vérifie que c'est bien votre wallet,
lit vos UTXO sur Koios, construit et signe la transaction EN LOCAL, puis
(après confirmation de votre part) la diffuse via Koios.

Usage :
  python3 sweep_yoroi.py --dest addr1...            # envoi de TEST (2 ADA)
  python3 sweep_yoroi.py --dest addr1... --all      # tout envoyer
  ajouter --dry-run pour tout calculer sans rien envoyer.
La clé root_xsk (ou 192 caractères hexadécimaux) est demandée en saisie masquée.
"""
import argparse
import getpass
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

# Vérification optionnelle : hash (56 caractères hex) de VOTRE clé de staking,
# à passer avec --expect-stake-hash. Il se déduit de l'adresse de récompense
# (stake1...) de votre wallet : c'est la partie après le premier octet "e1".
DEFAULT_STAKE_HASH = ""

# ============================ Ed25519 (étendu) ============================
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = (-121665 * _inv(121666)) % P
_SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x & 1) != sign:
        x = P - x
    return x


_BY = 4 * _inv(5) % P
_BX = _recover_x(_BY, 0)
G = (_BX, _BY, 1, _BX * _BY % P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _enc(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def pubkey(kl: bytes) -> bytes:
    return _enc(_mul(int.from_bytes(kl, "little"), G))


def sign(kl: bytes, kr: bytes, msg: bytes) -> bytes:
    a = int.from_bytes(kl, "little")
    pub = _enc(_mul(a, G))
    r = int.from_bytes(hashlib.sha512(kr + msg).digest(), "little") % L
    big_r = _enc(_mul(r, G))
    h = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % L
    return big_r + ((r + h * a) % L).to_bytes(32, "little")


# ===================== Dérivation BIP32-Ed25519 (V2) ======================
class Node:
    def __init__(self, kl, kr, cc):
        self.kl, self.kr, self.cc = kl, kr, cc
        self._pub = None

    @property
    def pub(self):
        if self._pub is None:
            self._pub = pubkey(self.kl)
        return self._pub


def derive(node: Node, index: int) -> Node:
    idx = index.to_bytes(4, "little")
    if index >= 0x80000000:
        z = hmac.new(node.cc, b"\x00" + node.kl + node.kr + idx, hashlib.sha512).digest()
        c = hmac.new(node.cc, b"\x01" + node.kl + node.kr + idx, hashlib.sha512).digest()
    else:
        z = hmac.new(node.cc, b"\x02" + node.pub + idx, hashlib.sha512).digest()
        c = hmac.new(node.cc, b"\x03" + node.pub + idx, hashlib.sha512).digest()
    zl = int.from_bytes(z[:28], "little")
    zr = int.from_bytes(z[32:], "little")
    kl = (int.from_bytes(node.kl, "little") + 8 * zl) % (1 << 256)
    kr = (int.from_bytes(node.kr, "little") + zr) % (1 << 256)
    return Node(kl.to_bytes(32, "little"), kr.to_bytes(32, "little"), c[32:])


H = 0x80000000


def blake224(b):
    return hashlib.blake2b(b, digest_size=28).digest()


# ================================ Bech32 ==================================
_CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bits(data, frm, to, pad):
    acc, bits, out, maxv = 0, 0, [], (1 << to) - 1
    for b in data:
        acc = (acc << frm) | b
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        raise ValueError("bech32 invalide")
    return out


def bech32_encode(hrp, data: bytes) -> str:
    d5 = _bits(data, 8, 5, True)
    pm = _polymod(_hrp(hrp) + d5 + [0] * 6) ^ 1
    return hrp + "1" + "".join(_CH[x] for x in d5 + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def bech32_decode(s: str):
    s = s.strip()
    if s != s.lower() and s != s.upper():
        raise ValueError("casse mélangée")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1:
        raise ValueError("pas du bech32")
    data = [_CH.find(c) for c in s[pos + 1:]]
    if -1 in data or len(data) < 6 or _polymod(_hrp(s[:pos]) + data) != 1:
        raise ValueError("somme de contrôle invalide (adresse mal copiée ?)")
    return s[:pos], bytes(_bits(data[:-6], 5, 8, False))


# ================================== CBOR ==================================
def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("entier trop grand")


def cbor(o):
    if o is True:
        return b"\xf5"
    if o is None:
        return b"\xf6"
    if isinstance(o, int):
        return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, (bytes, bytearray)):
        return _head(2, len(o)) + bytes(o)
    if isinstance(o, list):
        return _head(4, len(o)) + b"".join(cbor(x) for x in o)
    if isinstance(o, dict):
        return _head(5, len(o)) + b"".join(cbor(k) + cbor(v) for k, v in o.items())
    raise TypeError(type(o))


# ================================== Koios =================================
def http(method, url, body=None, ctype="application/json"):
    headers = {"Accept": "application/json", "User-Agent": "Mozilla/5.0 (sweep-script)"}
    if body is not None:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"Erreur Koios {e.code} sur {url}:\n{e.read().decode(errors='replace')[:600]}")
    except urllib.error.URLError as e:
        raise SystemExit(
            f"Connexion impossible à {url} : {e.reason}\n"
            "Si l'erreur parle de CERTIFICATE_VERIFY_FAILED sur Mac : lancez le fichier "
            "'Install Certificates.command' du dossier Python (Applications), puis réessayez.")


# ================================ Utilitaires =============================
def ada(n):
    return f"{n / 1_000_000:,.6f} ADA"


def asset_label(policy, name_hex):
    try:
        txt = bytes.fromhex(name_hex).decode("ascii")
        if txt.isprintable() and txt:
            return f"{txt} ({policy[:8]}…)"
    except ValueError:
        pass
    return f"{name_hex or '(sans nom)'} ({policy[:8]}…)"


def assets_cbor(assets):
    out = {}
    for (pol, name), q in sorted(assets.items()):
        out.setdefault(bytes.fromhex(pol), {})[bytes.fromhex(name)] = q
    return out


def value_cbor(coin, assets):
    return coin if not assets else [coin, assets_cbor(assets)]


def parse_root(text: str) -> Node:
    text = text.strip()
    if text.lower().startswith("root_xsk"):
        hrp, raw = bech32_decode(text)
        if hrp != "root_xsk":
            raise SystemExit("Préfixe inattendu.")
    else:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raise SystemExit("Clé illisible : attendu 'root_xsk1…' ou 192 caractères hexadécimaux.")
    if len(raw) != 96:
        raise SystemExit(f"Taille inattendue ({len(raw)} octets au lieu de 96).")
    return Node(raw[:32], raw[32:64], raw[64:])


def check_dest(addr: str) -> bytes:
    try:
        hrp, raw = bech32_decode(addr)
    except ValueError as e:
        raise SystemExit(f"Adresse de destination invalide : {e}")
    if hrp != "addr":
        raise SystemExit("La destination doit commencer par 'addr1' (réseau principal).")
    typ, net = raw[0] >> 4, raw[0] & 15
    if net != 1 or typ not in (0, 1, 2, 3, 6, 7):
        raise SystemExit("Type d'adresse non pris en charge.")
    if (typ < 4 and len(raw) != 57) or (typ in (6, 7) and len(raw) != 29):
        raise SystemExit("Longueur d'adresse inattendue.")
    return raw


# ================================== Main ==================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", required=True, help="adresse du NOUVEAU wallet (addr1...)")
    ap.add_argument("--all", action="store_true", help="tout envoyer (sinon : test de --test-ada)")
    ap.add_argument("--test-ada", type=float, default=2.0)
    ap.add_argument("--dry-run", action="store_true", help="ne rien diffuser")
    ap.add_argument("--koios", default="https://api.koios.rest/api/v1")
    ap.add_argument("--gap", type=int, default=40, help="nb d'adresses scannées par chaîne")
    ap.add_argument("--max-inputs", type=int, default=60)
    ap.add_argument("--expect-stake-hash", default=DEFAULT_STAKE_HASH)
    a = ap.parse_args()

    dest = check_dest(a.dest)
    root = parse_root(getpass.getpass("Clé racine (saisie masquée) : "))

    acct = derive(derive(derive(root, 1852 + H), 1815 + H), 0 + H)
    stake = derive(derive(acct, 2), 0)
    shash = blake224(stake.pub)
    if a.expect_stake_hash and shash.hex() != a.expect_stake_hash.lower():
        raise SystemExit(
            "ARRÊT : cette clé ne correspond PAS au wallet attendu (clé de staking différente).\n"
            f"  obtenu : {shash.hex()}\n  attendu: {a.expect_stake_hash}\n"
            "Rien n'a été envoyé. Vérifiez la ligne 'Key' déchiffrée et le mot de passe.")
    if a.expect_stake_hash:
        print("✔ La clé correspond bien à votre wallet.")
    else:
        print(f"Hash de votre clé de staking : {shash.hex()}")
        print("⚠ Aucune vérification demandée (--expect-stake-hash). Les UTXO trouvés ci-dessous "
              "doivent correspondre à votre solde : sinon, arrêtez-vous.")

    ext, internal = derive(acct, 0), derive(acct, 1)
    addrs = {}  # adresse bech32 -> (nœud, octets)
    for chain in (ext, internal):
        for i in range(a.gap):
            n = derive(chain, i)
            raw = b"\x01" + blake224(n.pub) + shash
            addrs[bech32_encode("addr", raw)] = (n, raw)
    change_addr_raw = addrs[next(iter(addrs))][1]  # adresse externe 0

    # ---- UTXO ----
    utxos = []
    keys = list(addrs)
    for s in range(0, len(keys), 20):
        batch = keys[s:s + 20]
        res = json.loads(http("POST", a.koios + "/address_info",
                              json.dumps({"_addresses": batch}).encode()))
        for entry in res:
            node = addrs[entry["address"]][0]
            for u in entry.get("utxo_set") or []:
                assets = {}
                for t in u.get("asset_list") or []:
                    assets[(t["policy_id"], t.get("asset_name") or "")] = int(t["quantity"])
                utxos.append(dict(h=u["tx_hash"], i=u["tx_index"], v=int(u["value"]),
                                  assets=assets, node=node,
                                  ref=bool(u.get("reference_script") or u.get("inline_datum"))))
    if not utxos:
        raise SystemExit("Aucun UTXO trouvé pour ce wallet (adresses scannées : %d)." % len(keys))
    if any(u["ref"] for u in utxos):
        raise SystemExit("UTXO avec script/datum détecté : je m'arrête par sécurité.")
    utxos.sort(key=lambda u: -u["v"])
    if len(utxos) > a.max_inputs:
        print(f"⚠ {len(utxos)} UTXO : seuls les {a.max_inputs} plus gros sont utilisés "
              "dans cette transaction (relancez ensuite pour le reste).")
        utxos = utxos[:a.max_inputs]

    total = sum(u["v"] for u in utxos)
    tokens = {}
    for u in utxos:
        for k, q in u["assets"].items():
            tokens[k] = tokens.get(k, 0) + q

    # ---- paramètres réseau ----
    try:
        pp = json.loads(http("GET", a.koios + "/cli_protocol_params"))
        fee_a, fee_b = int(pp["txFeePerByte"]), int(pp["txFeeFixed"])
        coin_per_byte = int(pp["utxoCostPerByte"])
    except (SystemExit, KeyError, ValueError):
        fee_a, fee_b, coin_per_byte = 44, 155381, 4310
        print("⚠ Paramètres réseau par défaut utilisés.")
    tip = json.loads(http("GET", a.koios + "/tip"))
    ttl = int(tip[0]["abs_slot"]) + 7200

    def min_coin(addr_raw, assets):
        coin = 1_000_000
        for _ in range(5):
            need = (160 + len(cbor([addr_raw, value_cbor(coin, assets)]))) * coin_per_byte
            if coin >= need:
                return coin
            coin = need
        return coin

    test_lovelace = int(a.test_ada * 1_000_000)

    def outputs(fee):
        if a.all:
            return [[dest, value_cbor(total - fee, tokens)]]
        return [[dest, test_lovelace],
                [change_addr_raw, value_cbor(total - test_lovelace - fee, tokens)]]

    def build(fee):
        body = cbor({0: [[bytes.fromhex(u["h"]), u["i"]] for u in utxos],
                     1: outputs(fee), 2: fee, 3: ttl})
        txid = hashlib.blake2b(body, digest_size=32).digest()
        wits, seen = [], set()
        for u in utxos:
            n = u["node"]
            if n.pub not in seen:
                seen.add(n.pub)
                wits.append([n.pub, sign(n.kl, n.kr, txid)])
        return b"\x84" + body + cbor({0: wits}) + b"\xf5\xf6", txid

    fee = 200_000
    for _ in range(8):
        tx, txid = build(fee)
        needed = fee_a * len(tx) + fee_b + 1000
        if needed == fee:
            break
        fee = needed
    if len(tx) > 16000:
        raise SystemExit("Transaction trop grosse : utilisez --max-inputs avec une valeur plus petite.")

    # ---- contrôles ----
    outs = outputs(fee)
    dest_coin = outs[0][1] if isinstance(outs[0][1], int) else outs[0][1][0]
    need_dest = min_coin(dest, tokens if a.all else {})
    if dest_coin < need_dest:
        raise SystemExit(f"Montant trop faible vers la destination (minimum {ada(need_dest)}).")
    if not a.all:
        ch = outs[1][1]
        ch_coin = ch if isinstance(ch, int) else ch[0]
        if ch_coin < min_coin(change_addr_raw, tokens):
            raise SystemExit("Pas assez d'ADA pour le test : utilisez --all.")

    print("\n================ RÉSUMÉ (rien n'est encore envoyé) ================")
    print(f"UTXO utilisés   : {len(utxos)}")
    print(f"ADA en entrée   : {ada(total)}")
    for (pol, name), q in tokens.items():
        print(f"Token           : {q} × {asset_label(pol, name)}")
    print(f"Frais           : {ada(fee)}")
    if a.all:
        print(f"ENVOI TOTAL     : {ada(dest_coin)} + tous les tokens ci-dessus")
    else:
        print(f"ENVOI DE TEST   : {ada(dest_coin)} (ADA seulement)")
        print("Le reste (ADA + tokens) revient sur votre adresse 0 de l'ancien wallet.")
    print(f"Destination     : {a.dest[:14]}…{a.dest[-10:]}")
    print(f"ID de transaction : {txid.hex()}")
    print("====================================================================")
    if a.dry_run:
        print("--dry-run : rien envoyé.")
        return
    if input("Vérifiez la destination caractère par caractère. Tapez ENVOYER pour diffuser : ").strip() != "ENVOYER":
        print("Annulé, rien n'a été envoyé.")
        return
    res = http("POST", a.koios + "/submittx", tx, "application/cbor")
    print("Réponse du réseau :", res.decode(errors="replace").strip())
    print(f"Suivi : https://cardanoscan.io/transaction/{txid.hex()}")


if __name__ == "__main__":
    main()
