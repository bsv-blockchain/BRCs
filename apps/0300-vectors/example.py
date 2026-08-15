"""Compute every value printed in BRC-300 Appendix A.

Deterministic, no third-party imports, no network. Run directly to print the
appendix; `verify_vectors.py` reads the printed values back out of 0300.md and
checks them against a fresh run of this file.

Every signature here is real: RFC 6979 deterministic ECDSA over secp256k1,
low-S normalised, DER encoded, verified before it is printed.
"""
import base64
import hashlib
import hmac
import json
import struct

from secp256k1 import N, G, add, mul, ser, deser, inv

# ---------------------------------------------------------------- primitives

def rfc6979_k(priv: int, h: bytes) -> int:
    v = b'\x01' * 32
    k = b'\x00' * 32
    x = priv.to_bytes(32, 'big')
    k = hmac.new(k, v + b'\x00' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        c = int.from_bytes(v, 'big')
        if 1 <= c < N:
            return c
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def der(r: int, s: int) -> bytes:
    def enc(x):
        b = x.to_bytes((x.bit_length() + 8) // 8, 'big') or b'\x00'
        return b'\x02' + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b'\x30' + bytes([len(body)]) + body


def undec(b, i):
    assert b[i] == 0x02
    ln = b[i + 1]
    return int.from_bytes(b[i + 2:i + 2 + ln], 'big'), i + 2 + ln


def sign(priv: int, msg: bytes) -> bytes:
    h = hashlib.sha256(msg).digest()
    z = int.from_bytes(h, 'big')
    k = rfc6979_k(priv, h)
    r = mul(k, G)[0] % N
    s = (inv(k, N) * (z + r * priv)) % N
    if s > N // 2:
        s = N - s
    return der(r, s)


def verify(pub, msg: bytes, sig: bytes) -> bool:
    z = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    r, i = undec(sig, 2)
    s, _ = undec(sig, i)
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = inv(s, N)
    p = add(mul(z * w % N, G), mul(r * w % N, pub))
    return p is not None and p[0] % N == r


def jcs(o) -> str:
    """RFC 8785 canonicalization, sufficient for the ASCII data used here."""
    if isinstance(o, dict):
        return '{' + ','.join(json.dumps(k) + ':' + jcs(v) for k, v in sorted(o.items())) + '}'
    if isinstance(o, list):
        return '[' + ','.join(jcs(v) for v in o) + ']'
    if isinstance(o, bool):
        return 'true' if o else 'false'
    if o is None:
        return 'null'
    if isinstance(o, int):
        return str(o)
    return json.dumps(o, ensure_ascii=False)


def varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def brc43_sign_key(signer_priv: int, protocol: str, key_id: str):
    """BRC-3/BRC-42/BRC-43 signing key for counterparty `anyone`.

    Counterparty `anyone` is private key 1, so the ECDH shared secret is the
    signer's own public key. Returns (childPriv, childPub) and asserts that the
    two sides agree, which is what makes the signature publicly verifiable.
    """
    invoice = f'2-{protocol}-{key_id}'
    shared = ser(mul(signer_priv, G))
    off = int.from_bytes(hmac.new(shared, invoice.encode(), hashlib.sha256).digest(), 'big')
    child_priv = (signer_priv + off) % N
    child_pub = add(mul(signer_priv, G), mul(off, G))
    assert ser(child_pub) == ser(mul(child_priv, G))
    return invoice, child_priv, child_pub


def brc43_verify_key(signer_pub_hex: str, protocol: str, key_id: str):
    """The same child public key, derived by a verifier holding only the signer's identity key."""
    invoice = f'2-{protocol}-{key_id}'
    shared = bytes.fromhex(signer_pub_hex)          # 1 * signerPub
    off = int.from_bytes(hmac.new(shared, invoice.encode(), hashlib.sha256).digest(), 'big')
    return add(deser(signer_pub_hex), mul(off, G))


def key(label: str):
    d = int.from_bytes(hashlib.sha256(('BRC-300 EXAMPLE / ' + label).encode()).digest(), 'big') % N
    return d, ser(mul(d, G)).hex()


PROTOCOL = 'wallet choice'
OUT = {}


def emit(section, label, value):
    OUT.setdefault(section, []).append((label, value))
    return value


# ------------------------------------------------------------ A.1 identifiers

TYPE_STRINGS = [
    'wallet choice offer v1',
    'wallet choice receipt v1',
    'wallet choice campaign v1',
    'wallet choice settlement v1',
]
TYPE_IDS = {}
for t in TYPE_STRINGS:
    TYPE_IDS[t] = base64.b64encode(hashlib.sha256(t.encode()).digest()).decode()
    emit('A.1', t, TYPE_IDS[t])

# ------------------------------------------------------------ parties

house_priv, house_pub = key('auction house')
sponsor_priv = int('c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc', 16)
sponsor_pub = ser(mul(sponsor_priv, G)).hex()
rival_priv = int('0badc0de00112233445566778899aabbccddeeff00112233445566778899aabb', 16)
rival_pub = ser(mul(rival_priv, G)).hex()
site_priv, site_pub = key('example.com certifier')
new_priv, new_pub = key('newcomer identity')

for lbl, pub in [('auction house', house_pub), ('sponsor (Nexus Labs)', sponsor_pub),
                 ('rival sponsor', rival_pub), ('site example.com', site_pub),
                 ('newcomer', new_pub)]:
    emit('A.0', lbl, pub)

# ------------------------------------------------------------ A.2 batch

CAMPAIGN_REF = hashlib.sha256(b'nexus onboarding autumn').digest()
BOUNTY = 21000
RIVAL_REF = hashlib.sha256(b'rival wallet spring').digest()
RIVAL_BOUNTY = 12000


SALT_TAG = b'wallet choice salt'


def salt(priv: int, ref: bytes, i: int) -> bytes:
    """Section 4.5. Tagged, so it cannot collide with the voucher key of 7.1."""
    return hashlib.sha256(SALT_TAG + priv.to_bytes(32, 'big') + ref + struct.pack('<I', i)).digest()


def voucher_key(priv: int, ref: bytes, i: int) -> bytes:
    """Section 7.1, BRC-227 section 2's untagged derivation."""
    return hashlib.sha256(priv.to_bytes(32, 'big') + ref + struct.pack('<I', i)).digest()


def commit(sats: int, s: bytes) -> bytes:
    return hashlib.sha256(struct.pack('>Q', sats) + s).digest()


emit('A.2', 'campaignRef', CAMPAIGN_REF.hex())
SALTS, COMMITS = {}, {}
for i in (0, 1):
    SALTS[i] = salt(sponsor_priv, CAMPAIGN_REF, i)
    COMMITS[i] = commit(BOUNTY, SALTS[i])
    emit('A.2', f'salt_{i}', SALTS[i].hex())
    emit('A.2', f'commitment_{i}', COMMITS[i].hex())

# The whole of what the tag buys: the published salt is not the money key.
for _i in (0, 1):
    assert salt(sponsor_priv, CAMPAIGN_REF, _i) != voucher_key(sponsor_priv, CAMPAIGN_REF, _i)
emit('A.2', 'voucherKey_0 (never published)', voucher_key(sponsor_priv, CAMPAIGN_REF, 0).hex())

RIVAL_SALT = salt(rival_priv, RIVAL_REF, 0)
RIVAL_COMMIT = commit(RIVAL_BOUNTY, RIVAL_SALT)
emit('A.2', 'rival campaignRef', RIVAL_REF.hex())
emit('A.2', 'rival salt_0', RIVAL_SALT.hex())
emit('A.2', 'rival commitment_0', RIVAL_COMMIT.hex())

# ------------------------------------------------------------ A.3 negative

NEG = commit(BOUNTY - 1, SALTS[0])
emit('A.3', 'commitment at 20999', NEG.hex())
assert NEG != COMMITS[0]

# ------------------------------------------------------------ A.4 offer signature

AUCTION_ID = base64.b64encode(hashlib.sha256(b'BRC-300 example auction 1').digest()).decode()
emit('A.4', 'auctionId', AUCTION_ID)

offer = {
    'protocol': 'metanet-connect-offer',
    'version': 1,
    'auctionId': AUCTION_ID,
    'slot': 0,
    'house': house_pub,
    'sponsor': sponsor_pub,
    'wallet': {
        'name': 'Nexus',
        'vendor': 'Nexus Labs',
        'icon': 'https://nexus.example/icon.png',
        'description': 'Built for people who have never used Bitcoin',
        'selfCustody': True,
        'install': {'android': 'https://play.google.com/store/apps/details?id=app.nexus'},
    },
    'predicate': {'all': [{'platform': ['android', 'ios']}]},
    'bountyCommitment': COMMITS[0].hex(),
    'commitmentIndex': 0,
    'claim': 'https://nexus.example/.well-known/metanet-connect/claim',
    'maturityBlocks': 144,
    'expiresHeight': 892150,
}
offer_canon = jcs(offer).encode()
offer_inv, offer_sk, offer_pk = brc43_sign_key(house_priv, PROTOCOL, 'offer')
offer_sig = sign(offer_sk, offer_canon)
assert verify(offer_pk, offer_canon, offer_sig)
assert ser(brc43_verify_key(house_pub, PROTOCOL, 'offer')) == ser(offer_pk)
emit('A.4', 'invoice', offer_inv)
emit('A.4', 'signing pubkey', ser(offer_pk).hex())
emit('A.4', 'canonical form', offer_canon.decode())
emit('A.4', 'signature', offer_sig.hex())

tampered = dict(offer, maturityBlocks=6)
assert not verify(offer_pk, jcs(tampered).encode(), offer_sig)

# ------------------------------------------------------------ A.5 connect receipt

CERT_TYPE = TYPE_IDS['wallet choice receipt v1']
SERIAL = base64.b64encode(hashlib.sha256(b'BRC-300 example receipt serial').digest()).decode()
REV_TXID = hashlib.sha256(b'BRC-300 example revocation tx').hexdigest()
REV_VOUT = 0

# BRC-52 signs the encrypted field values as Base64 strings. Encryption itself is
# BRC-52/BRC-2 and is not re-derived here; these ciphertexts are opaque inputs.
FIELDS = {
    'auctionId': base64.b64encode(hashlib.sha256(b'ct auctionId').digest()).decode(),
    'height': base64.b64encode(hashlib.sha256(b'ct height').digest()).decode(),
    'origin': base64.b64encode(hashlib.sha256(b'ct origin').digest()).decode(),
    'sponsor': base64.b64encode(hashlib.sha256(b'ct sponsor').digest()).decode(),
    'walletVendor': base64.b64encode(hashlib.sha256(b'ct walletVendor').digest()).decode(),
}


def cert_binary(fields=FIELDS) -> bytes:
    b = base64.b64decode(CERT_TYPE) + base64.b64decode(SERIAL)
    b += bytes.fromhex(new_pub) + bytes.fromhex(site_pub)
    b += bytes.fromhex(REV_TXID) + varint(REV_VOUT)
    b += varint(len(fields))
    for k in sorted(fields):
        b += varint(len(k)) + k.encode() + varint(len(fields[k])) + fields[k].encode()
    return b


cert_inv, cert_sk, cert_pk = brc43_sign_key(
    site_priv, 'certificate signature', f'{CERT_TYPE} {SERIAL}')
cert_pre = cert_binary()
cert_sig = sign(cert_sk, cert_pre)
assert verify(cert_pk, cert_pre, cert_sig)
assert ser(brc43_verify_key(site_pub, 'certificate signature',
                            f'{CERT_TYPE} {SERIAL}')) == ser(cert_pk)
emit('A.5', 'type', CERT_TYPE)
emit('A.5', 'serialNumber', SERIAL)
emit('A.5', 'revocationOutpoint', f'{REV_TXID}.{REV_VOUT}')
emit('A.5', 'invoice', cert_inv)
emit('A.5', 'signing pubkey', ser(cert_pk).hex())
emit('A.5', 'preimage', cert_pre.hex())
emit('A.5', 'signature', cert_sig.hex())

# negative: swap one field value, keep the signature
bad_fields = dict(FIELDS, origin=base64.b64encode(hashlib.sha256(b'ct evil origin').digest()).decode())
assert not verify(cert_pk, cert_binary(bad_fields), cert_sig)

# ------------------------------------------------------------ A.6 claim signature

claim = {
    'protocol': 'metanet-connect-claim',
    'version': 1,
    'auctionId': AUCTION_ID,
    'payTo': new_pub,
}
claim_canon = jcs(claim).encode()
claim_inv, claim_sk, claim_pk = brc43_sign_key(new_priv, PROTOCOL, f'claim {AUCTION_ID}')
claim_sig = sign(claim_sk, claim_canon)
assert verify(claim_pk, claim_canon, claim_sig)
emit('A.6', 'invoice', claim_inv)
emit('A.6', 'signing pubkey', ser(claim_pk).hex())
emit('A.6', 'canonical form', claim_canon.decode())
emit('A.6', 'signature', claim_sig.hex())

# ------------------------------------------------------------ A.7 retention proof

retention = {
    'protocol': 'metanet-connect-retention',
    'version': 1,
    'auctionId': AUCTION_ID,
    'subject': new_pub,
    'retentionHeight': 896460,
    'transactedWithThirdParty': True,
}
ret_canon = jcs(retention).encode()
ret_inv, ret_sk, ret_pk = brc43_sign_key(new_priv, PROTOCOL, f'retention {AUCTION_ID}')
ret_sig = sign(ret_sk, ret_canon)
assert verify(ret_pk, ret_canon, ret_sig)
emit('A.7', 'invoice', ret_inv)
emit('A.7', 'signing pubkey', ser(ret_pk).hex())
emit('A.7', 'canonical form', ret_canon.decode())
emit('A.7', 'signature', ret_sig.hex())

# the one that earns its place: flip the bit, keep the signature
flipped = dict(retention, transactedWithThirdParty=False)
assert not verify(ret_pk, jcs(flipped).encode(), ret_sig)
emit('A.7', 'canonical form, bit flipped', jcs(flipped))

# claim and retention keys MUST differ: that is why section 6.3.2 prefixes the key ID
assert ser(claim_pk) != ser(ret_pk)

if __name__ == '__main__':
    for section in sorted(OUT):
        print(f'## {section}')
        for label, value in OUT[section]:
            print(f'  {label:30} {value}')
        print()
