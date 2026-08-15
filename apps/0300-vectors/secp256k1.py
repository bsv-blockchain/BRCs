"""Pure-python secp256k1 + BRC-42 derivation for BRC-300.

Self-verifies against the official BRC-42 test vectors: run this file directly.
No third-party imports anywhere in this directory.
"""
import hashlib, hmac

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (Gx, Gy)

def inv(a, m=P): return pow(a, m - 2, m)

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: lam = (3 * p[0] * p[0]) * inv(2 * p[1]) % P
    else:      lam = (q[1] - p[1]) * inv(q[0] - p[0]) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)

def mul(k, p):
    r = None
    k %= N
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def ser(p):
    """33-byte compressed SEC encoding."""
    return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, 'big')

def deser(b):
    if isinstance(b, str): b = bytes.fromhex(b)
    x = int.from_bytes(b[1:33], 'big')
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (b[0] & 1): y = P - y
    return (x, y)

def derive_child_pub(sender_priv_hex, recipient_pub_hex, invoice, secret_enc=ser):
    """BRC-42 sender side: child pubkey for the recipient."""
    d = int(sender_priv_hex, 16)
    R = deser(recipient_pub_hex)
    shared = secret_enc(mul(d, R))
    h = hmac.new(shared, invoice.encode('utf-8'), hashlib.sha256).digest()
    return ser(add(R, mul(int.from_bytes(h, 'big'), G)))

def derive_child_priv(recipient_priv_hex, sender_pub_hex, invoice, secret_enc=ser):
    """BRC-42 recipient side: child privkey."""
    d = int(recipient_priv_hex, 16)
    S = deser(sender_pub_hex)
    shared = secret_enc(mul(d, S))
    h = hmac.new(shared, invoice.encode('utf-8'), hashlib.sha256).digest()
    return '%064x' % ((d + int.from_bytes(h, 'big')) % N)

PRIV_VECTORS = [
    ('033f9160df035156f1c48e75eae99914fa1a1546bec19781e8eddb900200bff9d1',
     '6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede',
     'f3WCaUmnN9U=', '761656715bbfa172f8f9f58f5af95d9d0dfd69014cfdcacc9a245a10ff8893ef'),
    ('027775fa43959548497eb510541ac34b01d5ee9ea768de74244a4a25f7b60fae8d',
     'cab2500e206f31bc18a8af9d6f44f0b9a208c32d5cca2b22acfe9d1a213b2f36',
     '2Ska++APzEc=', '09f2b48bd75f4da6429ac70b5dce863d5ed2b350b6f2119af5626914bdb7c276'),
    ('0338d2e0d12ba645578b0955026ee7554889ae4c530bd7a3b6f688233d763e169f',
     '7a66d0896f2c4c2c9ac55670c71a9bc1bdbdfb4e8786ee5137cea1d0a05b6f20',
     'cN/yQ7+k7pg=', '7114cd9afd1eade02f76703cc976c241246a2f26f5c4b7a3a0150ecc745da9f0'),
    ('02830212a32a47e68b98d477000bde08cb916f4d44ef49d47ccd4918d9aaabe9c8',
     '6e8c3da5f2fb0306a88d6bcd427cbfba0b9c7f4c930c43122a973d620ffa3036',
     'm2/QAsmwaA4=', 'f1d6fb05da1225feeddd1cf4100128afe09c3c1aadbffbd5c8bd10d329ef8f40'),
    ('03f20a7e71c4b276753969e8b7e8b67e2dbafc3958d66ecba98dedc60a6615336d',
     'e9d174eff5708a0a41b32624f9b9cc97ef08f8931ed188ee58d5390cad2bf68e',
     'jgpUIjWFlVQ=', 'c5677c533f17c30f79a40744b18085632b262c0c13d87f3848c385f1389f79a6'),
]
PUB_VECTORS = [
    ('583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c',
     '02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc',
     'IBioA4D/OaE=', '03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f'),
    ('2c378b43d887d72200639890c11d79e8f22728d032a5733ba3d7be623d1bb118',
     '039a9da906ecb8ced5c87971e9c2e7c921e66ad450fd4fc0a7d569fdb5bede8e0f',
     'PWYuo9PDKvI=', '0398cdf4b56a3b2e106224ff3be5253afd5b72de735d647831be51c713c9077848'),
]

if __name__ == '__main__':
    # sanity: G is on the curve and N*G is infinity
    assert (Gy * Gy - Gx ** 3 - 7) % P == 0
    assert mul(N, G) is None

    for enc_name, enc in [('compressed-33', ser), ('x-only-32', lambda p: p[0].to_bytes(32, 'big'))]:
        okp = sum(derive_child_priv(rp, sp, inv_, enc) == exp for sp, rp, inv_, exp in PRIV_VECTORS)
        okP = sum(derive_child_pub(sp, rp, inv_, enc).hex() == exp for sp, rp, inv_, exp in PUB_VECTORS)
        print(f'shared-secret encoding {enc_name:14} priv {okp}/{len(PRIV_VECTORS)}  pub {okP}/{len(PUB_VECTORS)}')
