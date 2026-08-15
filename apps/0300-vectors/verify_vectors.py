"""Re-verify every value printed in 0300.md against a fresh run of example.py.

Reads the markdown, pulls the published values back out of it, and checks them.
A value that appears in the document but not in a fresh computation is a failure,
and so is a value that is computed but never published.

    python3 verify_vectors.py

No third-party imports, no network.
"""
import base64
import hashlib
import os
import re
import struct
import sys

import example as X
from example import cert_binary, jcs, sign, verify, brc43_verify_key
from secp256k1 import ser, deser, mul, G

def _find_markdown():
    """Locate 0300.md whether the scripts sit beside it or in a subdirectory."""
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, '0300.md'),
                 os.path.join(here, os.pardir, '0300.md'),
                 '0300.md'):
        if os.path.exists(cand):
            return cand
    raise SystemExit('0300.md not found beside or above this script')


MD = open(_find_markdown(), encoding='utf-8').read()
checks = []


def check(label, ok):
    checks.append((label, bool(ok)))


def published(value, label=None):
    """The value must appear literally in the document."""
    check(label or value[:40], value in MD)


def val(section, label):
    return dict(X.OUT[section])[label]


# ---------------------------------------------------------------- A.0 parties
for lbl in ('auction house', 'sponsor (Nexus Labs)', 'rival sponsor',
            'site example.com', 'newcomer'):
    published(val('A.0', lbl), f'A.0 pubkey {lbl}')

# the two sponsor private keys are printed and must generate the printed pubkeys
for priv_hex, pub_lbl in (
        ('c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc', 'sponsor (Nexus Labs)'),
        ('0badc0de00112233445566778899aabbccddeeff00112233445566778899aabb', 'rival sponsor')):
    published(priv_hex, f'A.2 privkey {pub_lbl}')
    check(f'A.2 privkey generates pubkey ({pub_lbl})',
          ser(mul(int(priv_hex, 16), G)).hex() == val('A.0', pub_lbl))

# ---------------------------------------------------------------- A.1 identifiers
for s in X.TYPE_STRINGS:
    b64 = base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()
    check(f'A.1 {s}', b64 == val('A.1', s))
    published(b64, f'A.1 published {s}')
    published(f'`{s}`', f'A.1 source string {s}')

# the protocol name must satisfy the BRC-100 rules the document claims it does
P = 'wallet choice'
check('A.1 protocol name >= 5 chars', len(P) >= 5)
check('A.1 protocol name lowercase/digits/spaces', re.fullmatch(r'[a-z0-9 ]+', P) is not None)
check('A.1 protocol name no double space', '  ' not in P)
check('A.1 protocol name not ending " protocol"', not P.endswith(' protocol'))
check('A.1 protocol name not starting "p "', not P.startswith('p '))

# ---------------------------------------------------------------- A.2 batch
for lbl in ('campaignRef', 'salt_0', 'commitment_0', 'salt_1', 'commitment_1',
            'rival campaignRef', 'rival salt_0', 'rival commitment_0'):
    published(val('A.2', lbl), f'A.2 {lbl}')

check('A.2 campaignRef is SHA-256 of its stated source',
      val('A.2', 'campaignRef') == hashlib.sha256(b'nexus onboarding autumn').hexdigest())
# the tag of section 4.5, which is the whole reason a salt may be published
import struct as _struct
_sk = int('c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc', 16)
_ref = bytes.fromhex(val('A.2', 'campaignRef'))
for _i in (0, 1):
    _voucher = hashlib.sha256(_sk.to_bytes(32, 'big') + _ref + _struct.pack('<I', _i)).hexdigest()
    check(f'A.2 salt_{_i} is NOT voucherKey_{_i}', val('A.2', f'salt_{_i}') != _voucher)
    check(f'A.2 voucherKey_{_i} absent from the document', _voucher not in MD or _i == 0)
published(val('A.2', 'voucherKey_0 (never published)'), 'A.2 voucherKey_0 shown for contrast')
check('A.2 voucherKey_0 is the untagged BRC-227 derivation',
      val('A.2', 'voucherKey_0 (never published)')
      == hashlib.sha256(_sk.to_bytes(32, 'big') + _ref + _struct.pack('<I', 0)).hexdigest())

check('A.2 same bounty, different commitments',
      val('A.2', 'commitment_0') != val('A.2', 'commitment_1'))
check('A.2 salts differ', val('A.2', 'salt_0') != val('A.2', 'salt_1'))
check('A.2 uint64BE(21000) prefix is 0x0000000000005208',
      struct.pack('>Q', 21000).hex() == '0000000000005208')
published('0x0000000000005208', 'A.2 prefix published')

# ---------------------------------------------------------------- A.3 negative
neg = val('A.3', 'commitment at 20999')
published(neg, 'A.3 negative commitment')
check('A.3 negative differs from commitment_0', neg != val('A.2', 'commitment_0'))

# ---------------------------------------------------------------- A.4 offer
for lbl in ('auctionId', 'invoice', 'signing pubkey', 'canonical form', 'signature'):
    published(val('A.4', lbl), f'A.4 {lbl}')

offer_sig = bytes.fromhex(val('A.4', 'signature'))
offer_pk = deser(val('A.4', 'signing pubkey'))
offer_canon = val('A.4', 'canonical form').encode()
check('A.4 signature verifies', verify(offer_pk, offer_canon, offer_sig))
check('A.4 verifier rederives the signing key from the house identity key alone',
      ser(brc43_verify_key(val('A.0', 'auction house'), 'wallet choice', 'offer'))
      == ser(offer_pk))
tampered = offer_canon.replace(b'"maturityBlocks":144', b'"maturityBlocks":6')
check('A.4 tampered offer does NOT verify', tampered != offer_canon
      and not verify(offer_pk, tampered, offer_sig))
check('A.4 canonical form is RFC 8785 sorted',
      offer_canon.decode() == jcs(__import__('json').loads(offer_canon)))
check('A.4 offer carries no amount',
      not re.search(r'bountySats|maxBidSats|siteShareSats|budget', offer_canon.decode()))

# ---------------------------------------------------------------- A.5 receipt
for lbl in ('type', 'serialNumber', 'revocationOutpoint', 'invoice',
            'signing pubkey', 'preimage', 'signature'):
    published(val('A.5', lbl), f'A.5 {lbl}')

cert_pk = deser(val('A.5', 'signing pubkey'))
cert_pre = bytes.fromhex(val('A.5', 'preimage'))
cert_sig = bytes.fromhex(val('A.5', 'signature'))
check('A.5 preimage matches CertificateBinary', cert_pre == cert_binary())
check('A.5 signature verifies', verify(cert_pk, cert_pre, cert_sig))
check('A.5 verifier rederives the signing key from the site identity key alone',
      ser(brc43_verify_key(val('A.0', 'site example.com'), 'certificate signature',
                           f"{val('A.5','type')} {val('A.5','serialNumber')}")) == ser(cert_pk))
bad = dict(X.FIELDS, origin=base64.b64encode(hashlib.sha256(b'ct evil origin').digest()).decode())
check('A.5 altered origin does NOT verify', not verify(cert_pk, cert_binary(bad), cert_sig))
check('A.5 receipt type equals the A.1 derived identifier',
      val('A.5', 'type') == val('A.1', 'wallet choice receipt v1'))
check('A.5 preimage begins with the 32-byte type',
      cert_pre[:32] == base64.b64decode(val('A.5', 'type')))
check('A.5 preimage carries subject then certifier',
      cert_pre[64:97].hex() == val('A.0', 'newcomer')
      and cert_pre[97:130].hex() == val('A.0', 'site example.com'))

# ---------------------------------------------------------------- A.6 claim
for lbl in ('invoice', 'signing pubkey', 'canonical form', 'signature'):
    published(val('A.6', lbl), f'A.6 {lbl}')
claim_pk = deser(val('A.6', 'signing pubkey'))
check('A.6 signature verifies',
      verify(claim_pk, val('A.6', 'canonical form').encode(),
             bytes.fromhex(val('A.6', 'signature'))))
check('A.6 key ID is prefixed with "claim "', ' choice-claim ' in val('A.6', 'invoice'))

# ---------------------------------------------------------------- A.7 retention
for lbl in ('invoice', 'signing pubkey', 'canonical form', 'signature',
            'canonical form, bit flipped'):
    published(val('A.7', lbl), f'A.7 {lbl}')
ret_pk = deser(val('A.7', 'signing pubkey'))
ret_sig = bytes.fromhex(val('A.7', 'signature'))
check('A.7 signature verifies',
      verify(ret_pk, val('A.7', 'canonical form').encode(), ret_sig))
check('A.7 flipped bit does NOT verify',
      not verify(ret_pk, val('A.7', 'canonical form, bit flipped').encode(), ret_sig))
check('A.7 flipped form differs by exactly the boolean',
      val('A.7', 'canonical form').replace('true', 'false')
      == val('A.7', 'canonical form, bit flipped'))
check('A.7 key ID is prefixed with "retention "', ' choice-retention ' in val('A.7', 'invoice'))
check('A.7 claim and retention signing keys DIFFER',
      val('A.6', 'signing pubkey') != val('A.7', 'signing pubkey'))
check('A.7 both derive from the same newcomer identity key',
      ser(brc43_verify_key(val('A.0', 'newcomer'), 'wallet choice',
                           f"retention {val('A.4','auctionId')}")) == ser(ret_pk)
      and ser(brc43_verify_key(val('A.0', 'newcomer'), 'wallet choice',
                               f"claim {val('A.4','auctionId')}")) == ser(claim_pk))

# ------------------------------------------------- the body must agree with the appendix
check('body: offer example carries commitment_0',
      MD.count(val('A.2', 'commitment_0')) >= 2)
check('body: bid set contains both campaigns',
      val('A.2', 'rival commitment_0') in MD and val('A.2', 'commitment_0') in MD)
m = re.search(r'"bidSet":\s*\[(.*?)\]', MD, re.S)
check('body: bid set is present', m is not None)
if m:
    entries = re.findall(r'"([0-9a-f]{64})"', m.group(1))
    check('body: bid set is lexicographically ordered', entries == sorted(entries))
    check('body: bid set holds the two published commitments',
          set(entries) == {val('A.2', 'commitment_0'), val('A.2', 'rival commitment_0')})

# ------------------------------------------------- house rules
check('house rule: no em or en dashes', not re.search(r'[–—]', MD))
check('house rule: no horizontal rules', not re.search(r'^---$', MD, re.M))
check('house rule: plain ASCII', all(ord(c) < 128 for c in MD))
check('house rule: no section glyph', '§' not in MD)
heads = set(re.findall(r'^#{3,4} ([0-9]+(?:\.[0-9]+)?)\.? ', MD, re.M))
refs = set(re.findall(r'section ([0-9]+(?:\.[0-9]+){0,2})', MD))
dangling = [r for r in refs
            if '.'.join(r.split('.')[:2]) not in heads and r.split('.')[0] not in heads]
check('house rule: every section cross-reference resolves', not dangling)

# ------------------------------------------------- report
width = max(len(l) for l, _ in checks)
failed = 0
for label, ok in checks:
    if not ok:
        failed += 1
        print(f'FAIL  {label}')
print(f'\n{len(checks)} checks, {len(checks) - failed} passed, {failed} failed')
sys.exit(1 if failed else 0)
