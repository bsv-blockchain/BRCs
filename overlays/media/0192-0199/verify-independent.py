"""Independent frozen-wire oracle: Python CBOR, cryptography, BitcoinX.

Synthetic local chain only. No network, wallet, broadcast or mainnet claims.
"""

import base64, gzip, hashlib, hmac, json, importlib.util
from pathlib import Path
import cbor2
from bitcoinx import PublicKey, Tx, TxInputContext, InterpreterLimits, MinerPolicy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).parent
manifest = json.loads((HERE / "wire-manifest.json").read_text())
archive = (HERE / manifest["archive"]).read_bytes()
sha = lambda x: hashlib.sha256(x).digest()
assert sha(archive).hex() == manifest["sha256"]
raw = gzip.decompress(archive)
assert len(raw) == manifest["decodedBytes"]
v = json.loads(raw)
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
spec = importlib.util.spec_from_file_location("beef_oracle", HERE / "beef-oracle.py")
beef_oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(beef_oracle)


def canonical(x):
    if isinstance(x, dict):
        return (
            "{"
            + ",".join(
                canonical(k) + ":" + canonical(x[k])
                for k in sorted(x, key=lambda k: k.encode("utf-16-be"))
            )
            + "}"
        )
    if isinstance(x, list):
        return "[" + ",".join(map(canonical, x)) + "]"
    if isinstance(x, float):
        assert x.is_integer()
        x = int(x)
    if isinstance(x, int) and not isinstance(x, bool):
        assert abs(x) <= 9007199254740991
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def undiag(x):
    if isinstance(x, dict):
        if list(x) == ["$bytes"]:
            return bytes.fromhex(x["$bytes"])
        return {k: undiag(y) for k, y in x.items()}
    if isinstance(x, list):
        return list(map(undiag, x))
    return x


def b64(x):
    return base64.b64encode(x).decode()


def un64(x):
    decoded = base64.b64decode(x, validate=True)
    assert b64(decoded) == x
    return decoded


def pub(scalar):
    return (
        ec.derive_private_key(scalar, ec.SECP256K1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    )


def shared(scalar, other):
    return (
        PublicKey.from_bytes(other)
        .multiply(scalar.to_bytes(32, "big"))
        .to_bytes(compressed=True)
    )


def child(scalar, other, invoice):
    offset = int.from_bytes(
        hmac.new(shared(scalar, other), invoice.encode(), hashlib.sha256).digest(),
        "big",
    )
    return (scalar + offset) % order


scalars = {bytes.fromhex(a["identity"]): a["scalar"] for a in v["actors"].values()}


def verify77(message, sig, expected):
    assert sig[:4] == bytes.fromhex("42423301") and sig[37] == 0
    sender = sig[4:37]
    assert sender == expected
    invoice = "2-message signing-" + b64(sig[38:70])
    # The public 'anyone' counterparty is scalar 1: no signer secret is needed.
    offset = hmac.new(sender, invoice.encode(), hashlib.sha256).digest()
    derived = PublicKey.from_bytes(sender).add(offset).to_bytes(compressed=True)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), derived).verify(
        sig[70:], message, ec.ECDSA(hashes.SHA256())
    )


def verify_http(message, sig, sender, receiver, keyid):
    derived = child(scalars[sender], receiver, "2-auth message signature-" + keyid)
    ec.derive_private_key(derived, ec.SECP256K1()).public_key().verify(
        sig, message, ec.ECDSA(hashes.SHA256())
    )


def packet_pre(t, b):
    return ("BRC-OUTPUT/1/" + t + "\0").encode() + canonical(b).encode()


def lch_pre(t, b):
    return ("LCH/" + t + "/1\0").encode() + cbor2.dumps(b, canonical=True)


digests = json.loads((HERE / "digest-vectors.json").read_text())
registry = json.loads((HERE / "registry.json").read_text())
assert [row["domain"] for row in digests["vectors"]] == registry["digestDomains"]
assert canonical(digests["body"]) == digests["canonical"]
for row in digests["vectors"]:
    message = packet_pre(row["domain"], digests["body"])
    assert message.hex() == row["preimage"]
    assert sha(message).hex() == row["sha256"]


for p in v["packets"]:
    pre = packet_pre(p["type"], p["body"])
    assert pre.hex() == p["preimage"]
    assert sha(pre).hex() == p["id"]
    verify77(pre, un64(p["signature"]), bytes.fromhex(p["signer"]))
for item in v["lch"]:
    obj = undiag(item["object"])
    encoded = cbor2.dumps(obj, canonical=True)
    assert encoded.hex() == item["cbor"]
    assert cbor2.loads(encoded) == obj
    pre = lch_pre(item["type"], obj["body"])
    assert sha(pre).hex() == item["id"]
    for sig in obj["signatures"]:
        verify77(pre, sig, bytes.fromhex(item["signer"]))


def varint(n):
    if n < 0:
        n += 1 << 64
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 4294967295:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def sized(x):
    if isinstance(x, str):
        x = x.encode()
    return varint(len(x)) + x


def payload(t):
    p = un64(t["requestId"])
    if t["kind"] == "request":
        p += (
            sized(t["method"])
            + sized(t["path"])
            + (sized(t["query"]) if t["query"] else varint(-1))
        )
    else:
        p += varint(t["status"])
    headers = {
        k: x
        for k, x in t["headers"].items()
        if k == "authorization"
        or (t["kind"] == "request" and k == "content-type")
        or (k.startswith("x-bsv-") and not k.startswith("x-bsv-auth-"))
    }
    p += (
        varint(len(headers))
        + b"".join(sized(k) + sized(headers[k]) for k in sorted(headers))
        + sized(un64(t["body"]))
    )
    return p


for t in v["http"]:
    p = payload(t)
    assert p.hex() == t["payload"]
    assert len(un64(t["body"])) <= 4194304
    verify_http(
        p,
        bytes.fromhex(t["signature"]),
        bytes.fromhex(v["actors"][t["sender"]]["identity"]),
        bytes.fromhex(v["actors"][t["receiver"]]["identity"]),
        t["nonce"] + " " + t["yourNonce"],
    )
h = v["handshake"]
verify_http(
    bytes.fromhex(h["data"]),
    bytes.fromhex(h["initialResponse"]["signature"]),
    bytes.fromhex(h["initialResponse"]["identityKey"]),
    bytes.fromhex(h["initialRequest"]["identityKey"]),
    h["initialRequest"]["initialNonce"] + " " + h["initialResponse"]["initialNonce"],
)

roots = {(h["height"], h["merkleRoot"]) for h in v["headers"][:2]}
for txid, item in v["transactions"].items():
    txs, placements = beef_oracle.parse_beef(un64(item["beef"]), txid, roots)
    assert txs[txid].to_hex() == item["raw"]
    for ident, tx in txs.items():
        if ident not in placements:
            assert all(
                i.prev_hash[::-1].hex() in txs for i in tx.inputs
            ), "unresolved dependency"
beef_oracle.parse_beef(
    un64(v["mined"]["blockEvidence"]["beef"]), v["mined"]["txid"], roots
)

# Independently execute every non-checkpoint input from raw transactions.
limits = InterpreterLimits(
    MinerPolicy(1048576, 128, 128 * 1024 * 1024, 1000000, 8),
    is_genesis_enabled=True,
    is_consensus=False,
)
inputs = 0
for txid, item in v["transactions"].items():
    tx = Tx.from_hex(item["raw"])
    assert tx.hex_hash() == txid
    if item["label"] == "synthetic chain checkpoint":
        continue
    total = 0
    for i, s in enumerate(item["sources"]):
        previous = Tx.from_hex(v["transactions"][s["txid"]]["raw"])
        assert tx.inputs[i].prev_hash == previous.hash()
        assert tx.inputs[i].prev_idx == s["index"]
        assert TxInputContext(tx, i, previous.outputs[s["index"]]).verify_input(
            limits, is_utxo_after_genesis=True
        )
        total += previous.outputs[s["index"]].value
        inputs += 1
    assert total >= sum(o.value for o in tx.outputs)
for h in v["headers"]:
    raw = bytes.fromhex(h["raw"])
    assert sha(sha(raw))[::-1].hex() == h["hash"]
    assert raw[36:68][::-1].hex() == h["merkleRoot"]
    assert int.from_bytes(raw[72:76], "little") == 0x207FFFFF
    assert int(h["hash"], 16) <= (0x7FFFFF << 232)


def decrypt78(raw, buyer):
    assert raw[:4] == bytes.fromhex("42421033")
    sender = raw[4:37]
    recipient = raw[37:70]
    assert recipient == pub(buyer)
    invoice = "2-message encryption-" + b64(raw[70:102])
    a = child(scalars[sender], recipient, invoice)
    b = child(buyer, sender, invoice)
    key = shared(a, pub(b))[1:]
    cipher = raw[102:]
    return AESGCM(key).decrypt(cipher[:32], cipher[32:], None)


header = undiag(v["header"]["object"])
assert cbor2.dumps(header, canonical=True).hex() == v["header"]["cbor"]
asset = header["asset"]
assert sha(lch_pre("asset", asset)).hex() == v["asset"]["id"]
for a in v["acquisitions"]:
    context = undiag(a["context"])
    cb = cbor2.dumps(context, canonical=True)
    assert cb.hex() == a["contextCBOR"]
    assert len(cb) <= 2097152
    lic = context["license"]
    req = undiag(a["request"])
    offer = next(x["object"] for x in context["evidence"] if x["type"] == "offer")
    outer = a.get("prepare", a.get("acquire"))
    buyer = v["actors"][a["buyer"]]["scalar"]
    seller = bytes.fromhex(v["actors"]["seller"]["identity"])
    assert cbor2.dumps(req, canonical=True) == un64(outer["request"])
    assert sha(lch_pre("license-request", req["body"])).hex() == outer["requestId"]
    assert lic["body"]["subject"] == pub(buyer)
    assert lic["body"]["requestId"] == bytes.fromhex(outer["requestId"])
    assert lic["body"]["offerId"] == sha(lch_pre("offer", offer["body"]))
    assert req["body"]["acceptedPolicyDigest"] == sha(offer["body"]["policy"]["inline"])
    assert lic["body"]["agreement"]["digest"] == sha(lic["body"]["agreement"]["inline"])
    st = json.loads(context["settlement"])
    typ = (
        "lch-covenant-settlement"
        if a["mode"] == "listing-covenant"
        else "lch-lookup-settlement"
    )
    verify77(packet_pre(typ, st["body"]), un64(st["signature"]), seller)
    assert lic["body"]["fulfillments"][0]["receiptIds"] == [
        sha(packet_pre(typ, st["body"]))
    ]
    assert st["body"]["buyer"] == pub(buyer).hex()
    assert st["body"]["requestId"] == outer["requestId"]
    if a["mode"] == "listing-covenant":
        tx = Tx.from_hex(v["transactions"][a["submit"]["txid"]]["raw"])
        old = Tx.from_hex(v["transactions"][outer["listing"]["txid"]]["raw"])
        terms = a["terms"]["body"]
        assert tx.inputs[0].prev_hash == old.hash()
        assert tx.outputs[0].value == old.outputs[0].value + 1001
        assert tx.outputs[0].script_pubkey == old.outputs[0].script_pubkey
        receipt = (
            bytes.fromhex("006a4ca7524f534c0101")
            + bytes.fromhex(sha(packet_pre("sale-listing", v["descriptor"])).hex())
            + bytes.fromhex(terms["acquisitionId"])
            + bytes.fromhex(terms["requestDigest"])
            + pub(buyer)
            + bytes.fromhex(v["descriptor"]["termsDigest"])
        )
        assert (
            tx.outputs[1].script_pubkey.to_bytes() == receipt
            and tx.outputs[1].value == 1
        )
        purchase_preimage = list(tx.inputs[0].script_sig.ops())[0]
        purchase_commitment = sha(sha(purchase_preimage)).hex()
        assert st["body"]["purchaseCommitment"] == purchase_commitment
        assert a["envelope"]["result"]["purchaseCommitment"] == purchase_commitment
        assert a["envelope"]["result"]["potatoes"]["body"]["purchaseCommitment"] == purchase_commitment
        assert "buyer" not in offer["body"]["payment"]["pricing"]["requirements"][0]
    else:
        inv = (
            "2-3241645161d8-"
            + a["challenge"]["derivationPrefix"]
            + " "
            + a["paymentHeader"]["derivationSuffix"]
        )
        derived = child(scalars[seller], pub(buyer), inv)
        pkh = hashlib.new("ripemd160", sha(pub(derived))).digest()
        script = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        assert script.hex() == a["expectedPaymentScript"]
        tx = Tx.from_hex(v["transactions"][a["result"]["funding"]["txid"]]["raw"])
        assert (
            sum(
                o.value == 1001 and o.script_pubkey.to_bytes() == script
                for o in tx.outputs
            )
            == 1
        )
    grants = lic["body"]["keyGrants"]
    enc = asset["representation"]["encryption"]
    assert len(grants) == len(enc["keyPeriods"])
    assert lic["body"]["segmentSelection"]["ranges"] == [[0, enc["segmentCount"]]]
    plain = decrypt78(grants[0]["payload"], buyer)
    key = plain[32:]
    keyid = sha(b"LCH key id v1\0" + key)
    assert keyid == plain[:32] == grants[0]["keyId"] == enc["keyPeriods"][0]["keyId"]
    ciphertext = bytes.fromhex(v["content"]["ciphertext"])
    assert sha(ciphertext) == asset["representation"]["ciphertextDigest"]
    out = b""
    for i in range(enc["segmentCount"]):
        u = lambda n: n.to_bytes(8, "big")
        iv = enc["noncePrefix"] + u(i)
        aad = (
            b"LCH A256GCM segmented v1\0"
            + enc["encryptionId"]
            + u(i)
            + u(enc["segmentCount"])
            + u(enc["plaintextLength"])
            + keyid
        )
        record = ciphertext[
            i * (enc["segmentSize"] + 16) : (i + 1) * (enc["segmentSize"] + 16)
        ]
        out += AESGCM(key).decrypt(iv, record, aad)
        try:
            AESGCM(key).decrypt(iv, record[:-1] + bytes([record[-1] ^ 1]), aad)
        except Exception:
            pass
        else:
            raise AssertionError("altered GCM tag accepted")
    assert out.hex() == v["content"]["plaintext"]
print(
    json.dumps(
        {
            "independentPackets": len(v["packets"]),
            "independentCBORSignatures": len(v["lch"]),
            "independentHTTP": len(v["http"]),
            "independentScriptInputs": inputs,
            "independentPlayback": len(v["acquisitions"]),
            "syntheticChain": True,
        }
    )
)
