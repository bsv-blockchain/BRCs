"""Independent signed-byte/query-model oracle. No storage or live-provider claim."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
from bitcoinx import PublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).parent
v = json.loads((HERE / "proposal-query-vectors.json").read_text())


def canonical(value):
    if isinstance(value, dict):
        return "{" + ",".join(canonical(key) + ":" + canonical(value[key])
                              for key in sorted(value, key=lambda key: key.encode("utf-16-be"))) + "}"
    if isinstance(value, list):
        return "[" + ",".join(map(canonical, value)) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def preimage(domain, body):
    return ("BRC-OUTPUT/1/" + domain + "\0" + canonical(body)).encode()


def digest(domain, body):
    return hashlib.sha256(preimage(domain, body)).hexdigest()


assert digest("service-rules", v["rules"]) == v["rulesDigest"]
for row in v["queries"]:
    assert digest("lookup-query", {"service": v["service"], "query": row["query"]}) == row["digest"]
for name, head in v["heads"].items():
    body = head["body"]
    sig = base64.b64decode(head["signature"], validate=True)
    assert base64.b64encode(sig).decode() == head["signature"]
    assert sig[:4].hex() == "42423301" and sig[37] == 0
    sender = sig[4:37]
    assert sender.hex() == body["author"] == v["principal"]
    invoice = "2-message signing-" + base64.b64encode(sig[38:70]).decode()
    offset = hmac.new(sender, invoice.encode(), hashlib.sha256).digest()
    derived = PublicKey.from_bytes(sender).add(offset).to_bytes(compressed=True)
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), derived).verify(
        sig[70:], preimage("proposal", body), ec.ECDSA(hashes.SHA256()))
    assert body["service"] == v["service"] and body["chain"] == v["chain"]
    assert body["policy"] == v["rules"]["parameters"]["policy"]
    assert body["operation"] == "update" and int(body["issuedAt"]) < int(body["expiresAt"])
    assert body["anchors"] == [] and "transaction" not in body
    payload = base64.b64decode(body["payload"], validate=True).decode()
    document = json.loads(payload)
    assert set(document) == {"text"} and payload == canonical(document)
    if name != "a1":
        assert body["revision"] == "0" and body["previous"] is None
assert v["heads"]["a1"]["body"]["revision"] == "1"
assert v["heads"]["a1"]["body"]["previous"] == digest("proposal", v["heads"]["a0"]["body"])
assert v["heads"]["a1"]["body"]["recipients"] == v["heads"]["a0"]["body"]["recipients"]


def parse_query(value):
    assert isinstance(value, dict) and set(value) <= {"channels"}
    if not value:
        return None
    channels = value["channels"]
    assert isinstance(channels, list) and 1 <= len(channels) <= 256
    assert all(isinstance(item, str) and len(item) == 64 and all(c in "0123456789abcdef" for c in item) for item in channels)
    assert channels == sorted(set(channels))
    return channels


def execute(test):
    channels = parse_query(test.get("query", {}))
    principal = test.get("principal", v["principal"])
    if principal is None:
        raise ValueError("unauthorized")

    def visible(row):
        if row is None:
            return False
        body = v["heads"][row["head"]]["body"]
        return row["readable"] and principal in body["recipients"] and (channels is None or body["channel"] in channels)

    def key(row):
        body = v["heads"][row["head"]]["body"]
        return bytes.fromhex(body["policy"]["digest"] + body["channel"])

    def pair(row):
        return [{"kind": "proposal", "head": row["head"]},
                {"kind": "proposal-state", "head": row["head"], "state": row["state"]}]

    if "rows" in test:
        return [pair(row) for row in sorted(test["rows"], key=key) if visible(row)]
    selected = []
    for change in sorted(test["changes"], key=lambda change: key(change["after"] or change["before"])):
        old, new = change["before"], change["after"]
        before, after = visible(old), visible(new)
        if old is not None and new is not None and before != after:
            raise ValueError("reset-required")
        if before and after and old == new:
            continue
        if before and (not after or digest("proposal", v["heads"][old["head"]]["body"]) != digest("proposal", v["heads"][new["head"]]["body"])):
            selected.append({"kind": "proposal-remove", "head": old["head"]})
        if after:
            selected.extend(pair(new))
    return [selected] if selected else []


for test in v["cases"]:
    try:
        result = execute(test)
    except ValueError as error:
        assert test.get("error") == str(error), test["name"]
    else:
        assert "error" not in test and result == test["expected"], test["name"]
a, b = "11" * 32, "22" * 32
invalid = [None, [], {"extra": True}, {"channels": []}, {"channels": [a, a]},
           {"channels": [b, a]}, {"channels": ["FF" * 32]}, {"channels": [False]},
           {"channels": None}, {"channels": [f"{n:064x}" for n in range(257)]}]
for value in invalid:
    try:
        parse_query(value)
    except AssertionError:
        pass
    else:
        raise AssertionError("Accepted invalid query: " + repr(value))
assert len(parse_query({"channels": [f"{n:064x}" for n in range(256)]})) == 256
print(f"Independent proposal query: {len(v['cases'])} scenarios, {len(invalid)} rejections, 3 BRC-77 signatures and 4 digests passed.")
