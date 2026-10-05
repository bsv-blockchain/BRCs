// Offline cross-layer qualification of frozen bytes. Never calls a network or
// a funding wallet; ProtoWallet is used only for public fixture cryptography.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { createDecipheriv } from "node:crypto";
import {
  PrivateKey,
  PublicKey,
  Transaction,
  LockingScript,
  P2PKH,
  Hash,
  SignedMessage,
  EncryptedMessage,
  ProtoWallet,
  OverlayAdminTokenTemplate,
  Beef,
} from "@bsv/sdk";
import {
  sha,
  hash256,
  hex,
  b64,
  bytes,
  canonical,
  parseJSON,
  closed,
  identity,
  u64,
  extensions,
  preimage,
  digest,
  cbor,
  lchId,
  lchPreimage,
  undiagnostic,
  httpPayload,
  purchaseReceipt,
} from "./protocol.mjs";
import {
  encode,
  decode,
  pub,
  pkh,
  le,
  evaluate,
} from "../../../tokens/media/0197/family.mjs";
const read = (p) => readFileSync(new URL(p, import.meta.url)),
  manifest = JSON.parse(read("./wire-manifest.json")),
  archive = read("./" + manifest.archive);
assert.equal(hex(sha(archive)), manifest.sha256);
const decoded = gunzipSync(archive);
assert.equal(decoded.length, manifest.decodedBytes);
const v = JSON.parse(decoded);
const keys = Object.fromEntries(
    Object.entries(v.actors).map(([n, a]) => [n, new PrivateKey(a.scalar)]),
  ),
  wallets = Object.fromEntries(
    Object.entries(keys).map(([n, k]) => [n, new ProtoWallet(k)]),
  );
const E = "https://bsv.brc.dev/apps/0198#overlay-acquisition-v1",
  C = "https://bsv.brc.dev/apps/0198#listing-accumulation-v1",
  S = "https://bsv.brc.dev/apps/0198#standing-offer-v1",
  P = "https://bsv.brc.dev/apps/0198#paid-lookup-settlement-v1",
  L = "https://bsv.brc.dev/apps/0170#";
let checks = 0,
  negative = 0;
function check(name, fn) {
  try {
    fn();
    checks++;
  } catch (e) {
    throw Error(name + ": " + e.message, { cause: e });
  }
}
function rejects(name, fn) {
  assert.throws(fn, undefined, name);
  checks++;
  negative++;
}
async function rejectsAsync(name, fn) {
  await assert.rejects(fn, undefined, name);
  checks++;
  negative++;
}
function signature(type, obj, signer) {
  const sig = bytes(obj.signature);
  assert.equal(hex(sig.subarray(4, 37)), signer);
  assert.equal(sig[37], 0);
  assert(SignedMessage.verify([...preimage(type, obj.body)], [...sig]));
}
function lchSignature(type, obj, signer) {
  assert(obj.signatures.length);
  for (const s of obj.signatures) {
    assert.equal(hex(s.subarray(4, 37)), signer);
    assert.equal(s[37], 0);
    assert(SignedMessage.verify([...lchPreimage(type, obj.body)], [...s]));
  }
}
const digestVectors = JSON.parse(read("./digest-vectors.json"));
const registry = JSON.parse(read("./registry.json"));
assert.deepEqual(
  digestVectors.vectors.map((row) => row.domain),
  registry.digestDomains,
);
assert.equal(canonical(digestVectors.body), digestVectors.canonical);
for (const row of digestVectors.vectors)
  check("domain separation " + row.domain, () => {
    assert.equal(hex(preimage(row.domain, digestVectors.body)), row.preimage);
    assert.equal(digest(row.domain, digestVectors.body), row.sha256);
  });
for (const p of v.packets)
  check(p.type, () => {
    assert.equal(hex(preimage(p.type, p.body)), p.preimage);
    assert.equal(digest(p.type, p.body), p.id);
    signature(p.type, p, p.signer);
  });
for (const item of v.lch)
  check("CBOR " + item.type, () => {
    const obj = undiagnostic(item.object);
    assert.equal(hex(cbor(obj)), item.cbor);
    assert.equal(hex(lchId(item.type, obj.body)), item.id);
    lchSignature(item.type, obj, item.signer);
  });
rejects("packet altered body", () =>
  signature(
    "capabilities",
    {
      ...v.capability,
      body: { ...v.capability.body, baseURL: "https://wrong.example" },
    },
    v.actors.seller.identity,
  ),
);
for (const h of v.headers) {
  const raw = Buffer.from(h.raw, "hex");
  check("header proof of work", () => {
    assert.equal(raw.length, 80);
    assert.equal(hex(Buffer.from(hash256(raw)).reverse()), h.hash);
    assert.equal(
      hex(Buffer.from(raw.subarray(36, 68)).reverse()),
      h.merkleRoot,
    );
    assert.equal(hex(Buffer.from(raw.subarray(4, 36)).reverse()), h.previous);
    assert.equal(raw.readUInt32LE(72), 0x207fffff);
    assert(BigInt("0x" + h.hash) <= 0x7fffffn << 232n);
    if (h.height === 0) assert.equal(h.hash, v.chain.genesisHash);
    else assert.equal(h.previous, v.chain.genesisHash);
  });
}
const roots = v.headers.filter((_, i) => i < 2),
  tracker = {
    isValidRootForHeight: async (root, height) =>
      roots.some((h) => h.height === height && h.merkleRoot === root),
    currentHeight: async () => 101,
  };
async function evidence(e) {
  const beef = bytes(e.beef),
    tx = Transaction.fromBEEF([...beef], e.txid);
  assert.equal(tx.id("hex"), e.txid);
  assert(tx.outputs[e.outputIndex]);
  assert(await tx.verify(tracker, undefined, 128 * 1024 * 1024));
  return tx;
}
for (const [txid, t] of Object.entries(v.transactions)) {
  const tx = await evidence({ txid, beef: t.beef, outputIndex: 0 });
  assert.equal(tx.toHex(), t.raw);
  checks++;
  if (t.label !== "synthetic chain checkpoint")
    for (let i = 0; i < tx.inputs.length; i++) {
      assert(evaluate(tx, i));
      checks++;
    }
}
await rejectsAsync("wrong target", () =>
  evidence({ ...v.publication.request.evidence, txid: "99".repeat(32) }),
);
await rejectsAsync("corrupt BEEF", () =>
  evidence({ ...v.publication.request.evidence, beef: b64(Buffer.from([0])) }),
);
check("proof variants are facts not observation equivalence", () => {
  const a = v.publication.request,
    b = v.publication.proofVariant;
  assert.notEqual(a.evidence.beef, b.evidence.beef);
  assert.notEqual(
    hex(sha(bytes(a.evidence.beef))),
    hex(sha(bytes(b.evidence.beef))),
  );
  const semantic = (x) => {
    const z = structuredClone(x);
    delete z.evidence.beef;
    return digest("publication-request", z);
  };
  assert.equal(semantic(a), semantic(b));
  assert.notEqual(canonical(a), canonical(b));
});
await evidence(v.publication.proofVariant.evidence);
const handshake = v.handshake;
assert(
  (
    await wallets.buyerA.verifySignature({
      data: [...Buffer.from(handshake.data, "hex")],
      signature: [...Buffer.from(handshake.initialResponse.signature, "hex")],
      protocolID: [2, "auth message signature"],
      keyID:
        handshake.initialRequest.initialNonce +
        " " +
        handshake.initialResponse.initialNonce,
      counterparty: v.actors.seller.identity,
    })
  ).valid,
);
checks++;
for (const t of v.http) {
  assert.equal(hex(httpPayload(t)), t.payload);
  const args = {
    data: [...httpPayload(t)],
    signature: [...Buffer.from(t.signature, "hex")],
    protocolID: [2, "auth message signature"],
    keyID: t.nonce + " " + t.yourNonce,
    counterparty: v.actors[t.sender].identity,
  };
  assert((await wallets[t.receiver].verifySignature(args)).valid);
  checks++;
  for (const body of [
    bytes(t.body).subarray(0, -1),
    Buffer.concat([bytes(t.body), Buffer.from(" ")]),
  ]) {
    const changed = { ...t, body: b64(body) };
    await rejectsAsync("HTTP body integrity before publication", async () => {
      assert(
        (
          await wallets[t.receiver].verifySignature({
            ...args,
            data: [...httpPayload(changed)],
          })
        ).valid,
      );
    });
  }
}
const cap = v.capability.body;
check("manifest selection", () => {
  assert.equal(cap.identity, v.actors.seller.identity);
  for (const s of cap.services) {
    assert.equal(s.rulesDigest, digest("service-rules", s.rules));
    assert(new Set(s.profiles.map((p) => p.id)).size === s.profiles.length);
    for (const p of s.profiles) {
      const kind =
        p.id.includes("lookup-live") || p.id.includes("paid-lookup")
          ? "lookup"
          : p.id.includes("root-eviction")
            ? "coordination"
            : "topic";
      assert.equal(s.kind, kind);
      if (p.parameters.recoverySeconds)
        assert(BigInt(p.parameters.recoverySeconds) >= 86400n);
    }
  }
});
const header = undiagnostic(v.header.object),
  asset = header.asset,
  assetId = hex(lchId("asset", asset)),
  authority = header.authority[0];
check("Header authority", () => {
  const { signatures, ...body } = header;
  lchSignature("header", { body, signatures }, v.actors.seller.identity);
  assert.equal(hex(cbor(header)), v.header.cbor);
  lchSignature("authority", authority, v.actors.controller.identity);
  assert.equal(hex(authority.body.assetId), assetId);
  assert.equal(hex(authority.body.grantor), hex(asset.rights[0].controller));
  assert.equal(hex(authority.body.grantee), v.actors.seller.identity);
  for (const action of [
    "publishHeader",
    "issueOffer",
    "issueLicense",
    "releaseKey",
    "receivePayment",
  ])
    assert(authority.body.capabilities.includes(L + action));
  assert(
    authority.body.notBefore <= v.clock && authority.body.notAfter > v.clock,
  );
  assert.deepEqual(authority.body.interests, ["work"]);
  assert(
    authority.body.policyActions.includes("http://www.w3.org/ns/odrl/2/play"),
  );
  assert(authority.body.usageProfiles.includes(L + "fixed-render-v1"));
});
const initialScript = encode(v.descriptor, v.descriptor.initialRevenue);
check("inverse family and initial genesis", () => {
  assert.deepEqual(
    decode(initialScript, v.descriptor),
    v.descriptor.initialRevenue,
  );
  const authorization = v.packets.find((p) => p.type === "sale-genesis"),
    genesis = authorization.body.genesis,
    tx = Transaction.fromHex(v.transactions[genesis.txid].raw);
  assert.equal(tx.inputs[0].sourceTXID, v.descriptor.lineageAnchor.txid);
  assert.equal(
    tx.inputs[0].sourceOutputIndex,
    v.descriptor.lineageAnchor.outputIndex,
  );
  assert.equal(tx.outputs[0].satoshis, Number(v.descriptor.reserve));
  assert.equal(tx.outputs[0].lockingScript.toHex(), initialScript.toHex());
  assert.equal(authorization.body.genesis.txid, genesis.txid);
  assert.equal(
    authorization.body.listingId,
    digest("sale-listing", v.descriptor),
  );
  const activationEvidence = v.publication.request.evidence;
  const activation = Transaction.fromHex(v.transactions[activationEvidence.txid].raw);
  assert.equal(activation.inputs[0].sourceTXID, genesis.txid);
  assert.equal(activation.inputs[0].sourceOutputIndex, 0);
  assert.equal(activation.outputs[0].lockingScript.toHex(),
    encode(v.descriptor, v.descriptor.initialRevenue, "active").toHex());
  assert.equal(activation.outputs[0].satoshis, Number(v.descriptor.reserve));
});
function decrypt(lic, buyer) {
  const enc = asset.representation.encryption,
    grants = lic.body.keyGrants;
  assert.equal(grants.length, enc.keyPeriods.length);
  const content = Buffer.from(v.content.ciphertext, "hex");
  assert.equal(hex(sha(content)), hex(asset.representation.ciphertextDigest));
  assert.equal(content.length, asset.representation.ciphertextLength);
  assert.equal(hex(lchId("asset", asset)), assetId);
  const grant = grants[0],
    wrapped = grant.payload;
  assert.equal(hex(wrapped.subarray(4, 37)), v.actors.seller.identity);
  assert.equal(hex(wrapped.subarray(37, 70)), pub(buyer));
  const plain = Buffer.from(EncryptedMessage.decrypt([...wrapped], buyer));
  assert.equal(plain.length, 64);
  const key = plain.subarray(32),
    id = sha(Buffer.concat([Buffer.from("LCH key id v1\0"), key]));
  assert.equal(hex(id), hex(grant.keyId));
  assert.equal(hex(id), hex(plain.subarray(0, 32)));
  assert.equal(hex(id), hex(enc.keyPeriods[0].keyId));
  assert.deepEqual(lic.body.segmentSelection, {
    type: "segments",
    ranges: [[0, enc.segmentCount]],
  });
  const out = [];
  for (let i = 0; i < enc.segmentCount; i++) {
    const be = (n) => {
        const b = Buffer.alloc(8);
        b.writeBigUInt64BE(BigInt(n));
        return b;
      },
      iv = Buffer.concat([enc.noncePrefix, be(i)]),
      aad = Buffer.concat([
        Buffer.from("LCH A256GCM segmented v1\0"),
        enc.encryptionId,
        be(i),
        be(enc.segmentCount),
        be(enc.plaintextLength),
        id,
      ]),
      record = content.subarray(
        i * (enc.segmentSize + 16),
        Math.min((i + 1) * (enc.segmentSize + 16), content.length),
      ),
      dec = createDecipheriv("aes-256-gcm", key, iv);
    dec.setAAD(aad);
    dec.setAuthTag(record.subarray(-16));
    out.push(Buffer.concat([dec.update(record.subarray(0, -16)), dec.final()]));
  }
  assert.equal(hex(Buffer.concat(out)), v.content.plaintext);
  return Buffer.concat(out);
}
for (const a of v.acquisitions) {
  const buyer = keys[a.buyer],
    context = undiagnostic(a.context),
    request = undiagnostic(a.request),
    license = context.license,
    offer = context.evidence.find((e) => e.type === "offer").object,
    terms = offer.body.extensions[E],
    settlement = parseJSON(context.settlement),
    r = settlement.body,
    outer = a.prepare ?? a.acquire,
    release = a.envelope?.releaseEvidence ?? a.result.acceptance,
    profile = a.mode === "listing-covenant" ? C : P;
  check("acquisition binding " + a.mode + " " + a.buyer, () => {
    assert.equal(hex(cbor(context)), a.contextCBOR);
    assert.equal(b64(cbor(request)), outer.request);
    lchSignature("license-request", request, pub(buyer));
    lchSignature("offer", offer, v.actors.seller.identity);
    lchSignature("license", license, v.actors.seller.identity);
    assert.equal(hex(lchId("offer", offer.body)), outer.termsDigest);
    assert.equal(hex(request.body.offerId), outer.termsDigest);
    assert.equal(hex(request.body.assetId), assetId);
    assert.equal(request.body.buyer.toString("hex"), pub(buyer));
    assert.equal(
      hex(request.body.acceptedPolicyDigest),
      hex(sha(offer.body.policy.inline)),
    );
    assert.equal(hex(lchId("license-request", request.body)), outer.requestId);
    assert.equal(hex(license.body.requestId), outer.requestId);
    assert.equal(hex(license.body.subject), pub(buyer));
    assert.equal(hex(license.body.assetId), assetId);
    assert.equal(hex(license.body.offerId), outer.termsDigest);
    assert.equal(
      hex(sha(license.body.agreement.inline)),
      hex(license.body.agreement.digest),
    );
    const agreement = JSON.parse(license.body.agreement.inline);
    assert.equal(
      agreement.permission[0].assignee,
      "lch:identity:secp256k1:" + pub(buyer),
    );
    assert.equal(agreement.permission[0].target, "lch:asset:sha256:" + assetId);
    assert.equal(terms.mode, a.mode);
    assert.equal(terms.service, outer.topic ?? outer.service);
    assert.equal(
      offer.body.payment.endpoint,
      terms.endpoint +
        "/overlay/v1/" +
        (a.prepare ? "purchases/prepare" : "private/acquire"),
    );
    assert.equal(offer.body.payment.pricing.requirements.length, 1);
    assert.equal(
      offer.body.payment.pricing.requirements[0].satoshis,
      Number(r.satoshis),
    );
    assert.equal(r.requestId, outer.requestId);
    assert.equal(r.buyer, pub(buyer));
    assert.equal(r.offerId, outer.termsDigest);
    assert.equal(r.assetId, assetId);
    assert.equal(r.releaseEvidenceDigest, digest("release-evidence", release));
    assert.equal(
      r.recoveryUntil,
      outer === a.prepare
        ? a.terms.body.recoveryUntil
        : a.challenge.recoveryUntil,
    );
    assert(
      BigInt(r.recoveryUntil) >=
        BigInt(a.terms?.body.purchaseUntil ?? a.challenge.payableUntil) +
          172800n,
    );
    assert.equal(
      hex(license.body.fulfillments[0].receiptIds[0]),
      digest(
        a.prepare ? "lch-covenant-settlement" : "lch-lookup-settlement",
        r,
      ),
    );
    assert.equal(license.body.fulfillments[0].settlementProfile, profile);
    assert.equal(license.body.extensions[E].mode, a.mode);
    for (const x of [E, profile])
      assert(
        license.body.critical.includes(x) &&
          Object.hasOwn(license.body.extensions, x),
      );
    signature(
      a.prepare ? "lch-covenant-settlement" : "lch-lookup-settlement",
      settlement,
      v.actors.seller.identity,
    );
    const processor = parseJSON(bytes(release.processorEvidence));
    signature("processor-acceptance", processor, v.actors.processor.identity);
    assert.equal(processor.body.txid, release.txid);
    assert.equal(processor.body.policy, release.policy.policy);
    assert.equal(processor.body.acceptedAt, release.acceptedAt);
    assert.equal(canonical(processor.body.chain), canonical(v.chain));
  });
  if (a.prepare) {
    const tx = await evidence({
        txid: a.submit.txid,
        beef: a.submit.beef,
        outputIndex: 0,
      }),
      old = await evidence(
        a.lineage.transactions.find((t) => t.txid === a.prepare.listing.txid)
          ? {
              ...a.lineage.transactions.find(
                (t) => t.txid === a.prepare.listing.txid,
              ),
              outputIndex: 0,
            }
          : {},
      );
    check("covenant exact purchase", () => {
      assert.equal(
        a.terms.body.requestDigest,
        digest("purchase-request", a.prepare),
      );
      assert.equal(
        a.terms.body.acquisitionId,
        digest("purchase", {
          chain: v.chain,
          seller: v.actors.seller.identity,
          recipient: pub(buyer),
          topic: a.prepare.topic,
          requestId: a.prepare.requestId,
        }),
      );
      assert.equal(tx.inputs[0].sourceTXID, old.id("hex"));
      assert.equal(tx.outputs[0].satoshis, old.outputs[0].satoshis + 1001);
      assert.equal(
        tx.outputs[0].lockingScript.toHex(),
        old.outputs[0].lockingScript.toHex(),
      );
      assert.equal(
        tx.outputs[1].lockingScript.toHex(),
        hex(
          purchaseReceipt(
            {
              listingId: digest("sale-listing", v.descriptor),
              termsDigest: v.descriptor.termsDigest,
            },
            a.terms.body.acquisitionId,
            a.terms.body.requestDigest,
            pub(buyer),
          ),
        ),
      );
      assert.equal(tx.outputs[1].satoshis, 1);
      assert.equal(r.txid, tx.id("hex"));
      assert.equal(
        a.envelope.result.potatoes.body.evidenceDigest,
        digest("release-evidence", release),
      );
      assert.equal(a.envelope.result.potatoes.body.secret, b64(cbor(context)));
      assert.equal(offer.body.extensions[S].version, 1);
      assert(
        !Object.hasOwn(offer.body.payment.pricing.requirements[0], "buyer"),
      );
      assert.equal(offer.body.extensions[C].family, v.descriptor.scriptFamily);
      assert.equal(offer.body.extensions[C].expiryHeight, v.descriptor.expiryHeight);
      assert.equal(
        offer.body.extensions[C].retirement,
        "seller-child-or-expiry-height-exact-top-up",
      );
      assert.equal(offer.body.extensions[C].schedule, "immutable");
      assert.equal(offer.body.extensions[C].derivation, "brc29-anyone-fixed");
      assert.equal(offer.body.extensions[C].withdrawal, "permissionless-quanta");
      assert.deepEqual(
        offer.body.extensions[C].initialRevenue.recipients.map((x) => ({
          identity: hex(x.identity),
          weight: x.weight,
        })),
        v.descriptor.initialRevenue.recipients,
      );
      assert.equal(a.lineage.target.txid, a.prepare.listing.txid);
      assert.equal(
        canonical(parseJSON(bytes(a.terms.body.domainEvidence.bytes))),
        canonical(a.lineage),
      );
      assert.equal(a.pending.result.status, "admitted-delivery-pending");
      assert(!a.pending.result.potatoes);
      assert(evaluate(tx, 0));
    });
  } else {
    const payment = await evidence(parseJSON(context.paymentEvidence).payment),
      invoice =
        "2-3241645161d8-" +
        a.challenge.derivationPrefix +
        " " +
        a.paymentHeader.derivationSuffix,
      pk = keys.seller.toPublicKey().deriveChild(buyer, invoice),
      derived = keys.seller.deriveChild(buyer.toPublicKey(), invoice),
      script = new P2PKH().lock(pk.toAddress());
    check("payment output, not transaction alone", () => {
      assert.equal(pk.toString(), derived.toPublicKey().toString());
      const matches = payment.outputs
        .map((o, i) => ({ o, i }))
        .filter((x) => x.o.lockingScript.toHex() === script.toHex());
      assert.equal(matches.length, 1);
      assert.equal(matches[0].o.satoshis, 1001);
      assert.equal(matches[0].i, r.funding.outputIndex);
      assert.equal(payment.id("hex"), r.funding.txid);
      assert.equal(
        a.challenge.requestDigest,
        digest("acquire-request", a.acquire),
      );
      assert.equal(a.result.result.context, b64(cbor(context)));
      assert.equal(
        hex(offer.body.payment.pricing.requirements[0].buyer),
        pub(buyer),
      );
    });
  }
  check("authenticated playback " + a.buyer, () => decrypt(license, buyer));
  rejects("wrong key recipient", () => decrypt(license, keys.controller));
  const changed = undiagnostic(a.context).license;
  changed.body.keyGrants[0].payload[
    changed.body.keyGrants[0].payload.length - 1
  ] ^= 1;
  rejects("BRC-78 authentication", () => decrypt(changed, buyer));
  const wrongPeriod = undiagnostic(a.context).license;
  wrongPeriod.body.segmentSelection.ranges[0][1]++;
  rejects("key period boundary", () => decrypt(wrongPeriod, buyer));
}
check("two buyers one unchanged Offer", () => {
  const [a, b] = v.acquisitions;
  assert.equal(a.prepare.termsDigest, b.prepare.termsDigest);
  assert.notEqual(a.prepare.recipient, b.prepare.recipient);
  assert.equal(b.prepare.listing.txid, a.submit.txid);
  assert.equal(v.retry.original.requestId, v.retry.resigned.requestId);
  assert.notEqual(
    digest("acquire-request", v.retry.original),
    digest("acquire-request", v.retry.resigned),
  );
});
for (const adv of v.advertisements) {
  const tx = await evidence(adv.evidence);
  assert.deepEqual(
    await OverlayAdminTokenTemplate.decodeAndVerify(
      tx.outputs[0].lockingScript,
      adv.protocol,
    ),
    adv.decoded,
  );
  checks++;
}
for (const req of v.rootRequests)
  check("recipient-bound root request", () => {
    signature("root-eviction-request", req, v.actors.seller.identity);
    const t = req.body.targets[0],
      raw = Transaction.fromHex(v.transactions[t.outpoint.txid].raw);
    assert.equal(
      t.advertisementDigest,
      digest("root-advertisement", {
        service: t.service,
        outpoint: t.outpoint,
        lockingScript: b64(
          raw.outputs[t.outpoint.outputIndex].lockingScript.toBinary(),
        ),
      }),
    );
    assert.deepEqual(t.advertisement, t.evidence.advertisement);
    assert.notEqual(
      v.rootRequests[0].body.recipient,
      v.rootRequests[1].body.recipient,
    );
  });
check("mined proof and changed view", () => {
  assert.equal(v.mined.blockEvidence.blockHash, v.headers[1].hash);
  assert.equal(
    BigInt(v.mined.blockEvidence.tipHeight) -
      BigInt(v.mined.blockEvidence.height) +
      1n,
    1n,
  );
  assert.notEqual(v.reorganization.newTip, v.mined.blockEvidence.tipHash);
  assert(
    !v.headers
      .filter((_, i) => i !== 1)
      .some((h) => h.height === 1 && h.merkleRoot === v.mined.txid),
  );
});
await evidence({
  txid: v.mined.txid,
  outputIndex: 0,
  beef: v.mined.blockEvidence.beef,
});
checks++;
// Exact representation rejection vectors (syntax is not delegated to JSON.parse).
for (const [name, raw] of [
  ["escaped duplicate", '{"x":1,"\\u0078":2}'],
  [
    "nested unknown",
    '{"chain":{"network":"x","genesisHash":"' +
      "00".repeat(32) +
      '","extra":1}}',
  ],
  ["unsafe", "9007199254740992"],
  ["fraction", "0.5"],
  ["trailing", "{}x"],
  ["surrogate", '"\\ud800"'],
  ["utf8", Buffer.from([0xc3, 0x28])],
])
  rejects(name, () => {
    const value = parseJSON(raw);
    if (name === "nested unknown")
      closed(value.chain, ["network", "genesisHash"]);
  });
for (const n of ["1.0", "1e0", "-0"])
  check("JCS integral " + n, () =>
    assert.equal(canonical(parseJSON(n)), n === "-0" ? "0" : "1"),
  );
for (const b of ["YR==", "YQ", "YQ===", "Y Q=="])
  rejects("base64 canonical " + b, () => bytes(b));
check("empty opaque bytes", () => assert.equal(bytes("").length, 0));
rejects("U64 overflow", () => u64("18446744073709551616"));
rejects("invalid curve", () => identity("02" + "ff".repeat(32)));
rejects("critical duplicate", () =>
  extensions(
    { extensions: { "urn:test": 1 }, critical: ["urn:test", "urn:test"] },
    ["urn:test"],
  ),
);
rejects("unknown critical", () =>
  extensions({ extensions: { "urn:test": 1 }, critical: ["urn:test"] }),
);
rejects("nested depth", () => parseJSON("[".repeat(34) + "0" + "]".repeat(34)));
// Source authentication is separate from a self-described remote Scope.
const source = v.live.live,
  expectedScope = v.live.batch.scope;
const scopeCheck = (batch) => {
  assert.equal(canonical(batch.scope), canonical(expectedScope));
  for (const g of batch.groups) {
    assert(BigInt(g.sequence) <= BigInt(batch.through));
    for (const o of g.observations)
      assert.equal(canonical(o.scope), canonical(expectedScope));
  }
};
check("whole batch scope", () => scopeCheck(source));
const foreign = structuredClone(source);
foreign.groups[0].observations[1].scope.chain.network = "elsewhere";
rejects("single foreign observation", () => scopeCheck(foreign));
const spent = source.groups[0].observations[0],
  spendTx = await evidence({
    txid: spent.payload.spendingTxid,
    outputIndex: 0,
    beef: spent.payload.beef,
  });
const consumes = (p) =>
  spendTx.inputs.some(
    (i) => i.sourceTXID === p.txid && i.sourceOutputIndex === p.outputIndex,
  );
check("verified spend linkage", () => assert(consumes(spent.payload.previous)));
rejects("valid transaction unrelated asserted prevout", () =>
  assert(
    consumes({
      txid: v.transactions[Object.keys(v.transactions).at(-1)].raw.slice(0, 64),
      outputIndex: 0,
    }),
  ),
);
// Semantic rejection vectors are checked after cryptographic decoding; they
// isolate a binding rule instead of counting an unrelated signature failure.
function acquisitionProfile(offer, lic, req, settlement, required = [E, C, S]) {
  for (const id of offer.critical ?? [])
    assert(required.includes(id) || id === P, "unsupported critical mechanism");
  for (const id of required)
    assert(
      offer.critical.includes(id) && Object.hasOwn(offer.extensions, id),
      "required mechanism",
    );
  assert.equal(offer.payment.pricing.requirements.length, 1);
  const requirement = offer.payment.pricing.requirements[0],
    policy = JSON.parse(offer.policy.inline);
  assert.equal(policy.permission.length, 1);
  assert.equal(policy.permission[0].duty.length, 1);
  assert.equal(requirement.dutyUid, policy.permission[0].duty[0].uid);
  assert.equal(hex(requirement.payee), v.actors.seller.identity);
  assert.equal(lic.fulfillments.length, 1);
  assert.equal(lic.fulfillments[0].settlementProfile, C);
  assert.equal(hex(lic.subject), hex(req.buyer));
  assert.equal(settlement.buyer, hex(req.buyer));
  assert.equal(hex(lic.assetId), assetId);
  assert.equal(settlement.satoshis, String(requirement.satoshis));
  assert.equal(offer.extensions[E].service, "tm_listings");
  assert.equal(
    offer.payment.endpoint,
    offer.extensions[E].endpoint + "/overlay/v1/purchases/prepare",
  );
}
const cv = undiagnostic(v.acquisitions[0].context),
  co = cv.evidence.find((x) => x.type === "offer").object.body,
  cl = cv.license.body,
  cr = undiagnostic(v.acquisitions[0].request).body,
  cs = parseJSON(cv.settlement).body;
const clone = (x) =>
  undiagnostic(
    JSON.parse(
      JSON.stringify(x, (_, y) =>
        y && y.type === "Buffer"
          ? { $bytes: Buffer.from(y.data).toString("hex") }
          : y,
      ),
    ),
  );
check("single duty semantic profile", () => acquisitionProfile(co, cl, cr, cs));
for (const [name, mutate] of [
  [
    "extra unpaid duty",
    (o) => {
      const p = JSON.parse(o.policy.inline);
      p.permission[0].duty.push({
        ...p.permission[0].duty[0],
        uid: "urn:extra",
      });
      o.policy.inline = Buffer.from(canonical(p));
    },
  ],
  ["unknown required E/C", (o) => o.critical.push("urn:unknown:mechanism")],
  [
    "wrong collector",
    (o) =>
      (o.payment.pricing.requirements[0].payee = Buffer.from(
        v.actors.controller.identity,
        "hex",
      )),
  ],
  ["wrong service", (o) => (o.extensions[E].service = "tm_other")],
  [
    "relative endpoint",
    (o) => (o.payment.endpoint = "/overlay/v1/purchases/prepare"),
  ],
]) {
  const o = clone(co);
  mutate(o);
  rejects(name, () => acquisitionProfile(o, cl, cr, cs));
}
const wrongFulfillment = clone(cl);
wrongFulfillment.fulfillments[0].settlementProfile = L + "receipt-complete-v1";
rejects("settlement profile substitution", () =>
  acquisitionProfile(co, wrongFulfillment, cr, cs),
);
const wrongBuyer = clone(cl);
wrongBuyer.subject = Buffer.from(v.actors.buyerB.identity, "hex");
rejects("license buyer substitution", () =>
  acquisitionProfile(co, wrongBuyer, cr, cs),
);
rejects("settlement increment substitution", () =>
  acquisitionProfile(co, cl, cr, { ...cs, satoshis: "1000" }),
);
const rootBlockers = new Set(),
  rootActions = new Set();
for (const trace of v.rootTrace) {
  const r = trace.result.body,
    o = r.outcomes[0];
  check("root signed action " + trace.name, () => {
    assert.equal(
      r.requestDigest,
      digest("root-eviction-request", trace.request.body),
    );
    assert.equal(o.actionStatus, "applied");
    assert.equal(
      o.decisionId,
      digest("root-eviction-decision", {
        root: r.root,
        requestDigest: r.requestDigest,
        service: o.service,
        outpoint: o.outpoint,
        revision: o.revision,
      }),
    );
    assert(!rootActions.has(o.decisionId));
    rootActions.add(o.decisionId);
    if (trace.request.body.action === "suppress")
      rootBlockers.add(o.decisionId);
    else {
      assert.equal(
        o.affectedDecisionIds[0],
        trace.request.body.targets[0].restores,
      );
      assert(rootBlockers.delete(o.affectedDecisionIds[0]));
    }
    assert.deepEqual(
      [...rootBlockers].sort(),
      o.serving.blockers.map((b) => b.decisionId),
    );
    assert.equal(
      o.serving.state,
      rootBlockers.size ? "suppressed" : "eligible",
    );
  });
}
check("independent root policy", () =>
  assert.equal(
    v.rootIndependentResult.body.outcomes[0].actionStatus,
    "rejected",
  ),
);

console.log(
  JSON.stringify({
    checks,
    negative,
    packets: v.packets.length,
    httpTranscripts: v.http.length,
    acquisitions: v.acquisitions.length,
    playback: "verified in all three acquisitions",
    qualification:
      "offline byte/crypto/Script/domain corpus; not deployed runtime",
  }),
);
