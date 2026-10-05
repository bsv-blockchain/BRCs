// Explicit corpus regeneration. Random BRC-77/78 envelopes are frozen in the
// archive, not re-signed by the verification commands. All keys are PUBLIC TEST KEYS.
import assert from "node:assert/strict";
import { writeFileSync, readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { createCipheriv } from "node:crypto";
import {
  PrivateKey,
  PublicKey,
  Transaction,
  LockingScript,
  UnlockingScript,
  P2PKH,
  Hash,
  SignedMessage,
  EncryptedMessage,
  ProtoWallet,
  MerklePath,
  OverlayAdminTokenTemplate,
} from "@bsv/sdk";
import {
  sha,
  hash256,
  hex,
  b64,
  canonical,
  preimage,
  digest,
  cbor,
  lchId,
  lchPreimage,
  diagnostic,
  httpPayload,
  purchaseReceipt,
} from "./protocol.mjs";
import {
  encode,
  decode,
  pub,
  pkh,
  ys,
  le,
  output,
  unlock,
  preimage as covenantPreimage,
  evaluate,
  stateBytes,
} from "../../../tokens/media/0197/family.mjs";
const L = "https://bsv.brc.dev/apps/0170#",
  E = "https://bsv.brc.dev/apps/0198#overlay-acquisition-v1",
  C = "https://bsv.brc.dev/apps/0198#listing-accumulation-v1",
  S = "https://bsv.brc.dev/apps/0198#standing-offer-v1",
  P = "https://bsv.brc.dev/apps/0198#paid-lookup-settlement-v1",
  F = "https://bsv.brc.dev/tokens/0197#revenue-listing-v1";
const profile = (n, f) => `https://bsv.brc.dev/overlays/0${n}#${f}`;
const keys = Object.fromEntries(
  Object.entries({
    seller: 41,
    recipientA: 42,
    recipientB: 43,
    buyerA: 44,
    buyerB: 45,
    controller: 46,
    processor: 47,
    rootA: 48,
    rootB: 49,
    sellerFunding: 50,
    buyerAFunding: 51,
    buyerBFunding: 52,
  }).map(([n, k]) => [n, new PrivateKey(k)]),
);
const wallets = Object.fromEntries(
  Object.entries(keys).map(([n, k]) => [n, new ProtoWallet(k)]),
);
const keybuf = (k) => Buffer.from(pub(k), "hex"),
  now = 1790611200,
  until = String(now + 600),
  recovery = String(now + 600 + 172800);
const vector = {
  version: 1,
  warning:
    "All keys are public fixtures. Synthetic easy-work chain, no mainnet claim; no network/wallet effects.",
  clock: now,
  actors: Object.fromEntries(
    Object.entries(keys).map(([n, k]) => [
      n,
      { scalar: Number(k.toString(10)), identity: pub(k) },
    ]),
  ),
  packets: [],
  lch: [],
  transactions: {},
  http: [],
  headers: [],
};
const packet = (type, body, key) => {
  const item = {
    type,
    body,
    signature: b64(SignedMessage.sign([...preimage(type, body)], key)),
    id: digest(type, body),
    preimage: hex(preimage(type, body)),
    signer: pub(key),
  };
  vector.packets.push(item);
  return { body, signature: item.signature };
};
const signed = (type, body, key) => {
  const obj = {
    body,
    signatures: [
      Buffer.from(SignedMessage.sign([...lchPreimage(type, body)], key)),
    ],
  };
  vector.lch.push({
    type,
    object: diagnostic(obj),
    id: hex(lchId(type, body)),
    cbor: hex(cbor(obj)),
    signer: pub(key),
  });
  return obj;
};
const retain = (tx, label) => {
  vector.transactions[tx.id("hex")] = {
    label,
    raw: tx.toHex(),
    beef: b64(tx.toAtomicBEEF()),
    sources: tx.inputs.map((i) => ({
      txid: i.sourceTXID ?? i.sourceTransaction?.id("hex"),
      index: i.sourceOutputIndex,
    })),
  };
  return tx;
};
const input = (tx, index) => ({
  sourceTransaction: tx,
  sourceTXID: tx.id("hex"),
  sourceOutputIndex: index,
  sequence: 0xffffffff,
  unlockingScript: UnlockingScript.fromHex(""),
});
function mine(root, previous, height) {
  const raw = Buffer.alloc(80);
  raw.writeInt32LE(1);
  Buffer.from(previous, "hex").reverse().copy(raw, 4);
  Buffer.from(root, "hex").reverse().copy(raw, 36);
  raw.writeUInt32LE(now + height, 68);
  raw.writeUInt32LE(0x207fffff, 72);
  let nonce = 0;
  const target = 0x7fffffn << 232n;
  while (true) {
    raw.writeUInt32LE(nonce++, 76);
    if (
      BigInt("0x" + Buffer.from(hash256(raw)).reverse().toString("hex")) <=
      target
    )
      break;
  }
  const hash = Buffer.from(hash256(raw)).reverse().toString("hex");
  vector.headers.push({
    height,
    raw: hex(raw),
    hash,
    merkleRoot: root,
    previous,
  });
  return hash;
}
const fundingOwners = [
  "sellerFunding",
  "buyerAFunding",
  "buyerBFunding",
  "buyerAFunding",
  "sellerFunding",
  "sellerFunding",
  "buyerAFunding",
];
const rootTx = new Transaction(
  1,
  [
    {
      sourceTXID: "00".repeat(32),
      sourceOutputIndex: 0xffffffff,
      unlockingScript: UnlockingScript.fromHex("020101"),
      sequence: 0xffffffff,
    },
  ],
  fundingOwners.map((n) =>
    output(1000000, new P2PKH().lock([...pkh(keys[n])])),
  ),
  0,
);
const genesisHash = mine(rootTx.id("hex"), "00".repeat(32), 0);
rootTx.merklePath = new MerklePath(0, [
  [{ offset: 0, hash: rootTx.id("hex"), txid: true }],
]);
retain(rootTx, "synthetic chain checkpoint");
const chain = { network: "brc-fixture-easy-work", genesisHash };
vector.chain = chain;
const anchor = { chain, txid: rootTx.id("hex"), outputIndex: 0 },
  seller = keys.seller,
  buyerA = keys.buyerA;
const initialRevenue = {
  recipients: [keys.recipientA, keys.recipientB]
    .sort((a, b) => (pub(a) < pub(b) ? -1 : 1))
    .map((k, i) => ({ identity: pub(k), weight: i ? 3 : 7 })),
};
const encryptionId = sha(Buffer.from("public fixture encryption id")),
  cek = sha(Buffer.from("public fixture CEK")),
  keyId = sha(Buffer.concat([Buffer.from("LCH key id v1\0"), cek])),
  noncePrefix = Buffer.from("01234567", "hex");
const plaintext = Buffer.from("Portable rights and exact revenue shares.\n"),
  segmentSize = 16,
  segmentCount = Math.ceil(plaintext.length / segmentSize);
const encryption = {
  algorithm: L + "a256gcm-segmented-v1",
  encryptionId,
  plaintextLength: plaintext.length,
  segmentSize,
  segmentCount,
  noncePrefix,
  keyPeriods: [{ keyId, firstSegment: 0, segmentCount }],
};
const be8 = (x) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(x));
  return b;
};
const records = [];
for (let i = 0; i < segmentCount; i++) {
  const iv = Buffer.concat([noncePrefix, be8(i)]),
    aad = Buffer.concat([
      Buffer.from("LCH A256GCM segmented v1\0"),
      encryptionId,
      be8(i),
      be8(segmentCount),
      be8(plaintext.length),
      keyId,
    ]);
  const enc = createCipheriv("aes-256-gcm", cek, iv);
  enc.setAAD(aad);
  records.push(
    Buffer.concat([
      enc.update(plaintext.subarray(i * segmentSize, (i + 1) * segmentSize)),
      enc.final(),
      enc.getAuthTag(),
    ]),
  );
}
const ciphertext = Buffer.concat(records);
vector.content = {
  plaintext: hex(plaintext),
  cek: hex(cek),
  ciphertext: hex(ciphertext),
  records: records.map(hex),
  encryption: diagnostic(encryption),
};
const asset = {
  mediaType: "text/plain",
  name: "example.txt",
  representation: {
    ciphertextDigest: sha(ciphertext),
    ciphertextLength: ciphertext.length,
    plaintextDigest: sha(plaintext),
    encryption,
    locators: ["https://content.example/example.bin"],
  },
  rights: [
    {
      interest: "work",
      holder: { name: "Fixture controller" },
      controller: keybuf(keys.controller),
    },
  ],
};
const assetId = lchId("asset", asset),
  assetIri = "lch:asset:sha256:" + hex(assetId),
  party = (k) => "lch:identity:secp256k1:" + pub(k),
  selection = { type: "all" };
vector.asset = {
  body: diagnostic(asset),
  cbor: hex(cbor(asset)),
  id: hex(assetId),
};
const authority = signed(
  "authority",
  {
    version: 1,
    assetId,
    grantor: keybuf(keys.controller),
    grantee: keybuf(seller),
    interests: ["work"],
    capabilities: [
      "publishHeader",
      "issueOffer",
      "issueLicense",
      "releaseKey",
      "receivePayment",
    ].map((x) => L + x),
    policyActions: ["http://www.w3.org/ns/odrl/2/play"],
    usageProfiles: [L + "fixed-render-v1"],
    notBefore: now - 10,
    notAfter: now + 400000,
    mayDelegate: false,
    nonce: Buffer.alloc(16, 7),
  },
  keys.controller,
);
const policy = (agreement, buyer) => ({
  "@context": ["http://www.w3.org/ns/odrl.jsonld", { lchv: L }],
  "@type": agreement ? "Agreement" : "Offer",
  uid: agreement ? "lch:license:self" : "lch:offer:self",
  profile: L + "odrl-profile",
  permission: [
    {
      target: assetIri,
      assigner: party(seller),
      ...(buyer ? { assignee: party(buyer) } : {}),
      action: "play",
      constraint: [
        {
          leftOperand: L + "selection",
          operator: "eq",
          rightOperand: {
            "@id": "lch:selection:sha256:" + hex(lchId("selection", selection)),
          },
        },
      ],
      duty: [
        {
          uid: "urn:fixture:duty:access",
          action: [
            {
              "rdf:value": { "@id": "odrl:compensate" },
              refinement: [
                {
                  leftOperand: "payAmount",
                  operator: "eq",
                  rightOperand: { "@value": "1001", "@type": "xsd:integer" },
                  unit: L + "satoshi",
                },
              ],
            },
          ],
          compensatedParty: party(seller),
        },
      ],
    },
  ],
});
const policyRef = (p) => {
  const inline = Buffer.from(canonical(p));
  return { mediaType: "application/ld+json", digest: sha(inline), inline };
};
const releasePolicy = {
  kind: "processor-accepted",
  identity: pub(keys.processor),
  policy: profile(196, "processor-attestation-v1"),
};
function offer(mode) {
  const covenant = mode === "listing-covenant",
    endpoint = "https://seller.example/api",
    route =
      endpoint +
      "/overlay/v1/" +
      (covenant ? "purchases/prepare" : "private/acquire"),
    binding = {
      version: 1,
      mode,
      seller: keybuf(seller),
      service: covenant ? "tm_listings" : "ls_catalogue",
      endpoint,
      chain: {
        network: chain.network,
        genesisHash: Buffer.from(chain.genesisHash, "hex"),
      },
      ...(covenant
        ? {
            lineageAnchor: {
              txid: Buffer.from(anchor.txid, "hex"),
              outputIndex: 0,
            },
            releasePolicy: Buffer.from(canonical(releasePolicy)),
          }
        : {}),
    };
  const body = {
    version: 1,
    assetId,
    usageProfile: L + "fixed-render-v1",
    seller: keybuf(seller),
    licenseIssuer: keybuf(seller),
    requiredInterests: ["work"],
    authorityIds: [lchId("authority", authority.body)],
    policy: policyRef(policy(false, covenant ? undefined : buyerA)),
    payment: {
      protocol: covenant ? C : L + "brc105-single-v1",
      endpoint: route,
      asset: "BSV",
      unit: "satoshi",
      recoveryPeriodSeconds: 172800,
      pricing: {
        kind: "fixed",
        requirements: [
          {
            dutyUid: "urn:fixture:duty:access",
            payee: keybuf(seller),
            ...(covenant ? {} : { buyer: keybuf(buyerA) }),
            endpoint: route,
            satoshis: 1001,
            interest: "work",
          },
        ],
      },
    },
    keyDelivery: { mechanism: L + "brc78-key-v1" },
    enforcement: {
      class: L + "conformingApplication",
      connectivity: L + "either",
    },
    notBefore: now - 1,
    notAfter: now + 600,
    nonce: Buffer.alloc(16, covenant ? 8 : 9),
    extensions: {
      [E]: binding,
      ...(covenant
        ? {
            [C]: {
              version: 1,
              family: F,
              expiryHeight: 123456,
              initialRevenue: {
                recipients: initialRevenue.recipients.map((r) => ({
                  identity: Buffer.from(r.identity, "hex"),
                  weight: r.weight,
                })),
              },
              schedule: "immutable",
              derivation: "brc29-anyone-fixed",
              withdrawal: "permissionless-quanta",
              remainders: "retain-until-payout",
              retirement: "seller-child-or-expiry-height-exact-top-up",
            },
            [S]: { version: 1 },
          }
        : { [P]: { version: 1 } }),
    },
    critical: covenant ? [E, C, S] : [E, P],
  };
  return signed("offer", body, seller);
}
const covenantOffer = offer("listing-covenant"),
  paidOffer = offer("paid-lookup");
const headerBody = {
  lch: 1,
  asset,
  acquisition: [
    { mode: "inline", offer: covenantOffer },
    { mode: "inline", offer: paidOffer },
  ],
  authority: [authority],
};
const headerSigned = signed("header", headerBody, seller);
const header = { ...headerBody, signatures: headerSigned.signatures };
vector.header = { object: diagnostic(header), cbor: hex(cbor(header)) };
const descriptor = {
  version: 1,
  chain,
  assetId: hex(assetId),
  seller: pub(seller),
  lineageAnchor: anchor,
  purchasePrice: "1001",
  reserve: "1",
  expiryHeight: 123456,
  termsDigest: hex(lchId("offer", covenantOffer.body)),
  scriptFamily: F,
  metadataDigest: hex(sha(Buffer.from("fixture metadata"))),
  initialRevenue,
};
const genesis = new Transaction(
  1,
  [input(rootTx, 0)],
  [
    output(1, encode(descriptor, initialRevenue)),
    output(999899, new P2PKH().lock([...pkh(keys.sellerFunding)])),
  ],
  0,
);
genesis.inputs[0].unlockingScript = await new P2PKH()
  .unlock(keys.sellerFunding)
  .sign(genesis, 0);
retain(genesis, "authorized listing genesis");
const activation = new Transaction(
  1,
  [input(genesis, 0), input(genesis, 1)],
  [
    output(1, encode(descriptor, initialRevenue, "active")),
    output(999799, new P2PKH().lock([...pkh(keys.sellerFunding)])),
  ],
  0,
);
activation.inputs[0].unlockingScript = unlock(activation, 0, {
  operation: 0,
  descriptor,
  changeHash: pkh(keys.sellerFunding),
  changeAmount: 999799,
});
activation.inputs[1].unlockingScript = await new P2PKH()
  .unlock(keys.sellerFunding)
  .sign(activation, 1);
retain(activation, "public-key linkage activation");
assert(evaluate(activation, 0));
const genesisAuth = packet(
  "sale-genesis",
  {
    version: 1,
    listingId: digest("sale-listing", descriptor),
    genesis: { chain, txid: genesis.id("hex"), outputIndex: 0 },
  },
  seller,
);
const lineage = (txs) => ({
  version: 1,
  descriptor,
  genesis: genesisAuth,
  target: { chain, txid: txs.at(-1).id("hex"), outputIndex: 0 },
  transactions: txs
    .map((tx) => ({ txid: tx.id("hex"), beef: b64(tx.toAtomicBEEF()) }))
    .sort((a, b) => (a.txid < b.txid ? -1 : 1)),
});
vector.descriptor = descriptor;
const rules = {
  id: "urn:brc-fixture:catalogue-rules:1",
  parameters: {
    order: "outpoint",
    visibility: "authorized",
    selection: "listing-descendants",
  },
};
const rulesDigest = digest("service-rules", rules);
const policyRegistration = {
  id: profile(194, "author-document-v1"),
  parameters: { maxTextBytes: 4096 },
};
const proposalPolicy = {
  ...policyRegistration,
  digest: digest("proposal-policy", policyRegistration),
};
const prof = (id, authentication, payment, parameters) => ({
  id,
  authentication,
  payment,
  maxRequestBytes: 1048576,
  maxResponseBytes: 4194304,
  parameters,
});
const capabilityBody = {
  version: 1,
  identity: pub(seller),
  baseURL: "https://seller.example/api",
  chain,
  issuedAt: String(now - 1),
  expiresAt: String(now + 1000),
  services: [
    {
      name: "ls_catalogue",
      kind: "lookup",
      rules,
      rulesDigest,
      profiles: [
        prof(profile(193, "lookup-live-v1"), "brc103", "none", {
          replaySeconds: "600",
          sessionSeconds: "300",
          maxObservations: 1024,
          maxWaitMs: 25000,
        }),
        prof(profile(195, "paid-lookup-v1"), "brc103", "brc105", {
          recoverySeconds: "172800",
          acceptancePolicy: releasePolicy,
        }),
      ],
    },
    {
      name: "tm_listings",
      kind: "topic",
      rules,
      rulesDigest,
      profiles: [
        prof(profile(194, "proposal-v1"), "brc103", "none", {
          policies: [proposalPolicy],
          maxLifetimeSeconds: "3600",
          retentionSeconds: "86400",
        }),
        prof(profile(195, "private-publish-v1"), "brc103", "none", {
          maxPrivateBytes: 1048576,
          schemas: ["urn:brc-fixture:key-publication:1"],
        }),
        prof(profile(196, "steak-potatoes-v1"), "brc103", "covenant", {
          recoverySeconds: "172800",
          releasePolicies: [
            releasePolicy,
            { kind: "local-admission" },
            { kind: "mined", confirmations: 1 },
          ],
          domainProfiles: [
            "https://bsv.brc.dev/tokens/0197#listing-purchase-v1",
          ],
        }),
      ],
    },
    {
      name: "root-advertisements",
      kind: "coordination",
      rules,
      rulesDigest,
      profiles: [
        prof(profile(199, "root-eviction-v1"), "brc103", "none", {
          maxTargets: 64,
          maxLifetimeSeconds: "86400",
        }),
      ],
    },
  ],
  extensions: {
    [E]: {
      version: 1,
      bindings: [
        {
          kind: "lookup",
          service: "ls_catalogue",
          mode: "paid-lookup",
          mechanisms: [
            E,
            P,
            L + "brc105-single-v1",
            L + "fixed-render-v1",
            L + "a256gcm-segmented-v1",
            L + "brc78-key-v1",
          ].sort(),
        },
        {
          kind: "topic",
          service: "tm_listings",
          mode: "listing-covenant",
          mechanisms: [
            E,
            C,
            S,
            F,
            L + "fixed-render-v1",
            L + "a256gcm-segmented-v1",
            L + "brc78-key-v1",
          ].sort(),
        },
      ],
    },
  },
};
const capability = packet("capabilities", capabilityBody, seller),
  capabilityId = digest("capabilities", capabilityBody);
vector.capability = capability;
const request = (offer, buyer, nonce) =>
  signed(
    "license-request",
    {
      version: 1,
      offerId: lchId("offer", offer.body),
      assetId,
      buyer: keybuf(buyer),
      action: "http://www.w3.org/ns/odrl/2/play",
      selection,
      acceptedPolicyDigest: offer.body.policy.digest,
      requestNonce: Buffer.alloc(16, nonce),
      createdAt: now,
    },
    buyer,
  );
const releases = (tx) => {
  const p = packet(
    "processor-acceptance",
    {
      version: 1,
      chain,
      txid: tx.id("hex"),
      policy: releasePolicy.policy,
      acceptedAt: String(now + 1),
    },
    keys.processor,
  );
  return {
    chain,
    txid: tx.id("hex"),
    policy: releasePolicy,
    acceptedAt: String(now + 1),
    processorEvidence: b64(Buffer.from(canonical(p))),
  };
};
function license(offer, req, buyer, settlement, mode) {
  const fulfillmentProfile = mode === "listing-covenant" ? C : P,
    stType =
      mode === "listing-covenant"
        ? "lch-covenant-settlement"
        : "lch-lookup-settlement",
    settlementId = Buffer.from(digest(stType, settlement.body), "hex");
  return signed(
    "license",
    {
      version: 1,
      assetId,
      offerId: lchId("offer", offer.body),
      requestId: lchId("license-request", req.body),
      issuer: keybuf(seller),
      subject: keybuf(buyer),
      issuedAt: now + 2,
      agreement: policyRef(policy(true, buyer)),
      selection,
      segmentSelection: { type: "segments", ranges: [[0, segmentCount]] },
      fulfillments: [
        {
          dutyUid: "urn:fixture:duty:access",
          settlementProfile: fulfillmentProfile,
          receiptIds: [settlementId],
        },
      ],
      keyGrants: [
        {
          keyId,
          delivery: L + "brc78-key-v1",
          payload: Buffer.from(
            EncryptedMessage.encrypt(
              [...Buffer.concat([keyId, cek])],
              seller,
              buyer.toPublicKey(),
            ),
          ),
        },
      ],
      extensions: {
        [E]: { version: 1, mode, settlementId },
        [fulfillmentProfile]: { version: 1 },
      },
      critical: [E, fulfillmentProfile],
    },
    seller,
  );
}
vector.acquisitions = [];
let current = activation,
  ancestors = [genesis, activation];
for (const [buyerName, nonce, fundingIndex] of [
  ["buyerA", 10, 1],
  ["buyerB", 11, 2],
]) {
  const buyer = keys[buyerName],
    req = request(covenantOffer, buyer, nonce),
    requestId = hex(lchId("license-request", req.body)),
    listing = { chain, txid: current.id("hex"), outputIndex: 0 },
    domainEvidence = lineage(ancestors);
  const prepare = {
      version: 1,
      requestId,
      topic: "tm_listings",
      listing,
      assetId: hex(assetId),
      termsDigest: descriptor.termsDigest,
      recipient: pub(buyer),
      request: b64(cbor(req)),
    },
    acquisitionId = digest("purchase", {
      chain,
      seller: pub(seller),
      recipient: pub(buyer),
      topic: "tm_listings",
      requestId,
    }),
    requestDigest = digest("purchase-request", prepare);
  const terms = packet(
    "purchase-terms",
    {
      version: 1,
      acquisitionId,
      requestDigest,
      seller: pub(seller),
      recipient: pub(buyer),
      topic: "tm_listings",
      listing,
      assetId: hex(assetId),
      termsDigest: descriptor.termsDigest,
      domainProfile: "https://bsv.brc.dev/tokens/0197#listing-purchase-v1",
      domainEvidence: {
        schema: "https://bsv.brc.dev/tokens/0197#lineage-package-v1",
        bytes: b64(Buffer.from(canonical(domainEvidence))),
      },
      releasePolicy,
      purchaseUntil: until,
      recoveryUntil: recovery,
    },
    seller,
  );
  const receipt = LockingScript.fromHex(
    hex(
      purchaseReceipt(
        {
          listingId: digest("sale-listing", descriptor),
          termsDigest: descriptor.termsDigest,
        },
        acquisitionId,
        requestDigest,
        pub(buyer),
      ),
    ),
  );
  const tx = new Transaction(
    1,
    [input(current, 0), input(rootTx, fundingIndex)],
    [
      output(
        current.outputs[0].satoshis + 1001,
        current.outputs[0].lockingScript,
      ),
      output(1, receipt),
      output(998898, new P2PKH().lock([...pkh(keys[buyerName+"Funding"])])),
    ],
    0,
  );
  tx.inputs[0].unlockingScript = unlock(tx, 0, {
    operation: 1,
    receipt,
    recipientY: ys(buyer),
    changeHash: pkh(keys[buyerName+"Funding"]),
    changeAmount: 998898,
  });
  tx.inputs[1].unlockingScript = await new P2PKH().unlock(keys[buyerName+"Funding"]).sign(tx, 1);
  retain(tx, buyerName + " purchase");
  assert(evaluate(tx, 0));
  const purchaseCommitment = hex(hash256(covenantPreimage(tx, 0)));
  const release = releases(tx);
  const settlement = packet(
    "lch-covenant-settlement",
    {
      version: 1,
      seller: pub(seller),
      buyer: pub(buyer),
      requestId,
      offerId: descriptor.termsDigest,
      assetId: hex(assetId),
      dutyUid: "urn:fixture:duty:access",
      acquisitionId,
      listingId: digest("sale-listing", descriptor),
      previous: listing,
      successor: { chain, txid: tx.id("hex"), outputIndex: 0 },
      txid: tx.id("hex"),
      purchaseCommitment,
      satoshis: "1001",
      releasePolicy,
      releaseEvidenceDigest: digest("release-evidence", release),
      issuedAt: String(now + 2),
      recoveryUntil: recovery,
    },
    seller,
  );
  const lic = license(
      covenantOffer,
      req,
      buyer,
      settlement,
      "listing-covenant",
    ),
    purchase = {
      txid: tx.id("hex"),
      outputIndex: 0,
      beef: b64(tx.toAtomicBEEF()),
    },
    purchaseEvidence = {
      version: 1,
      lineage: domainEvidence,
      purchase,
      terms,
      release,
    };
  const context = {
    version: 1,
    license: lic,
    evidence: [
      { type: "authority", object: authority },
      { type: "offer", object: covenantOffer },
    ],
    settlement: Buffer.from(canonical(settlement)),
    purchaseEvidence: Buffer.from(canonical(purchaseEvidence)),
  };
  const potatoes = packet(
    "potatoes",
    {
      version: 1,
      acquisitionId,
      requestDigest,
      seller: pub(seller),
      recipient: pub(buyer),
      topic: "tm_listings",
      txid: tx.id("hex"),
      purchaseCommitment,
      assetId: hex(assetId),
      termsDigest: descriptor.termsDigest,
      releasePolicy,
      evidenceDigest: digest("release-evidence", release),
      schema: E,
      secret: b64(cbor(context)),
      issuedAt: String(now + 2),
      recoveryUntil: recovery,
    },
    seller,
  );
  const result = {
    version: 1,
    acquisitionId,
    txid: tx.id("hex"),
    purchaseCommitment,
    status: "delivered",
    steak: {
      tm_listings: {
        outputsToAdmit: [0],
        coinsToRetain: [0],
        coinsRemoved: [0],
      },
    },
    potatoes,
    recoveryUntil: recovery,
  };
  vector.acquisitions.push({
    mode: "listing-covenant",
    buyer: buyerName,
    request: diagnostic(req),
    prepare,
    terms,
    submit: {
      version: 1,
      acquisitionId,
      txid: tx.id("hex"),
      beef: b64(tx.toAtomicBEEF()),
    },
    pending: {
      result: {
        version: 1,
        acquisitionId,
        txid: tx.id("hex"),
        purchaseCommitment,
        status: "admitted-delivery-pending",
        steak: result.steak,
        recoveryUntil: recovery,
      },
    },
    envelope: { result, releaseEvidence: release },
    context: diagnostic(context),
    contextCBOR: hex(cbor(context)),
    lineage: domainEvidence,
  });
  current = tx;
  ancestors.push(tx);
}
// Paid lookup uses a real BRC-29 destination, independently derivable by payee.
const paidRequest = request(paidOffer, buyerA, 12),
  paidId = hex(lchId("license-request", paidRequest.body)),
  listing = { chain, txid: genesis.id("hex"), outputIndex: 0 };
const acquire = {
  version: 1,
  requestId: paidId,
  service: "ls_catalogue",
  assetId: hex(assetId),
  listing,
  termsDigest: hex(lchId("offer", paidOffer.body)),
  recipient: pub(buyerA),
  request: b64(cbor(paidRequest)),
};
const acquisitionId = digest("acquisition", {
    chain,
    seller: pub(seller),
    buyer: pub(buyerA),
    service: "ls_catalogue",
    requestId: paidId,
  }),
  prefix = b64(Buffer.alloc(32, 0x51)),
  suffix = b64(Buffer.alloc(32, 0x52)),
  invoice = "2-3241645161d8-" + prefix + " " + suffix;
const destination = seller.toPublicKey().deriveChild(buyerA, invoice),
  privateDestination = seller.deriveChild(buyerA.toPublicKey(), invoice);
assert.equal(
  destination.toString(),
  privateDestination.toPublicKey().toString(),
);
const payment = new Transaction(
  1,
  [input(rootTx, 3)],
  [
    output(1001, new P2PKH().lock(destination.toAddress())),
    output(998899, new P2PKH().lock([...pkh(keys.buyerAFunding)])),
  ],
  0,
);
payment.inputs[0].unlockingScript = await new P2PKH()
  .unlock(keys.buyerAFunding)
  .sign(payment, 0);
retain(payment, "BRC-105 payment");
const challenge = {
    version: 1,
    acquisitionId,
    requestDigest: digest("acquire-request", acquire),
    seller: pub(seller),
    buyer: pub(buyerA),
    assetId: hex(assetId),
    termsDigest: acquire.termsDigest,
    satoshis: "1001",
    derivationPrefix: prefix,
    acceptancePolicy: releasePolicy,
    rulesDigest,
    payableUntil: until,
    recoveryUntil: recovery,
  },
  release = releases(payment),
  funding = { chain, txid: payment.id("hex"), outputIndex: 0 };
const settlement = packet(
  "lch-lookup-settlement",
  {
    version: 1,
    seller: pub(seller),
    buyer: pub(buyerA),
    requestId: paidId,
    offerId: acquire.termsDigest,
    assetId: hex(assetId),
    dutyUid: "urn:fixture:duty:access",
    acquisitionId,
    funding,
    satoshis: "1001",
    acceptancePolicy: releasePolicy,
    releaseEvidenceDigest: digest("release-evidence", release),
    issuedAt: String(now + 2),
    recoveryUntil: recovery,
  },
  seller,
);
const paidLicense = license(
    paidOffer,
    paidRequest,
    buyerA,
    settlement,
    "paid-lookup",
  ),
  paymentEvidence = {
    version: 1,
    challenge,
    payment: {
      txid: payment.id("hex"),
      outputIndex: 0,
      beef: b64(payment.toAtomicBEEF()),
    },
    release,
    derivationSuffix: suffix,
  },
  paidContext = {
    version: 1,
    license: paidLicense,
    evidence: [
      { type: "authority", object: authority },
      { type: "offer", object: paidOffer },
    ],
    settlement: Buffer.from(canonical(settlement)),
    paymentEvidence: Buffer.from(canonical(paymentEvidence)),
  };
const acquired = {
  version: 1,
  acquisitionId,
  status: "delivered",
  recoveryUntil: recovery,
  challenge,
  funding,
  acceptance: release,
  result: {
    evidence: {
      txid: genesis.id("hex"),
      outputIndex: 0,
      beef: b64(genesis.toAtomicBEEF()),
    },
    context: b64(cbor(paidContext)),
    schema: E,
  },
};
const paymentHeader = {
  derivationPrefix: prefix,
  derivationSuffix: suffix,
  transaction: b64(payment.toAtomicBEEF()),
};
vector.acquisitions.push({
  mode: "paid-lookup",
  buyer: "buyerA",
  request: diagnostic(paidRequest),
  acquire,
  challenge,
  paymentHeader,
  result: acquired,
  context: diagnostic(paidContext),
  contextCBOR: hex(cbor(paidContext)),
  expectedPaymentScript: payment.outputs[0].lockingScript.toHex(),
});
// Same body, newly randomized BRC-77 signature: same inner ID, outer conflict.
const resigned = signed("license-request", paidRequest.body, buyerA);
vector.retry = {
  original: acquire,
  resigned: { ...acquire, request: b64(cbor(resigned)) },
  innerId: paidId,
  expected: "conflict-no-payment",
};
const publication = {
  version: 1,
  requestId: "publication-example-0001",
  topic: "tm_listings",
  evidence: {
    txid: activation.id("hex"),
    outputIndex: 0,
    beef: b64(activation.toAtomicBEEF()),
  },
  assetId: hex(assetId),
  schema: "urn:brc-fixture:key-publication:1",
  privateValues: b64(Buffer.concat([assetId, keyId, cek])),
};
vector.publication = {
  request: publication,
  proofVariant: {
    ...publication,
    evidence: { ...publication.evidence, beef: b64(activation.toBEEF()) },
  },
  result: {
    version: 1,
    publicationId: digest("private-publication", {
      chain,
      publisher: pub(seller),
      topic: "tm_listings",
      requestId: publication.requestId,
    }),
    txid: activation.id("hex"),
    status: "ready",
    updatedAt: String(now),
  },
};
const proposal = packet(
  "proposal",
  {
    version: 1,
    service: "tm_listings",
    chain,
    policy: { id: proposalPolicy.id, digest: proposalPolicy.digest },
    channel: hex(sha(Buffer.from("fixture channel"))),
    revision: "0",
    previous: null,
    author: pub(buyerA),
    recipients: [pub(seller), pub(buyerA)].sort(),
    anchors: [],
    issuedAt: String(now),
    expiresAt: String(now + 60),
    operation: "update",
    payload: b64(
      Buffer.from(canonical({ text: "A shared proposed document." })),
    ),
  },
  buyerA,
);
vector.proposal = proposal;
const finalScript = LockingScript.fromHex(
  "006a24" +
    Buffer.from("PRP1").toString("hex") +
    digest("proposal", proposal.body),
);
const finalizationTx = new Transaction(
  1,
  [input(rootTx, 6)],
  [output(1, finalScript), output(999899, new P2PKH().lock([...pkh(keys.buyerAFunding)]))],
  0,
);
finalizationTx.inputs[0].unlockingScript = await new P2PKH()
  .unlock(keys.buyerAFunding)
  .sign(finalizationTx, 0);
retain(finalizationTx, "author-document finalization");
vector.proposalFinalization = {
  version: 1,
  operationId: "proposal-finalize-0001",
  service: "tm_listings",
  proposalId: digest("proposal", proposal.body),
  beef: b64(finalizationTx.toAtomicBEEF()),
  txid: finalizationTx.id("hex"),
};

// Actual SHIP and SLAP scripts, signed by their advertising identity.
vector.advertisements = [];
for (const [protocol, name, index] of [
  ["SHIP", "tm_listings", 4],
  ["SLAP", "ls_catalogue", 5],
]) {
  const template = new OverlayAdminTokenTemplate(wallets.seller),
    script = await template.lock(protocol, "https://seller.example", name);
  const tx = new Transaction(
    1,
    [input(rootTx, index)],
    [output(1, script), output(999899, new P2PKH().lock([...pkh(keys.sellerFunding)]))],
    0,
  );
  tx.inputs[0].unlockingScript = await new P2PKH().unlock(keys.sellerFunding).sign(tx, 0);
  retain(tx, protocol + " advertisement");
  vector.advertisements.push({
    protocol,
    decoded: await OverlayAdminTokenTemplate.decodeAndVerify(script, protocol),
    evidence: {
      txid: tx.id("hex"),
      outputIndex: 0,
      beef: b64(tx.toAtomicBEEF()),
    },
  });
}
vector.rootRequests = [];
for (const rootName of ["rootA", "rootB"]) {
  const adv = vector.advertisements[0],
    tx = Transaction.fromHex(vector.transactions[adv.evidence.txid].raw),
    outpoint = { chain, txid: adv.evidence.txid, outputIndex: 0 },
    advertisementDigest = digest("root-advertisement", {
      service: "ls_ship",
      outpoint,
      lockingScript: b64(tx.outputs[0].lockingScript.toBinary()),
    }),
    body = {
      version: 1,
      requestId: "eviction-" + rootName + "-0001",
      requester: pub(seller),
      recipient: pub(keys[rootName]),
      chain,
      issuedAt: String(now),
      expiresAt: String(now + 60),
      action: "suppress",
      targets: [
        {
          service: "ls_ship",
          outpoint,
          advertisementDigest,
          evidence: { kind: "owner-withdrawal", advertisement: adv.evidence },
          advertisement: adv.evidence,
        },
      ],
      reason: "owner-withdrawal",
    };
  vector.rootRequests.push(packet("root-eviction-request", body, seller));
}
// Separate action history from current serving state, including independent roots.
vector.rootTrace = [];
const rootA = keys.rootA,
  firstRootRequest = vector.rootRequests[0],
  target = firstRootRequest.body.targets[0];
const rootPolicy = digest("fixture-root-policy", {
    mode: "authorized-owner",
    chain,
  }),
  rootBPolicy = digest("fixture-root-policy", { mode: "manual-review", chain });
const blockers = [];
let revision = 0;
for (const [name, action, restores] of [
  ["suppress-A", "suppress", null],
  ["suppress-B", "suppress", null],
  ["restore-A", "restore", 0],
  ["restore-B", "restore", 1],
]) {
  const body = {
    ...firstRootRequest.body,
    requestId: "root-trace-" + name,
    action,
    targets: [
      {
        ...target,
        ...(restores === null
          ? {}
          : {
              restores:
                vector.rootTrace[restores].result.body.outcomes[0].decisionId,
            }),
      },
    ],
  };
  const request = packet("root-eviction-request", body, seller),
    requestDigest = digest("root-eviction-request", body);
  revision++;
  const decisionId = digest("root-eviction-decision", {
    root: pub(rootA),
    requestDigest,
    service: target.service,
    outpoint: target.outpoint,
    revision: String(revision),
  });
  const affected =
    restores === null ? [decisionId] : [body.targets[0].restores];
  if (action === "suppress")
    blockers.push({ decisionId, policyDigest: rootPolicy });
  else
    blockers.splice(
      blockers.findIndex((x) => x.decisionId === affected[0]),
      1,
    );
  const outcome = {
    service: target.service,
    outpoint: target.outpoint,
    actionStatus: "applied",
    reasonCode:
      action === "suppress" ? "owner-withdrawal" : "authorized-restore",
    decisionId,
    affectedDecisionIds: affected,
    revision: String(revision),
    serving: {
      state: blockers.length ? "suppressed" : "eligible",
      revision: String(revision),
      blockers: [...blockers].sort((a, b) =>
        a.decisionId < b.decisionId ? -1 : 1,
      ),
    },
  };
  const result = packet(
    "root-eviction-result",
    {
      version: 1,
      requestDigest,
      root: pub(rootA),
      policyDigest: rootPolicy,
      issuedAt: String(now + revision),
      outcomes: [outcome],
    },
    rootA,
  );
  vector.rootTrace.push({
    name,
    request,
    result,
    expectedServing: outcome.serving.state,
  });
}
const blockedRequest = vector.rootRequests[1],
  rootBResult = packet(
    "root-eviction-result",
    {
      version: 1,
      requestDigest: digest("root-eviction-request", blockedRequest.body),
      root: pub(keys.rootB),
      policyDigest: rootBPolicy,
      issuedAt: String(now),
      outcomes: [
        {
          service: target.service,
          outpoint: target.outpoint,
          actionStatus: "rejected",
          reasonCode: "manual-review-required",
          affectedDecisionIds: [],
          revision: "0",
          serving: { state: "eligible", revision: "0", blockers: [] },
        },
      ],
    },
    keys.rootB,
  );
vector.rootIndependentResult = rootBResult;

// Authenticated complete HTTP messages. Crypto transcript, not a running server.
let httpSerial = 1;
const sessionNonce = {
  buyerA: b64(Buffer.alloc(32, 21)),
  seller: b64(Buffer.alloc(32, 22)),
};
const handshakeData = Buffer.concat([
  Buffer.from(sessionNonce.buyerA, "base64"),
  Buffer.from(sessionNonce.seller, "base64"),
]);
const handshakeSig = await wallets.seller.createSignature({
  data: [...handshakeData],
  protocolID: [2, "auth message signature"],
  keyID: sessionNonce.buyerA + " " + sessionNonce.seller,
  counterparty: pub(buyerA),
});
vector.handshake = {
  initialRequest: {
    version: "0.1",
    messageType: "initialRequest",
    identityKey: pub(buyerA),
    initialNonce: sessionNonce.buyerA,
  },
  initialResponse: {
    version: "0.1",
    messageType: "initialResponse",
    identityKey: pub(seller),
    initialNonce: sessionNonce.seller,
    yourNonce: sessionNonce.buyerA,
    signature: hex(handshakeSig.signature),
  },
  data: hex(handshakeData),
};
async function http(kind, path, body, p, status = 200, extra = {}, requestId) {
  const sender = kind === "request" ? "buyerA" : "seller",
    receiver = sender === "buyerA" ? "seller" : "buyerA",
    nonce = b64(sha(Buffer.from("http nonce " + httpSerial++))),
    headers = {
      "content-type": "application/json",
      "x-bsv-overlay-capability": capabilityId,
      "x-bsv-overlay-profile": p,
      ...extra,
    };
  if (kind === "response") headers["cache-control"] = "private, no-store";
  const item = {
    kind,
    method: "POST",
    path,
    query: "",
    status,
    requestId: requestId ?? b64(sha(Buffer.from("request " + httpSerial))),
    headers,
    body: b64(Buffer.from(canonical(body))),
    sender,
    receiver,
    nonce,
    yourNonce: sessionNonce[receiver],
  };
  const payload = httpPayload(item),
    sig = await wallets[sender].createSignature({
      data: [...payload],
      protocolID: [2, "auth message signature"],
      keyID: nonce + " " + item.yourNonce,
      counterparty: pub(keys[receiver]),
    });
  item.signature = hex(sig.signature);
  item.payload = hex(payload);
  item.headers = {
    ...headers,
    "x-bsv-auth-version": "0.1",
    "x-bsv-auth-identity-key": pub(keys[sender]),
    "x-bsv-auth-nonce": nonce,
    "x-bsv-auth-your-nonce": item.yourNonce,
    "x-bsv-auth-request-id": item.requestId,
    "x-bsv-auth-signature": item.signature,
  };
  vector.http.push(item);
  return item.requestId;
}
const limits = { maxBytes: 4194304, maxObservations: 1024, waitMs: 0 },
  query = { assetId: hex(assetId) },
  scope = {
    chain,
    provider: pub(seller),
    service: "ls_catalogue",
    queryDigest: digest("lookup-query", { service: "ls_catalogue", query }),
    rulesDigest,
    access: "public",
    epoch: "fixture-epoch-1",
  },
  session = b64(Buffer.alloc(32, 31)),
  open = {
    version: 1,
    requestId: "open-example-0001",
    service: "ls_catalogue",
    query,
    requiredRulesDigest: rulesDigest,
    limits,
  };
const observation = {
  id: "snapshot/1/output/0",
  scope,
  kind: "output",
  payload: {
    evidence: {
      txid: activation.id("hex"),
      outputIndex: 0,
      beef: b64(activation.toAtomicBEEF()),
    },
  },
};
const batch = {
  version: 1,
  session,
  scope,
  phase: "snapshot",
  groups: [
    { id: "snapshot/1/group/0", sequence: "10", observations: [observation] },
  ],
  cursor: b64(Buffer.alloc(32, 32)),
  snapshotComplete: true,
  through: "10",
  highWater: "12",
  expiresAt: String(now + 300),
  replayUntil: String(now + 900),
  limits,
};
let rid = await http(
  "request",
  "/api/overlay/v1/lookup/open",
  open,
  profile(193, "lookup-live-v1"),
);
await http(
  "response",
  "/api/overlay/v1/lookup/open",
  batch,
  profile(193, "lookup-live-v1"),
  200,
  {},
  rid,
);
const firstPurchase = vector.acquisitions[0],
  spentObs = {
    id: "live/12/spend",
    scope,
    kind: "spend",
    payload: {
      previous: { chain, txid: activation.id("hex"), outputIndex: 0 },
      spendingTxid: firstPurchase.submit.txid,
      beef: firstPurchase.submit.beef,
    },
  },
  createdObs = {
    id: "live/12/output",
    scope,
    kind: "output",
    payload: {
      evidence: {
        txid: firstPurchase.submit.txid,
        outputIndex: 0,
        beef: firstPurchase.submit.beef,
      },
    },
  },
  live = {
    ...batch,
    phase: "live",
    groups: [
      { id: "live/12", sequence: "12", observations: [spentObs, createdObs] },
    ],
    cursor: b64(Buffer.alloc(32, 33)),
    through: "12",
    highWater: "13",
  };
rid = await http(
  "request",
  "/api/overlay/v1/lookup/read",
  { version: 1, session, cursor: batch.cursor, limits },
  profile(193, "lookup-live-v1"),
);
await http(
  "response",
  "/api/overlay/v1/lookup/read",
  live,
  profile(193, "lookup-live-v1"),
  200,
  {},
  rid,
);
rid = await http(
  "request",
  "/api/overlay/v1/lookup/close",
  { version: 1, session },
  profile(193, "lookup-live-v1"),
);
await http(
  "response",
  "/api/overlay/v1/lookup/close",
  { version: 1, closed: true },
  profile(193, "lookup-live-v1"),
  200,
  {},
  rid,
);
rid = await http(
  "request",
  "/api/overlay/v1/private/acquire",
  acquire,
  profile(195, "paid-lookup-v1"),
);
await http(
  "response",
  "/api/overlay/v1/private/acquire",
  challenge,
  profile(195, "paid-lookup-v1"),
  402,
  {
    "x-bsv-payment-version": "1.0",
    "x-bsv-payment-satoshis-required": "1001",
    "x-bsv-payment-derivation-prefix": prefix,
  },
  rid,
);
rid = await http(
  "request",
  "/api/overlay/v1/private/acquire",
  acquire,
  profile(195, "paid-lookup-v1"),
  200,
  { "x-bsv-payment": canonical(paymentHeader) },
);
await http(
  "response",
  "/api/overlay/v1/private/acquire",
  acquired,
  profile(195, "paid-lookup-v1"),
  200,
  {},
  rid,
);
for (const [route, body, response] of [
  ["prepare", firstPurchase.prepare, firstPurchase.terms],
  ["submit", firstPurchase.submit, firstPurchase.pending],
  [
    "recover",
    { version: 1, acquisitionId: firstPurchase.terms.body.acquisitionId },
    firstPurchase.envelope,
  ],
]) {
  rid = await http(
    "request",
    "/api/overlay/v1/purchases/" + route,
    body,
    profile(196, "steak-potatoes-v1"),
  );
  await http(
    "response",
    "/api/overlay/v1/purchases/" + route,
    response,
    profile(196, "steak-potatoes-v1"),
    200,
    {},
    rid,
  );
}
rid = await http(
  "request",
  "/api/overlay/v1/proposals/put",
  { version: 1, proposal },
  profile(194, "proposal-v1"),
);
await http(
  "response",
  "/api/overlay/v1/proposals/put",
  {
    version: 1,
    proposalId: digest("proposal", proposal.body),
    status: "recorded",
    expiresAt: proposal.body.expiresAt,
  },
  profile(194, "proposal-v1"),
  200,
  {},
  rid,
);
rid = await http(
  "request",
  "/api/overlay/v1/proposals/finalize",
  vector.proposalFinalization,
  profile(194, "proposal-v1"),
);
await http(
  "response",
  "/api/overlay/v1/proposals/finalize",
  {
    version: 1,
    proposalId: digest("proposal", proposal.body),
    state: {
      status: "finalized",
      recordedAt: String(now + 2),
      operationId: vector.proposalFinalization.operationId,
      txid: finalizationTx.id("hex"),
      steak: { tm_listings: { outputsToAdmit: [0], coinsToRetain: [] } },
      assessmentContextId: "fixture-view-0",
    },
  },
  profile(194, "proposal-v1"),
  200,
  {},
  rid,
);

vector.live = {
  open,
  batch,
  live,
  emptySnapshot: { ...batch, groups: [] },
  localPartition: {
    application: "fixture",
    account: "buyerA",
    access: "public",
  },
};
// Later synthetic inclusion of the first purchase gives a second valid BEEF
// variant and a real Merkle/PoW path under the explicitly selected fixture policy.
const minedTx = Transaction.fromBEEF([
  ...Buffer.from(firstPurchase.submit.beef, "base64"),
]);
const blockHash = mine(minedTx.id("hex"), genesisHash, 1);
minedTx.merklePath = new MerklePath(1, [
  [{ offset: 0, hash: minedTx.id("hex"), txid: true }],
]);
vector.mined = {
  chain,
  txid: minedTx.id("hex"),
  policy: { kind: "mined", confirmations: 1 },
  acceptedAt: String(now + 3),
  blockEvidence: {
    blockHash,
    height: "1",
    tipHash: blockHash,
    tipHeight: "1",
    beef: b64(minedTx.toAtomicBEEF()),
    contextId: "fixture-view-1",
    chainPolicyDigest: digest("fixture-chain-policy", {
      genesisHash,
      bits: 0x207fffff,
    }),
  },
};
const replacementHash = mine(payment.id("hex"), genesisHash, 1);
vector.reorganization = {
  oldTip: blockHash,
  newTip: replacementHash,
  affectedTxid: minedTx.id("hex"),
  expected: "stale-not-erased",
};
const data = Buffer.from(JSON.stringify(vector)),
  archive = gzipSync(data, { level: 9 });
writeFileSync(new URL("./wire-vectors.json.gz", import.meta.url), archive);
writeFileSync(
  new URL("./wire-manifest.json", import.meta.url),
  JSON.stringify(
    {
      version: 1,
      archive: "wire-vectors.json.gz",
      sha256: hex(sha(archive)),
      decodedBytes: data.length,
      clock: now,
      chain,
      counts: {
        packets: vector.packets.length,
        lch: vector.lch.length,
        http: vector.http.length,
        transactions: Object.keys(vector.transactions).length,
        acquisitions: vector.acquisitions.length,
      },
      warning: vector.warning,
    },
    null,
    2,
  ) + "\n",
);
console.log(
  JSON.stringify({
    wireBytes: data.length,
    archiveBytes: archive.length,
    packets: vector.packets.length,
    http: vector.http.length,
  }),
);
