// Authoring tool only. PUBLIC fixture scalar; no network or wallet operations.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import {
  Transaction,
  PrivateKey,
  P2PKH,
  UnlockingScript,
  Hash,
  MerklePath,
} from "@bsv/sdk";
const key = new PrivateKey(63),
  lock = new P2PKH().lock(Hash.hash160(key.toPublicKey().encode(true)));
const txs = {},
  names = new Map();
function keep(name, tx) {
  txs[name] = tx;
  names.set(tx.id("hex"), name);
  return tx;
}
const root = keep(
  "root",
  new Transaction(
    1,
    [
      {
        sourceTXID: "00".repeat(32),
        sourceOutputIndex: 0xffffffff,
        unlockingScript: UnlockingScript.fromHex("020101"),
        sequence: 0xffffffff,
      },
    ],
    [{ satoshis: 1000000, lockingScript: lock }],
    0,
  ),
);
async function spend(
  name,
  sources,
  amounts,
  sequences = sources.map(() => 0xffffffff),
  lockTime = 0,
) {
  const tx = new Transaction();
  tx.lockTime = lockTime;
  sources.forEach(([parent, index], i) =>
    tx.addInput({
      sourceTransaction: txs[parent],
      sourceOutputIndex: index,
      sequence: sequences[i],
      unlockingScriptTemplate: new P2PKH().unlock(key, "all", false),
    }),
  );
  amounts.forEach((satoshis) =>
    tx.addOutput({ satoshis, lockingScript: lock }),
  );
  await tx.sign();
  return keep(name, tx);
}
await spend("P", [["root", 0]], Array(8).fill(10000));
await spend("A", [["P", 0]], [9000]);
await spend("B", [["P", 0]], [8999]);
await spend("AC", [["A", 0]], [8000]);
await spend("BC", [["B", 0]], [7999]);
await spend("Q", [["P", 3]], [9000]);
await spend("QC", [["Q", 0]], [8000]);
await spend("X", [["P", 4]], [9000]);
await spend(
  "E",
  [
    ["P", 0],
    ["X", 0],
  ],
  [18000],
);
const pair = [
  ["P", 1],
  ["P", 2],
];
await spend("N", pair, [19000], [1, 7], 110);
await spend("NC", [["N", 0]], [18000]);
await spend("R", pair, [18999], [2, 7], 110);
await spend("equal", pair, [18998], [2, 7], 110);
await spend("incomparable", pair, [18997], [3, 6], 110);
await spend("largeMaximum", pair, [18996], [0, 100], 110);
await spend(
  "reordered",
  [
    ["P", 2],
    ["P", 1],
  ],
  [18995],
  [8, 3],
  110,
);
await spend(
  "partial",
  [
    ["P", 1],
    ["P", 5],
  ],
  [18994],
  [3, 8],
  110,
);
await spend("extraInput", [...pair, ["P", 6]], [28993], [3, 8, 1], 110);
await spend("allFinal", pair, [18992], [0xffffffff, 0xffffffff], 999999999);
await spend("zeroFinal", pair, [18991], [3, 7], 0);
await spend("locktimeOnly", pair, [18990], [2, 7], 0);
await spend("oneFinal", pair, [18989], [0xffffffff, 7], 110);
await spend("timestamp", [["P", 7]], [9000], [1], 1000000200);
await spend("heightBoundary", [["P", 7]], [8998], [1], 499999999);
await spend("timeBoundary", [["P", 7]], [8997], [1], 500000000);
const bad = Transaction.fromHex(txs.A.toHex());
bad.inputs[0].unlockingScript = UnlockingScript.fromHex("00");
keep("badSignature", bad);
// Reuse the independently executed BRC-197 family fixture, including both
// signed inputs of its permissionless expiry retirement.
const family = JSON.parse(readFileSync(new URL("../../../tokens/media/0197/lineage-vectors.json", import.meta.url)));
const familyParent = keep("brc197Parent", Transaction.fromHex(family.records.find(r=>r.name==="split").tx));
const familyFunding = keep("brc197Funding", Transaction.fromHex(family.funding[4]));
const familyRetirement = keep("brc197Retire", Transaction.fromHex(family.records.find(r=>r.name==="retire").tx));
const expiryHeight = Buffer.from(familyParent.outputs[1].lockingScript.toBinary()).readUInt32LE(3+86);
if (expiryHeight !== familyRetirement.lockTime ||
    familyRetirement.inputs[0].sourceTXID !== familyParent.id("hex") ||
    familyRetirement.inputs[1].sourceTXID !== familyFunding.id("hex"))
  throw Error("BRC-197 expiry fixture dependency mismatch");
const h2 = (b) =>
  createHash("sha256").update(createHash("sha256").update(b).digest()).digest();
const headers = [];
function mine(label, previous, height, merkleRoot, time = 1000000000 + height) {
  const b = Buffer.alloc(80);
  b.writeUInt32LE(1);
  Buffer.from(previous, "hex").reverse().copy(b, 4);
  Buffer.from(merkleRoot, "hex").reverse().copy(b, 36);
  b.writeUInt32LE(time, 68);
  b.writeUInt32LE(0x207fffff, 72);
  for (let n = 0; ; n++) {
    b.writeUInt32LE(n, 76);
    if (BigInt("0x" + h2(b).reverse().toString("hex")) <= 0x7fffffn << 232n)
      break;
  }
  const hash = h2(b).reverse().toString("hex");
  headers.push({ label, height, hash, raw: b.toString("hex") });
  return hash;
}
const proof = (n, height) =>
  new MerklePath(height, [
    [
      {
        offset: 0,
        hash: createHash("sha256")
          .update(`fixture-coinbase-${height}`)
          .digest("hex"),
      },
      { offset: 1, hash: txs[n].id("hex"), txid: true },
    ],
  ]);
const pPath = proof("P", 101),
  bPath = proof("B", 102);
let tip = mine("root", "00".repeat(32), 0, root.id("hex"));
for (let h = 1; h <= 100; h++)
  tip = mine(
    `h${h}`,
    tip,
    h,
    createHash("sha256").update(`empty-fixture-${h}`).digest("hex"),
  );
tip = mine("base", tip, 101, pPath.computeRoot(txs.P.id("hex")));
const branch = mine("B", tip, 102, bPath.computeRoot(txs.B.id("hex")));
const fork = mine(
  "fork",
  tip,
  102,
  createHash("sha256").update("other-branch").digest("hex"),
  1000000103,
);
let mature = tip;
for (let h = 102; h <= 110; h++)
  mature = mine(
    `m${h}`,
    mature,
    h,
    createHash("sha256").update(`mature-${h}`).digest("hex"),
  );
root.merklePath = new MerklePath(0, [
  [{ offset: 0, hash: root.id("hex"), txid: true }],
]);
txs.P.merklePath = pPath;
const bProof = Transaction.fromHex(txs.B.toHex());
bProof.merklePath = bPath;
const corpus = {
  version: 1,
  warning:
    "PUBLIC test keys; signed P2PKH transactions, one frozen BRC-197 expiry retirement and synthetic easy-PoW headers. Not mainnet, a full consensus node or a production adapter.",
  transactions: Object.fromEntries(
    Object.entries(txs).map(([name, tx]) => [
      name,
      {
        txid: tx.id("hex"),
        raw: tx.toHex(),
        scriptValid: name !== "badSignature",
      },
    ]),
  ),
  headers,
  views: {
    base: { tipHash: tip },
    included: { tipHash: branch },
    fork: { tipHash: fork },
    mature: { tipHash: mature },
  },
  preverifiedRoots: ["brc197Parent", "brc197Funding"],
  finalityContexts: {
    expiryBefore: { height: expiryHeight-1, mtp: 1000000000 },
    expiryEligible: { height: expiryHeight, mtp: 1000000000 },
  },
  expiryRetirement: {
    name: "brc197Retire", listingParent: "brc197Parent", listingOutputIndex: 1,
    fundingParent: "brc197Funding", expiryHeight,
  },
  anchors: [
    {
      name: "root",
      height: 0,
      beef: Buffer.from(root.toAtomicBEEF()).toString("base64"),
    },
    {
      name: "P",
      height: 101,
      beef: Buffer.from(txs.P.toAtomicBEEF()).toString("base64"),
    },
  ],
  inclusion: {
    name: "B",
    view: "included",
    height: 102,
    beef: Buffer.from(bProof.toAtomicBEEF()).toString("base64"),
  },
  finality: [
    { name: "brc197Retire", height: expiryHeight-1, mtp: 1000000000, expected: false },
    { name: "brc197Retire", height: expiryHeight, mtp: 1000000000, expected: true },
    { name: "N", height: 108, mtp: 1000000000, expected: false },
    { name: "N", height: 109, mtp: 1000000000, expected: false },
    { name: "N", height: 110, mtp: 1000000000, expected: true },
    { name: "timestamp", height: 101, mtp: 1000000199, expected: false },
    { name: "timestamp", height: 101, mtp: 1000000200, expected: false },
    { name: "timestamp", height: 101, mtp: 1000000201, expected: true },
    { name: "allFinal", height: 101, mtp: 1000000000, expected: true },
    { name: "zeroFinal", height: 101, mtp: 1000000000, expected: true },
    { name: "oneFinal", height: 101, mtp: 1000000000, expected: false },
    {
      name: "heightBoundary",
      height: 499999997,
      mtp: 1000000000,
      expected: false,
    },
    {
      name: "heightBoundary",
      height: 499999998,
      mtp: 1000000000,
      expected: false,
    },
    {
      name: "heightBoundary",
      height: 499999999,
      mtp: 1000000000,
      expected: true,
    },
    {
      name: "timeBoundary",
      height: 999999999,
      mtp: 499999999,
      expected: false,
    },
    {
      name: "timeBoundary",
      height: 999999999,
      mtp: 500000000,
      expected: false,
    },
    { name: "timeBoundary", height: 1, mtp: 500000001, expected: true },
  ],
  replacements: [
    ["N", "R", true],
    ["R", "equal", false],
    ["R", "incomparable", false],
    ["R", "largeMaximum", false],
    ["R", "reordered", false],
    ["R", "partial", false],
    ["R", "extraInput", false],
    ["R", "allFinal", true],
    ["R", "zeroFinal", true],
    ["R", "locktimeOnly", false],
    ["R", "oneFinal", true],
  ],
};
writeFileSync(
  new URL("./reconciliation-vectors.json", import.meta.url),
  JSON.stringify(corpus, null, 2) + "\n",
);
console.log(
  JSON.stringify({
    transactions: Object.keys(txs).length,
    headers: headers.length,
    finality: corpus.finality.length,
    replacements: corpus.replacements.length,
  }),
);
