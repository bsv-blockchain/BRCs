// BRC-169 Appendix A.7 envelope test vectors.
// Reproduces the published vectors for a given `payment` shape and prints
// the JSON (RFC 8785) and DAG-CBOR preimages and signatures.
// All keys are PUBLIC TEST KEYS from BRC-169 Appendix A.1.
//   node vectors.mjs           -> current (outputs-list) payment shape
//   node vectors.mjs --legacy  -> the pre-amendment single-object shape, asserted
//                                 byte-for-byte against the vectors BRC-169 published
//                                 before the payment-outputs amendment (harness check)
import { createHash } from "node:crypto";
import { PrivateKey, PublicKey, ProtoWallet, Signature, ECDSA, BigNumber, Utils } from "@bsv/sdk";
import * as dagCbor from "@ipld/dag-cbor";
import canonicalize from "canonicalize";

const legacy = process.argv.includes("--legacy");
const sha256 = (b) => createHash("sha256").update(b).digest();
const keyFromLabel = (label) =>
  new PrivateKey([...sha256(Buffer.from("BRC-169 EXAMPLE / " + label))]); // reduced mod n by the SDK

const crumbs = keyFromLabel("crumbs identity");
const crumbsPub = crumbs.toPublicKey().toString();
const wallet = new ProtoWallet(crumbs);
const sigArgs = { protocolID: [2, "metanet handles envelope"], keyID: "send", counterparty: "anyone" };
const { publicKey: signingPub } = await wallet.getPublicKey({ ...sigArgs, forSelf: true });

const prefix = "D1vMjXw0XVElldVZgrWk4w==";
const suffix = "nEK2VVSJFSCulgp/tHd1ng==";
const BEEF_JSON = "<Atomic BEEF, BRC-95, elided>";
const b64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

const paymentJson = legacy
  ? { derivationPrefix: prefix, derivationSuffix: suffix, protocol: "3241645161d8", satoshis: 21545, beef: BEEF_JSON }
  : { beef: BEEF_JSON, outputs: [
      { protocol: "wallet payment", outputIndex: 0, derivationPrefix: prefix, derivationSuffix: suffix, satoshis: 21545 } ] };
const paymentCbor = legacy
  ? { derivationPrefix: b64(prefix), derivationSuffix: b64(suffix), protocol: "3241645161d8", satoshis: 21545, beef: new Uint8Array(0) }
  : { beef: new Uint8Array(0), outputs: [
      { protocol: "wallet payment", outputIndex: 0, derivationPrefix: b64(prefix), derivationSuffix: b64(suffix), satoshis: 21545 } ] };

const plaintext = "See you at conf2036 — crumbs";
const contentHash = sha256(Buffer.from(plaintext, "utf8"));
const meta = {
  metanetHandles: "1.0",
  recipient: { handle: "deggen", tag: "conf2036", domain: "lkup.net" },
  sender: { identityKey: crumbsPub, handle: "crumbs", domain: "nexus.example" },
  created: "2026-07-30T09:15:00Z",
  quoteId: "0d34cb39c1c6fe06cd4a346867e1e334",
};

async function sign(bytes) {
  const { signature } = await wallet.createSignature({ ...sigArgs, data: [...bytes] });
  const { valid } = await wallet.verifySignature({ ...sigArgs, forSelf: true, data: [...bytes], signature });
  if (!valid) throw new Error("signature does not verify");
  // independent check: plain ECDSA over SHA-256(preimage) against the derived public key
  const sig = Signature.fromDER(signature);
  if (!ECDSA.verify(new BigNumber(sha256(bytes).toString("hex"), 16), sig, PublicKey.fromString(signingPub)))
    throw new Error("signature does not verify against derived pubkey");
  return Utils.toHex(signature);
}

const jsonPre = canonicalize({ ...meta, payment: paymentJson, contentHash: contentHash.toString("hex") });
const jsonSig = await sign(Buffer.from(jsonPre, "utf8"));

const cborMap = {
  ...meta,
  sender: { ...meta.sender, identityKey: new Uint8Array(Buffer.from(crumbsPub, "hex")) },
  payment: paymentCbor,
  contentHash: new Uint8Array(contentHash),
};
const cborPre = dagCbor.encode(cborMap);
const cborSig = await sign(Buffer.from(cborPre));

if (legacy) {
  const published = {
    jsonSig: "304402202321ddef29a863e6ff2d03856a6eb1a1f10a058e8197e6a63499d5a31801c74a02207801f7755d4d303255f739e24363ae697bbc7c9dbbb83fb5e7b79cad45ec0e70",
    cborSig: "304402206a2bf0b0628386870202789d718001580279cc1add7b3dc3ff81e08858e22f8c022051d6e6d5756bf2bd1d06ea5199af080e721bb1f5dddefe9a36884796d5d04cf7",
    cborLen: 398,
    signingPub: "022b380d363a1da7db379d567ebd438ff34684d1ab5cc82d8de57868d873c69552",
  };
  if (jsonSig !== published.jsonSig || cborSig !== published.cborSig ||
      cborPre.length !== published.cborLen || signingPub !== published.signingPub)
    throw new Error("harness does not reproduce the published pre-amendment vectors");
}

console.log("shape:", legacy ? "legacy single object" : "outputs list");
console.log("identityKey:", crumbsPub);
console.log("signing pubkey:", signingPub);
console.log("contentHash:", contentHash.toString("hex"));
console.log("\nJSON envelope payment:\n" + JSON.stringify(paymentJson, null, 2));
console.log("\nJCS preimage:\n" + jsonPre);
console.log("\nJSON signature:\n" + jsonSig);
console.log(`\nDAG-CBOR preimage (${cborPre.length} bytes):\n` + Buffer.from(cborPre).toString("hex"));
console.log("\nbinary signature:\n" + cborSig);
