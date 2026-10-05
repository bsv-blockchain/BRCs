// Offline authoring only. Expected query results below are specified by hand.
// Test execution never regenerates signed bytes or expected results.
import { readFileSync, writeFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { PrivateKey, SignedMessage } from "@bsv/sdk";
import { b64, canonical, digest, preimage } from "./protocol.mjs";

const read = (name) => readFileSync(new URL(name, import.meta.url));
const corpus = JSON.parse(gunzipSync(read("wire-vectors.json.gz")));
const author = new PrivateKey(corpus.actors.buyerA.scalar);
const base = corpus.proposal.body;
const heads = {};
function head(name, changes) {
  const body = { ...base, ...changes };
  heads[name] = {
    body,
    signature: b64(SignedMessage.sign([...preimage("proposal", body)], author)),
  };
}
head("a0", { channel: "11".repeat(32) });
head("a1", {
  channel: heads.a0.body.channel,
  revision: "1",
  previous: digest("proposal", heads.a0.body),
  payload: b64(Buffer.from(canonical({ text: "A new current document." }))),
});
head("b0", { channel: "22".repeat(32) });
const at = base.issuedAt,
  end = base.expiresAt;
const row = (head, status = "active", readable = true) => ({
  head,
  state: { status, recordedAt: status === "expired" ? end : at },
  readable,
});
const a0 = row("a0"),
  a1 = row("a1"),
  b0 = row("b0"),
  expired = row("a1", "expired");
const pair = (name, status = "active") => [
  { kind: "proposal", head: name },
  {
    kind: "proposal-state",
    head: name,
    state: { status, recordedAt: status === "expired" ? end : at },
  },
];
const remove = (name) => ({ kind: "proposal-remove", head: name });
const change = (before, after) => ({ before, after });
const cases = [
  {
    name: "snapshot orders channels by key",
    rows: [b0, a0],
    expected: [pair("a0"), pair("b0")],
  },
  {
    name: "snapshot retains expired signed intent as history",
    rows: [expired],
    expected: [pair("a1", "expired")],
  },
  {
    name: "snapshot can begin with an unknown predecessor",
    rows: [a1],
    expected: [pair("a1")],
  },
  {
    name: "selected channel filters other heads",
    query: { channels: [heads.b0.body.channel] },
    rows: [a0, b0],
    expected: [pair("b0")],
  },
  {
    name: "private unreadable rows disclose nothing",
    rows: [row("a0", "active", false)],
    expected: [],
  },
  {
    name: "nonrecipient sees no signed head",
    principal: corpus.actors.buyerB.identity,
    rows: [a0],
    expected: [],
  },
  {
    name: "anonymous reads fail even for an empty snapshot",
    principal: null,
    rows: [],
    error: "unauthorized",
  },
  {
    name: "new visible channel enters without a reset",
    changes: [change(null, a0)],
    expected: [pair("a0")],
  },
  {
    name: "replacement is one ordered atomic group",
    changes: [change(a0, a1)],
    expected: [[remove("a0"), ...pair("a1")]],
  },
  {
    name: "lifecycle expiry retains exact signed head",
    changes: [change(a1, expired)],
    expected: [pair("a1", "expired")],
  },
  {
    name: "retention removal is only a membership assertion",
    changes: [change(expired, null)],
    expected: [[remove("a1")]],
  },
  {
    name: "unchanged state produces no observation",
    changes: [change(a0, a0)],
    expected: [],
  },
  {
    name: "multiple channels remain one canonically ordered group",
    changes: [change(null, b0), change(a0, a1)],
    expected: [[remove("a0"), ...pair("a1"), ...pair("b0")]],
  },
  {
    name: "narrowed access resets before disclosing removal",
    changes: [change(a0, row("a0", "active", false))],
    error: "reset-required",
  },
  {
    name: "widened access cannot silently edit captured selection",
    changes: [change(row("a0", "active", false), a0)],
    error: "reset-required",
  },
  {
    name: "excluded channel changes are irrelevant",
    query: { channels: [heads.b0.body.channel] },
    changes: [change(a0, a1)],
    expected: [],
  },
];
const id = "https://bsv.brc.dev/overlays/0194#proposal-channel-heads-v1";
const rules = { id, parameters: { policy: base.policy } };
const queries = [
  {},
  { channels: [heads.a0.body.channel] },
  { channels: [heads.a0.body.channel, heads.b0.body.channel] },
];
const result = {
  version: 1,
  claim:
    "Signed examples and bounded query-mapping model only; not durable provider qualification.",
  service: base.service,
  chain: base.chain,
  principal: base.author,
  rules,
  rulesDigest: digest("service-rules", rules),
  queries: queries.map((query) => ({
    query,
    digest: digest("lookup-query", { service: base.service, query }),
  })),
  heads,
  cases,
};
writeFileSync(
  new URL("proposal-query-vectors.json", import.meta.url),
  JSON.stringify(result, null, 2) + "\n",
);
