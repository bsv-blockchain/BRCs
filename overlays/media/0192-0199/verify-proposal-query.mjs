// Bounded specification model, not a durable provider or a production parser.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SignedMessage } from "@bsv/sdk";
import { canonical, closed, bytes, digest, preimage } from "./protocol.mjs";

const read = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url)));
const v = read("proposal-query-vectors.json");
const registry = read("registry.json");
assert(
  registry.identifiers.some((row) => row.id === v.rules.id && row.immutable),
);
assert.equal(digest("service-rules", v.rules), v.rulesDigest);
for (const { query, digest: expected } of v.queries)
  assert.equal(digest("lookup-query", { service: v.service, query }), expected);
for (const [name, head] of Object.entries(v.heads)) {
  const sig = bytes(head.signature);
  assert.equal(sig.subarray(4, 37).toString("hex"), head.body.author, name);
  assert.equal(sig[37], 0);
  assert(
    SignedMessage.verify([...preimage("proposal", head.body)], [...sig]),
    name,
  );
  assert.equal(head.body.service, v.service);
  assert.deepEqual(head.body.chain, v.chain);
  assert.deepEqual(head.body.policy, v.rules.parameters.policy);
  assert.equal(head.body.author, v.principal);
  assert.equal(head.body.operation, "update");
  assert(BigInt(head.body.issuedAt) < BigInt(head.body.expiresAt));
  assert.deepEqual(head.body.anchors, []);
  assert.equal(head.body.transaction, undefined);
  const payload = bytes(head.body.payload).toString("utf8");
  const document = JSON.parse(payload);
  closed(document, ["text"]);
  assert.equal(payload, canonical(document));
  if (name !== "a1") {
    assert.equal(head.body.revision, "0");
    assert.equal(head.body.previous, null);
  }
}
assert.equal(v.heads.a1.body.previous, digest("proposal", v.heads.a0.body));
assert.equal(v.heads.a1.body.revision, "1");
assert.deepEqual(v.heads.a1.body.recipients, v.heads.a0.body.recipients);

function query(input) {
  closed(input, [], ["channels"]);
  if (!Object.hasOwn(input, "channels")) return null;
  const channels = input.channels;
  assert(
    Array.isArray(channels) && channels.length >= 1 && channels.length <= 256,
  );
  for (let i = 0; i < channels.length; i++) {
    assert(
      typeof channels[i] === "string" && /^[0-9a-f]{64}$/.test(channels[i]),
    );
    assert(i === 0 || channels[i - 1] < channels[i]);
  }
  return new Set(channels);
}

function execute(test) {
  const channels = query(test.query ?? {});
  const principal = Object.hasOwn(test, "principal")
    ? test.principal
    : v.principal;
  if (principal === null) throw Error("unauthorized");
  const visible = (row) =>
    row !== null &&
    row.readable &&
    v.heads[row.head].body.recipients.includes(principal) &&
    (channels === null || channels.has(v.heads[row.head].body.channel));
  const key = (row) =>
    v.heads[row.head].body.policy.digest + v.heads[row.head].body.channel;
  const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const pair = (row) => [
    { kind: "proposal", head: row.head },
    { kind: "proposal-state", head: row.head, state: row.state },
  ];
  if (test.rows)
    return test.rows
      .filter(visible)
      .sort((a, b) => compare(key(a), key(b)))
      .map(pair);
  const observations = [];
  for (const { before, after } of [...test.changes].sort((a, b) =>
    compare(key(a.after ?? a.before), key(b.after ?? b.before)),
  )) {
    const oldVisible = visible(before),
      newVisible = visible(after);
    if (before && after && oldVisible !== newVisible)
      throw Error("reset-required");
    if (oldVisible && newVisible && canonical(before) === canonical(after))
      continue;
    if (
      oldVisible &&
      (!newVisible ||
        digest("proposal", v.heads[before.head].body) !==
          digest("proposal", v.heads[after.head].body))
    )
      observations.push({ kind: "proposal-remove", head: before.head });
    if (newVisible) observations.push(...pair(after));
  }
  return observations.length ? [observations] : [];
}

for (const test of v.cases) {
  if (test.error)
    assert.throws(() => execute(test), { message: test.error }, test.name);
  else assert.deepEqual(execute(test), test.expected, test.name);
}
const a = "11".repeat(32),
  b = "22".repeat(32);
const invalid = [
  null,
  [],
  { extra: true },
  { channels: [] },
  { channels: [a, a] },
  { channels: [b, a] },
  { channels: ["FF".repeat(32)] },
  { channels: [false] },
  { channels: null },
  {
    channels: Array.from({ length: 257 }, (_, n) =>
      n.toString(16).padStart(64, "0"),
    ),
  },
];
for (const value of invalid) assert.throws(() => query(value));
assert.equal(
  query({
    channels: Array.from({ length: 256 }, (_, n) =>
      n.toString(16).padStart(64, "0"),
    ),
  }).size,
  256,
);
console.log(
  `Proposal query: ${v.cases.length} mapping scenarios, ${invalid.length} query rejections, 3 signed heads and 4 frozen digests passed.`,
);
