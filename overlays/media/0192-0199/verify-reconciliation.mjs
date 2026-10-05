// Executable specification model, not a production runtime. Offline public fixtures.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Transaction } from "@bsv/sdk";
import { evaluate } from "../../../tokens/media/0197/family.mjs";
const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url)));
const corpus = read("./reconciliation-vectors.json"),
  traces = read("./reconciliation-traces.json");
const h2 = (b) =>
  createHash("sha256").update(createHash("sha256").update(b).digest()).digest();
const txs = Object.fromEntries(
  Object.entries(corpus.transactions).map(([n, t]) => [
    n,
    Transaction.fromHex(t.raw),
  ]),
);
const names = Object.fromEntries(
  Object.entries(corpus.transactions).map(([n, t]) => [t.txid, n]),
);
const inputs = (n) =>
  txs[n].inputs.map((i) => `${names[i.sourceTXID]}:${i.sourceOutputIndex}`);
const parents = (n) => [...new Set(inputs(n).map((o) => o.split(":")[0]))];
const seq = (n) => txs[n].inputs.map((i) => i.sequence);
const scriptValid = {};
let inputChecks = 0;
for (const [n, tx] of Object.entries(txs)) {
  assert.equal(tx.id("hex"), corpus.transactions[n].txid);
  assert.equal(tx.toHex(), corpus.transactions[n].raw);
  if (n === "root" || corpus.preverifiedRoots.includes(n)) continue;
  assert.equal(new Set(inputs(n)).size, tx.inputs.length);
  let funds = 0,
    ok = true;
  for (let i = 0; i < tx.inputs.length; i++) {
    const inp = tx.inputs[i];
    inp.sourceTransaction = txs[names[inp.sourceTXID]];
    funds += inp.sourceTransaction.outputs[inp.sourceOutputIndex].satoshis;
    try {
      ok = evaluate(tx, i) && ok;
    } catch {
      ok = false;
    }
    inputChecks++;
  }
  assert.ok(funds >= tx.outputs.reduce((a, o) => a + o.satoshis, 0));
  scriptValid[n] = ok;
  assert.equal(ok, corpus.transactions[n].scriptValid, n);
}
const headers = {};
for (const h of corpus.headers) {
  const b = Buffer.from(h.raw, "hex");
  assert.equal(b.length, 80);
  assert.equal(h2(b).reverse().toString("hex"), h.hash);
  assert.equal(b.readUInt32LE(72), 0x207fffff);
  assert.ok(BigInt("0x" + h.hash) <= 0x7fffffn << 232n);
  const previous = Buffer.from(b.subarray(4, 36)).reverse().toString("hex");
  if (h.height === 0) assert.equal(previous, "00".repeat(32));
  else assert.equal(headers[previous].height + 1, h.height);
  headers[h.hash] = {
    ...h,
    previous,
    root: Buffer.from(b.subarray(36, 68)).reverse().toString("hex"),
    time: b.readUInt32LE(68),
  };
}
const views = {};
for (const [id, v] of Object.entries(corpus.views)) {
  const chain = [];
  for (let h = headers[v.tipHash]; h; h = headers[h.previous]) chain.push(h);
  const times = chain
    .slice(0, 11)
    .map((h) => h.time)
    .sort((a, b) => a - b);
  views[id] = {
    id,
    height: chain[0].height,
    mtp: times[Math.floor(times.length / 2)],
    chain,
  };
}
for(const [id,context] of Object.entries(corpus.finalityContexts))
  views[id]={id,...context,chain:[]}
const family=JSON.parse(readFileSync(new URL("../../../tokens/media/0197/lineage-vectors.json",import.meta.url)))
const expiry=corpus.expiryRetirement,retirement=txs[expiry.name]
assert.equal(txs[expiry.listingParent].toHex(),family.records.find(r=>r.name==="split").tx)
assert.equal(txs[expiry.fundingParent].toHex(),family.funding[4])
assert.equal(retirement.toHex(),family.records.find(r=>r.name==="retire").tx)
assert.equal(retirement.inputs[0].sourceTXID,txs[expiry.listingParent].id("hex"))
assert.equal(retirement.inputs[0].sourceOutputIndex,expiry.listingOutputIndex)
assert.equal(retirement.inputs[1].sourceTXID,txs[expiry.fundingParent].id("hex"))
assert.equal(Buffer.from(txs[expiry.listingParent].outputs[expiry.listingOutputIndex].lockingScript.toBinary()).readUInt32LE(3+86),expiry.expiryHeight)
assert.equal(retirement.lockTime,expiry.expiryHeight)
assert.notEqual(retirement.inputs[0].sequence,0xffffffff)
assert.ok(retirement.outputs[0].lockingScript.toHex().startsWith("006a4c56524f534c0105"))
assert.equal(scriptValid[expiry.name],true)
for (const anchor of [...corpus.anchors, corpus.inclusion]) {
  const t = Transaction.fromAtomicBEEF(Buffer.from(anchor.beef, "base64"));
  assert.equal(t.id("hex"), corpus.transactions[anchor.name].txid);
  const view = views[anchor.view ?? "base"];
  assert.ok(
    await t.verify({
      currentHeight: async () => view.height,
      isValidRootForHeight: async (root, height) =>
        view.chain.some((h) => h.height === height && h.root === root),
    }),
  );
}
const included = Transaction.fromAtomicBEEF(
  Buffer.from(corpus.inclusion.beef, "base64"),
);
await assert.rejects(
  included.verify({
    currentHeight: async () => views.fork.height,
    isValidRootForHeight: async (root, height) =>
      views.fork.chain.some((h) => h.height === height && h.root === root),
  }),
  /Invalid merkle path/,
);
function final(n, c) {
  return (
    txs[n].lockTime === 0 ||
    seq(n).every((s) => s === 0xffffffff) ||
    txs[n].lockTime < (txs[n].lockTime < 500000000 ? c.height + 1 : c.mtp)
  );
}
function increases(a, b) {
  return (
    JSON.stringify(inputs(a)) === JSON.stringify(inputs(b)) &&
    seq(b).every((s, i) => s >= seq(a)[i]) &&
    seq(b).some((s, i) => s > seq(a)[i])
  );
}
for (const f of corpus.finality)
  assert.equal(final(f.name, f), f.expected, JSON.stringify(f));
for (const [a, b, want] of corpus.replacements)
  assert.equal(increases(a, b), want, `${a}->${b}`);

class Model {
  constructor(nonFinal = true) {
    this.nonFinal = nonFinal;
    this.view = "base";
    this.position = 0;
    this.raw = {};
    this.verified = {};
    this.sources = {};
    this.last = {};
    this.log = [];
  }
  event(e) {
    this.log.push(e);
    this.apply(e);
    this.snapshot();
  }
  apply(e) {
    if (e.op === "receive") {
      ++this.position;
      [...e.names]
        .sort((a, b) =>
          corpus.transactions[a].txid.localeCompare(
            corpus.transactions[b].txid,
          ),
        )
        .forEach((n, index) => {
          this.raw[n] ??= {
            position: this.position,
            index,
            view: this.view,
            source: e.source,
          };
        });
    } else if (e.op === "verify") {
      if (!e.context || e.context === this.view)
        for (const n of e.names) {
          assert.ok(this.raw[n]);
          this.verified[n] = scriptValid[n];
        }
    } else if (e.op === "view") {
      ++this.position;
      this.view = e.id;
    } else if (e.op === "membership") {
      ++this.position;
      const s = (this.sources[e.source] ??= {
        generation: e.generation,
        rows: {},
        closed: -1,
        staging: {},
      });
      if (e.generation <= s.closed || e.generation < s.generation) return;
      const g = (s.staging[e.generation] ??= {
        queue: [],
        rows: e.generation === s.generation ? structuredClone(s.rows) : {},
        through: -1,
        complete: false,
        seen: {},
      });
      if (g.seen[e.id]) {
        assert.deepEqual(g.seen[e.id], e);
        return;
      }
      if (e.phase !== "snapshot" && e.sequence <= g.through) return;
      if (e.phase === "snapshot")
        assert.ok(!g.complete && e.sequence >= g.through);
      g.seen[e.id] = structuredClone(e);
      // The source adapter has already checked authenticated transport order.
      assert.ok(!g.queue.length || e.sequence >= g.queue.at(-1).event.sequence);
      g.queue.push({ id: e.id, event: e, verified: e.verified !== false });
      this.flush(e.source, e.generation);
    } else if (e.op === "membershipVerified") {
      const s = this.sources[e.source],
        g = s?.staging[e.generation];
      if (!g || e.generation <= s.closed) return;
      const item = g.queue.find((x) => x.id === e.id);
      if (item) item.verified = true;
      this.flush(e.source, e.generation);
    } else throw Error(`unknown event ${e.op}`);
  }
  flush(source, generation) {
    const s = this.sources[source],
      g = s.staging[generation];
    while (g.queue[0]?.verified) {
      const { event: e } = g.queue.shift();
      for (const a of e.changes)
        g.rows[a.outpoint] = { present: a.present, sequence: e.sequence };
      g.through = e.sequence;
      g.complete ||= !!e.complete;
    }
    if (generation === s.generation) {
      s.rows = structuredClone(g.rows);
    } else if (g.complete) {
      s.closed = generation - 1;
      s.generation = generation;
      s.rows = structuredClone(g.rows);
    }
  }
  snapshot(watch = []) {
    const anchor = new Set(["root", "P",...corpus.preverifiedRoots]),
      order = {},
      pending = new Set(),
      state = {};
    const ready = (n) => {
      if (anchor.has(n)) return { at: 0, depth: 0 };
      if (order[n]) return order[n];
      if (!this.raw[n]) return null;
      const ps = parents(n).map(ready);
      if (ps.some((p) => !p)) return null;
      const at = Math.max(this.raw[n].position, ...ps.map((p) => p.at));
      const same = ps.filter((p) => p.at === at);
      return (order[n] = {
        at,
        depth: same.length ? Math.max(...same.map((p) => p.depth)) + 1 : 0,
        context:
          Object.values(this.raw).find((r) => r.position === at)?.view ??
          this.view,
      });
    };
    for (const n of Object.keys(this.raw)) ready(n);
    // Connected components include input conflicts and dependency edges, but not
    // unrelated outputs of a common confirmed anchor.
    const adjacent = (a, b) =>
      parents(a).includes(b) ||
      parents(b).includes(a) ||
      inputs(a).some((i) => inputs(b).includes(i));
    for (const n of Object.keys(this.raw))
      if (order[n] && !(n in this.verified)) pending.add(n);
    let changed = true;
    while (changed) {
      changed = false;
      for (const n of Object.keys(this.raw))
        if (!pending.has(n) && [...pending].some((p) => adjacent(n, p))) {
          pending.add(n);
          changed = true;
        }
    }
    const chosen = new Set(anchor),
      held = {},
      replacement = {},
      eligible = {};
    const forced = new Set();
    if (this.view === "included" && this.raw.B && this.verified.B) {
      forced.add("B");
      chosen.add("B");
      for (const i of inputs("B")) held[i] = "B";
      state.B = "included";
    }
    const sorted = Object.keys(this.raw).sort((a, b) => {
      const x = order[a],
        y = order[b];
      if (!x || !y) return x ? -1 : y ? 1 : a.localeCompare(b);
      return (
        x.at - y.at ||
        x.depth - y.depth ||
        this.raw[a].position - this.raw[b].position ||
        this.raw[a].index - this.raw[b].index ||
        corpus.transactions[a].txid.localeCompare(corpus.transactions[b].txid)
      );
    });
    // Replay finality frontiers, not all arrivals under today's locktime context.
    // Otherwise an already-replaced non-final parent could acquire a child when
    // it matures, before the replay reaches its historical replacement.
    const contexts = { 0: "base" };
    let pos = 0;
    for (const e of this.log) {
      if (["receive", "view", "membership"].includes(e.op)) pos++;
      if (e.op === "view") contexts[pos] = e.id;
    }
    const frontiers = [
      ...new Set([
        ...Object.values(order).map((o) => o.at),
        ...Object.keys(contexts).map(Number),
        this.position,
      ]),
    ].sort((a, b) => a - b);
    for (const at of frontiers) {
      const ctx =
        views[
          contexts[
            Math.max(
              ...Object.keys(contexts)
                .map(Number)
                .filter((p) => p <= at),
            )
          ]
        ];
      for (const n of sorted) {
        if (forced.has(n) || chosen.has(n) || state[n] === "conflicting")
          continue;
        if (pending.has(n)) {
          state[n] = "pending";
          continue;
        }
        if (!order[n]) {
          state[n] = "unresolved";
          continue;
        }
        if (order[n].at > at) continue;
        if (!this.verified[n]) {
          state[n] = "invalid";
          continue;
        }
        if (
          parents(n).some(
            (p) =>
              !chosen.has(p) ||
              (!anchor.has(p) && !forced.has(p) && !final(p, ctx)),
          )
        ) {
          state[n] = "dependent-conflict";
          continue;
        }
        if (!this.nonFinal && !final(n, ctx)) {
          state[n] = "unsupported";
          continue;
        }
        eligible[n] ??= { at, context: ctx.id };
        const competing = [
          ...new Set(
            inputs(n)
              .map((i) => held[i])
              .filter(Boolean),
          ),
        ];
        const prior = competing[0];
        if (
          competing.length &&
          !(
            competing.length === 1 &&
            !forced.has(prior) &&
            !final(prior, ctx) &&
            increases(prior, n)
          )
        ) {
          state[n] = "conflicting";
          continue;
        }
        if (prior) {
          chosen.delete(prior);
          state[prior] = "conflicting";
          replacement[n] = prior;
          for (const i of inputs(prior)) delete held[i];
        }
        chosen.add(n);
        for (const i of inputs(n)) held[i] = n;
        state[n] = "selected";
      }
    }
    // Collapse historical replacement chains into their inherited input
    // reservations, then assess the compatible graph in the current view.
    // This also removes children made unusable by a locktime-reversing reorg.
    const replaced = new Set(Object.values(replacement));
    const root = (n) => (replacement[n] ? root(replacement[n]) : n);
    const rank = new Map(sorted.map((n, i) => [n, i]));
    chosen.clear();
    for (const n of [...anchor, ...forced]) chosen.add(n);
    for (const i of Object.keys(held)) delete held[i];
    for (const n of forced) for (const i of inputs(n)) held[i] = n;
    for (const n of [...sorted].sort(
      (a, b) =>
        (eligible[root(a)]?.at ?? Infinity) -
          (eligible[root(b)]?.at ?? Infinity) ||
        rank.get(root(a)) - rank.get(root(b)) ||
        rank.get(a) - rank.get(b),
    )) {
      if (forced.has(n)) {
        state[n] = "included";
        continue;
      }
      if (pending.has(n)) {
        state[n] = "pending";
        continue;
      }
      if (!order[n]) {
        state[n] = "unresolved";
        continue;
      }
      if (!this.verified[n]) {
        state[n] = "invalid";
        continue;
      }
      if (replaced.has(n)) {
        state[n] = "conflicting";
        continue;
      }
      if (
        parents(n).some(
          (p) =>
            !chosen.has(p) ||
            (!anchor.has(p) && !forced.has(p) && !final(p, views[this.view])),
        )
      ) {
        state[n] = "dependent-conflict";
        continue;
      }
      if (!this.nonFinal && !final(n, views[this.view])) {
        state[n] = "unsupported";
        continue;
      }
      if (inputs(n).some((i) => held[i])) {
        state[n] = "conflicting";
        continue;
      }
      chosen.add(n);
      for (const i of inputs(n)) held[i] = n;
      state[n] = final(n, views[this.view])
        ? "selected-final"
        : "selected-non-final";
    }
    const spent = {};
    for (const n of chosen)
      if (!anchor.has(n) && final(n, views[this.view]))
        for (const i of inputs(n)) spent[i] = n;
    const memberships = [];
    for (const [source, s] of Object.entries(this.sources))
      for (const [outpoint, r] of Object.entries(s.rows))
        memberships.push(
          `${source}/${s.generation}/${outpoint}/${r.present ? "present" : "absent"}/${r.sequence}`,
        );
    const current = watch
      .filter((o) => {
        const n = o.split(":")[0];
        return (
          chosen.has(n) &&
          final(n, views[this.view]) &&
          !spent[o] &&
          ![...pending].some((p) => inputs(p).includes(o))
        );
      })
      .sort();
    const stale = [];
    for (const n of pending)
      if (this.last[n]) stale.push(`${n}:${this.last[n]}`);
    for (const n of Object.keys(state))
      if (!pending.has(n)) this.last[n] = state[n];
    return {
      view: this.view,
      states: Object.keys(state)
        .sort()
        .map((n) => `${n}:${state[n]}`),
      current,
      spent: Object.keys(spent)
        .filter((o) => watch.includes(o))
        .sort()
        .map((o) => `${o}->${spent[o]}`),
      memberships: memberships.sort(),
      stale: stale.sort(),
      walletActions: 0,
      orders: Object.fromEntries(
        Object.keys(order)
          .filter(
            (n) =>
              this.verified[n] &&
              parents(n).every((p) => anchor.has(p) || this.verified[p]),
          )
          .sort()
          .map((n) => [
            n,
            {
              readyAt: order[n].at,
              depth: order[n].depth,
              firstRaw: this.raw[n].position,
              context: order[n].context,
            },
          ]),
      ),
    };
  }
}
let checkpoints = 0,
  restarts = 0;
for (const trace of traces) {
  let model = new Model(trace.nonFinal ?? true);
  for (const step of trace.steps) {
    if (step.op === "restart") {
      const before = model.snapshot(trace.watch),
        log = structuredClone(model.log),
        last = structuredClone(model.last);
      model = new Model(trace.nonFinal ?? true);
      for (const e of log) model.event(e);
      model.last = last;
      assert.deepEqual(model.snapshot(trace.watch), before, trace.name);
      restarts++;
    } else if (step.op === "expect") {
      const got = model.snapshot(trace.watch);
      for (const [key, want] of Object.entries(step.value))
        assert.deepEqual(got[key], want, `${trace.name}: ${key}`);
      checkpoints++;
    } else model.event(step);
  }
}
console.log(
  JSON.stringify({
    reconciliation: "SDK + independent JavaScript model",
    transactions: Object.keys(txs).length,
    inputChecks,
    headers: corpus.headers.length,
    finality: corpus.finality.length,
    replacements: corpus.replacements.length,
    traces: traces.length,
    checkpoints,
    restarts,
  }),
);
