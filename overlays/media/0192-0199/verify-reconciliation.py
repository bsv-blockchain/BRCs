"""Independent BitcoinX/SQLite executable specification, not a production adapter.

The frozen transaction and trace files are the only shared test inputs. No JS
reducer or expected-result generator is imported. Public fixtures; offline only.
"""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from bitcoinx import Tx, TxInputContext, InterpreterLimits, MinerPolicy

HERE = Path(__file__).parent
corpus = json.loads((HERE / "reconciliation-vectors.json").read_text())
traces = json.loads((HERE / "reconciliation-traces.json").read_text())
txs = {n: Tx.from_hex(t["raw"]) for n, t in corpus["transactions"].items()}
names = {t.hex_hash(): n for n, t in txs.items()}


def inputs(n):
    return [f"{names[i.prev_hash[::-1].hex()]}:{i.prev_idx}" for i in txs[n].inputs]


def parents(n):
    return sorted({o.split(":")[0] for o in inputs(n)})


def sequences(n):
    return [i.sequence for i in txs[n].inputs]


def h2(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


limits = InterpreterLimits(
    MinerPolicy(1048576, 128, 128 * 1024 * 1024, 1000000, 8),
    is_genesis_enabled=True,
    is_consensus=False,
)
valid = {}
input_checks = 0
for name, tx in txs.items():
    assert tx.hex_hash() == corpus["transactions"][name]["txid"]
    assert tx.to_bytes().hex() == corpus["transactions"][name]["raw"]
    if name == "root" or name in corpus["preverifiedRoots"]:
        continue
    assert len(set(inputs(name))) == len(tx.inputs)
    results, funds = [], 0
    for i, inp in enumerate(tx.inputs):
        previous = txs[names[inp.prev_hash[::-1].hex()]].outputs[inp.prev_idx]
        funds += previous.value
        try:
            results.append(
                TxInputContext(tx, i, previous).verify_input(
                    limits, is_utxo_after_genesis=True
                )
            )
        except Exception:
            results.append(False)
        input_checks += 1
    assert funds >= sum(o.value for o in tx.outputs)
    valid[name] = all(results)
    assert valid[name] == corpus["transactions"][name]["scriptValid"], name

headers = {}
for item in corpus["headers"]:
    raw = bytes.fromhex(item["raw"])
    assert len(raw) == 80 and h2(raw)[::-1].hex() == item["hash"]
    assert int.from_bytes(raw[72:76], "little") == 0x207FFFFF
    assert int(item["hash"], 16) <= (0x7FFFFF << 232)
    previous = raw[4:36][::-1].hex()
    if item["height"]:
        assert headers[previous]["height"] + 1 == item["height"]
    else:
        assert previous == "00" * 32
    headers[item["hash"]] = dict(
        item,
        previous=previous,
        root=raw[36:68][::-1].hex(),
        time=int.from_bytes(raw[68:72], "little"),
    )
views = {}
for label, view in corpus["views"].items():
    chain, cursor = [], view["tipHash"]
    while cursor in headers:
        chain.append(headers[cursor])
        cursor = headers[cursor]["previous"]
    times = sorted(h["time"] for h in chain[:11])
    views[label] = dict(
        height=chain[0]["height"], mtp=times[len(times) // 2], chain=chain
    )
for label, context in corpus["finalityContexts"].items():
    views[label] = dict(context, chain=[])
family = json.loads((HERE / "../../../tokens/media/0197/lineage-vectors.json").read_text())
expiry = corpus["expiryRetirement"]
retirement = txs[expiry["name"]]
assert txs[expiry["listingParent"]].to_hex() == next(r["tx"] for r in family["records"] if r["name"] == "split")
assert txs[expiry["fundingParent"]].to_hex() == family["funding"][4]
assert retirement.to_hex() == next(r["tx"] for r in family["records"] if r["name"] == "retire")
assert retirement.inputs[0].prev_hash[::-1].hex() == txs[expiry["listingParent"]].hex_hash()
assert retirement.inputs[0].prev_idx == expiry["listingOutputIndex"]
assert retirement.inputs[1].prev_hash[::-1].hex() == txs[expiry["fundingParent"]].hex_hash()
parent_lock = txs[expiry["listingParent"]].outputs[expiry["listingOutputIndex"]].script_pubkey.to_bytes()
assert int.from_bytes(parent_lock[3+86:3+90], "little") == expiry["expiryHeight"]
assert retirement.locktime == expiry["expiryHeight"]
assert retirement.inputs[0].sequence != 0xFFFFFFFF
assert retirement.outputs[0].script_pubkey.to_bytes().startswith(bytes.fromhex("006a4c56524f534c0105"))
assert list(retirement.inputs[0].script_sig.ops())[11] == b""
assert valid[expiry["name"]]

# Reuse only the independently written bounded byte reader, not its one-leaf
# BEEF interpretation. This corpus adds explicit non-coinbase two-leaf paths.
spec = importlib.util.spec_from_file_location("reader", HERE / "beef-oracle.py")
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def inclusion(item, view):
    r = reader.Reader(base64.b64decode(item["beef"]))
    assert r.uint(4) == 0x01010101
    target = r.read(32)[::-1].hex()
    assert target == txs[item["name"]].hex_hash()
    assert r.uint(4) == 0xEFBE0001 and r.varint() == 1
    height = r.varint()
    assert height == item["height"] and r.uint(1) == 1
    count = r.varint()
    assert count in (1, 2)
    leaves, selected = [], []
    for i in range(count):
        assert r.varint() == i
        flag = r.uint(1)
        assert flag in (0, 2)
        leaf = r.read(32)
        leaves.append(leaf)
        if flag == 2:
            selected.append((i, leaf[::-1].hex()))
    assert len(selected) == 1 and selected[0][1] == target
    root = (leaves[0] if count == 1 else h2(b"".join(leaves)))[::-1].hex()
    assert r.varint() == 1
    parsed = Tx.read(r.read)
    assert parsed.to_bytes() == txs[item["name"]].to_bytes()
    assert r.uint(1) == 1 and r.varint() == 0 and r.pos == len(r.data)
    if selected[0][0] == 0:
        assert height + 100 <= view["height"]
    assert any(
        h["height"] == height and h["root"] == root for h in view["chain"]
    ), "unselected root"


for a in corpus["anchors"] + [corpus["inclusion"]]:
    inclusion(a, views[a.get("view", "base")])
try:
    inclusion(corpus["inclusion"], views["fork"])
except AssertionError as error:
    assert str(error) == "unselected root"
else:
    raise AssertionError("foreign branch accepted")


def final(n, context):
    lock = txs[n].locktime
    return (
        lock == 0
        or all(s == 0xFFFFFFFF for s in sequences(n))
        or lock < (context["height"] + 1 if lock < 500000000 else context["mtp"])
    )


def increases(a, b):
    return (
        inputs(a) == inputs(b)
        and all(y >= x for x, y in zip(sequences(a), sequences(b)))
        and any(y > x for x, y in zip(sequences(a), sequences(b)))
    )


for row in corpus["finality"]:
    assert final(row["name"], row) == row["expected"], row
for a, b, expected in corpus["replacements"]:
    assert increases(a, b) == expected, (a, b)


class Model:
    def __init__(self, non_final=True):
        self.enabled, self.view, self.position = non_final, "base", 0
        self.raw, self.verified, self.sources, self.last, self.journal = (
            {},
            {},
            {},
            {},
            [],
        )

    def event(self, e):
        self.journal.append(copy.deepcopy(e))
        self.apply(e)
        self.snapshot()

    def apply(self, e):
        op = e["op"]
        if op == "receive":
            self.position += 1
            for index, n in enumerate(
                sorted(e["names"], key=lambda n: txs[n].hex_hash())
            ):
                self.raw.setdefault(
                    n, dict(position=self.position, index=index, view=self.view)
                )
        elif op == "verify":
            if e.get("context", self.view) == self.view:
                for n in e["names"]:
                    assert n in self.raw
                    self.verified[n] = valid[n]
        elif op == "view":
            self.position += 1
            self.view = e["id"]
        elif op == "membership":
            self.position += 1
            generation = e["generation"]
            source = self.sources.setdefault(
                e["source"], dict(generation=generation, rows={}, closed=-1, staging={})
            )
            if generation <= source["closed"] or generation < source["generation"]:
                return
            group = source["staging"].setdefault(
                generation,
                dict(
                    queue=[],
                    through=-1,
                    complete=False,
                    seen={},
                    rows=(
                        copy.deepcopy(source["rows"])
                        if generation == source["generation"]
                        else {}
                    ),
                ),
            )
            if e["id"] in group["seen"]:
                assert group["seen"][e["id"]] == e
                return
            if e.get("phase") != "snapshot" and e["sequence"] <= group["through"]:
                return
            if e.get("phase") == "snapshot":
                assert not group["complete"] and e["sequence"] >= group["through"]
            group["seen"][e["id"]] = copy.deepcopy(e)
            assert (
                not group["queue"]
                or e["sequence"] >= group["queue"][-1]["event"]["sequence"]
            )
            group["queue"].append(dict(event=e, verified=e.get("verified", True)))
            self.flush(e["source"], generation)
        elif op == "membershipVerified":
            source = self.sources.get(e["source"])
            group = source["staging"].get(e["generation"]) if source else None
            if not group or e["generation"] <= source["closed"]:
                return
            for row in group["queue"]:
                if row["event"]["id"] == e["id"]:
                    row["verified"] = True
            self.flush(e["source"], e["generation"])
        else:
            raise AssertionError(op)

    def flush(self, name, generation):
        source = self.sources[name]
        group = source["staging"][generation]
        while group["queue"] and group["queue"][0]["verified"]:
            event = group["queue"].pop(0)["event"]
            for change in event["changes"]:
                group["rows"][change["outpoint"]] = dict(
                    present=change["present"], sequence=event["sequence"]
                )
            group["through"] = event["sequence"]
            group["complete"] |= event.get("complete", False)
        if generation == source["generation"]:
            source["rows"] = copy.deepcopy(group["rows"])
        elif group["complete"]:
            source.update(
                closed=generation - 1,
                generation=generation,
                rows=copy.deepcopy(group["rows"]),
            )

    def snapshot(self, watch=()):
        anchors, orders = {"root", "P", *corpus["preverifiedRoots"]}, {}

        def ready(n):
            if n in anchors:
                return dict(at=0, depth=0)
            if n in orders:
                return orders[n]
            if n not in self.raw:
                return None
            ps = [ready(p) for p in parents(n)]
            if any(p is None for p in ps):
                return None
            at = max([self.raw[n]["position"]] + [p["at"] for p in ps])
            cohort = [p["depth"] for p in ps if p["at"] == at]
            orders[n] = dict(
                at=at,
                depth=max(cohort) + 1 if cohort else 0,
                context=next(
                    r["view"] for r in self.raw.values() if r["position"] == at
                ),
            )
            return orders[n]

        for n in self.raw:
            ready(n)
        pending = {n for n in self.raw if n in orders and n not in self.verified}

        def adjacent(a, b):
            return (
                a in parents(b)
                or b in parents(a)
                or bool(set(inputs(a)) & set(inputs(b)))
            )

        while True:
            expanded = pending | {
                n for n in self.raw if any(adjacent(n, p) for p in pending)
            }
            if expanded == pending:
                break
            pending = expanded
        chosen, held, states, forced = set(anchors), {}, {}, set()
        replacement, eligible = {}, {}
        if self.view == "included" and self.verified.get("B"):
            forced.add("B")
            chosen.add("B")
            states["B"] = "included"
            held.update({o: "B" for o in inputs("B")})

        def order(n):
            if n not in orders:
                return (float("inf"), 0, 0, 0, n)
            return (
                orders[n]["at"],
                orders[n]["depth"],
                self.raw[n]["position"],
                self.raw[n]["index"],
                txs[n].hex_hash(),
            )

        contexts, position = {0: "base"}, 0
        for event in self.journal:
            if event["op"] in ("receive", "view", "membership"):
                position += 1
            if event["op"] == "view":
                contexts[position] = event["id"]
        frontiers = sorted(
            set([o["at"] for o in orders.values()] + list(contexts) + [self.position])
        )
        for at in frontiers:
            context = views[contexts[max(p for p in contexts if p <= at)]]
            for n in sorted(self.raw, key=order):
                if n in forced or n in chosen or states.get(n) == "conflicting":
                    continue
                if n in pending:
                    states[n] = "pending"
                elif n not in orders:
                    states[n] = "unresolved"
                elif orders[n]["at"] > at:
                    continue
                elif not self.verified[n]:
                    states[n] = "invalid"
                elif any(
                    p not in chosen
                    or (p not in anchors and p not in forced and not final(p, context))
                    for p in parents(n)
                ):
                    states[n] = "dependent-conflict"
                elif not self.enabled and not final(n, context):
                    states[n] = "unsupported"
                else:
                    eligible.setdefault(n, at)
                    rivals = {held[o] for o in inputs(n) if o in held}
                    prior = next(iter(rivals)) if len(rivals) == 1 else None
                    replace = (
                        prior is not None
                        and prior not in forced
                        and not final(prior, context)
                        and increases(prior, n)
                    )
                    if rivals and not replace:
                        states[n] = "conflicting"
                        continue
                    if prior:
                        chosen.remove(prior)
                        states[prior] = "conflicting"
                        replacement[n] = prior
                        for o in inputs(prior):
                            del held[o]
                    chosen.add(n)
                    held.update({o: n for o in inputs(n)})
                    states[n] = "selected"
        replaced = set(replacement.values())

        def root(n):
            return root(replacement[n]) if n in replacement else n

        rank = {n: i for i, n in enumerate(sorted(self.raw, key=order))}
        chosen, held = anchors | forced, {o: n for n in forced for o in inputs(n)}
        for n in sorted(
            self.raw,
            key=lambda n: (eligible.get(root(n), float("inf")), rank[root(n)], rank[n]),
        ):
            if n in forced:
                states[n] = "included"
            elif n in pending:
                states[n] = "pending"
            elif n not in orders:
                states[n] = "unresolved"
            elif not self.verified[n]:
                states[n] = "invalid"
            elif n in replaced:
                states[n] = "conflicting"
            elif any(
                p not in chosen
                or (
                    p not in anchors
                    and p not in forced
                    and not final(p, views[self.view])
                )
                for p in parents(n)
            ):
                states[n] = "dependent-conflict"
            elif not self.enabled and not final(n, views[self.view]):
                states[n] = "unsupported"
            elif any(o in held for o in inputs(n)):
                states[n] = "conflicting"
            else:
                chosen.add(n)
                held.update({o: n for o in inputs(n)})
                states[n] = (
                    "selected-final"
                    if final(n, views[self.view])
                    else "selected-non-final"
                )
        spent = {
            o: n
            for n in chosen - anchors
            if final(n, views[self.view])
            for o in inputs(n)
        }
        rows = sorted(
            f"{name}/{source['generation']}/{outpoint}/{'present' if row['present'] else 'absent'}/{row['sequence']}"
            for name, source in self.sources.items()
            for outpoint, row in source["rows"].items()
        )
        current = sorted(
            o
            for o in watch
            if o.split(":")[0] in chosen
            and final(o.split(":")[0], views[self.view])
            and o not in spent
            and not any(o in inputs(p) for p in pending)
        )
        stale = sorted(f"{n}:{self.last[n]}" for n in pending if n in self.last)
        self.last.update({n: state for n, state in states.items() if n not in pending})
        return dict(
            view=self.view,
            states=sorted(f"{n}:{state}" for n, state in states.items()),
            current=current,
            spent=sorted(f"{o}->{n}" for o, n in spent.items() if o in watch),
            memberships=rows,
            stale=stale,
            walletActions=0,
            orders={
                n: dict(
                    readyAt=o["at"],
                    depth=o["depth"],
                    firstRaw=self.raw[n]["position"],
                    context=o["context"],
                )
                for n, o in sorted(orders.items())
                if self.verified.get(n)
                and all(p in anchors or self.verified.get(p) for p in parents(n))
            },
        )


class JournalStore:
    """Append journal and its complete model projection in one SQLite WAL commit."""

    def __init__(self, path, enabled=True, watch=()):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS journal (position INTEGER PRIMARY KEY, event TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS projection (id INTEGER PRIMARY KEY CHECK(id=1), through INTEGER, state TEXT)"
        )
        self.model = Model(enabled)
        self.watch = watch
        for (event,) in self.db.execute("SELECT event FROM journal ORDER BY position"):
            self.model.event(json.loads(event))
        saved = self.db.execute(
            "SELECT through,state FROM projection WHERE id=1"
        ).fetchone()
        if saved:
            assert saved[0] == len(self.model.journal)
            assert json.loads(saved[1]) == self.model.snapshot(
                watch
            ), "journal/projection diverged"

    def commit(self, event, crash=None):
        self.model.event(event)
        count = len(self.model.journal)
        self.db.execute("BEGIN IMMEDIATE")
        self.db.execute("INSERT INTO journal VALUES (?,?)", (count, json.dumps(event)))
        self.db.execute(
            "INSERT OR REPLACE INTO projection VALUES (1,?,?)",
            (count, json.dumps(self.model.snapshot(self.watch))),
        )
        if crash == "before":
            os._exit(73)
        self.db.commit()
        if crash == "after":
            os._exit(74)


if len(sys.argv) > 1 and sys.argv[1] == "--crash":
    store = JournalStore(sys.argv[2])
    store.commit(dict(op="verify", names=["A"]), crash=sys.argv[3])
    raise AssertionError("did not crash")

checkpoints = restarts = 0
with tempfile.TemporaryDirectory(prefix="brc192-reconciliation-") as directory:
    for index, trace in enumerate(traces):
        for durable in (False, True):
            path = Path(directory) / f"{index}.sqlite"
            store = (
                JournalStore(path, trace.get("nonFinal", True), trace["watch"])
                if durable
                else None
            )
            model = store.model if store else Model(trace.get("nonFinal", True))
            for step in trace["steps"]:
                if step["op"] == "restart":
                    before = model.snapshot(trace["watch"])
                    if store:
                        store.db.close()
                        store = JournalStore(
                            path, trace.get("nonFinal", True), trace["watch"]
                        )
                        model = store.model
                    else:
                        journal = copy.deepcopy(model.journal)
                        model = Model(trace.get("nonFinal", True))
                        for event in journal:
                            model.event(event)
                    assert model.snapshot(trace["watch"]) == before, trace["name"]
                    restarts += 1
                elif step["op"] == "expect":
                    got = model.snapshot(trace["watch"])
                    for key, want in step["value"].items():
                        assert got[key] == want, (trace["name"], key, got[key], want)
                    checkpoints += 1
                elif store:
                    store.commit(step)
                else:
                    model.event(step)
            if store:
                store.db.close()
    for crash, code, count in [("before", 73, 1), ("after", 74, 2)]:
        path = Path(directory) / f"crash-{crash}.sqlite"
        store = JournalStore(path)
        store.commit(dict(op="receive", names=["A"], source="a"))
        store.db.close()
        result = subprocess.run(
            [sys.executable, __file__, "--crash", str(path), crash], capture_output=True
        )
        assert result.returncode == code, result.stderr.decode()
        store = JournalStore(path)
        assert len(store.model.journal) == count
        assert store.model.snapshot()["states"] == [
            f"A:{'pending' if crash=='before' else 'selected-final'}"
        ]
        store.db.close()
print(
    json.dumps(
        dict(
            reconciliation="BitcoinX + independent Python model + SQLite WAL",
            transactions=len(txs),
            inputChecks=input_checks,
            headers=len(headers),
            finality=len(corpus["finality"]),
            replacements=len(corpus["replacements"]),
            traces=len(traces),
            adapterRuns=2 * len(traces),
            checkpoints=checkpoints,
            restarts=restarts,
            processCrashes=2,
        )
    )
)
