// The Bitcoin half of the E2E experiment, on the pinned mainnet evidence:
// SPV settles each token transaction, the holder's one signature unlocks each
// token input, the issuer signed the deploy, and the script never reads an
// amount. The token rules half is crates/bnt-step/tests/mainnet_e2e.rs.
//
//     npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { Transaction, Spend, Script, LockingScript, UnlockingScript, OP, PrivateKey, PublicKey, P2PKH, Hash, Utils } from '@bsv/sdk'

const evidence = JSON.parse(readFileSync(new URL('./mainnet.json', import.meta.url), 'utf8'))
const ROLES = ['deploy', 'split', 'merge']
const tx = Object.fromEntries(ROLES.map((role) => [role, Transaction.fromHex(evidence.txs[role].hex)]))
const parentOf = (input) => Transaction.fromHex(evidence.parents[input.sourceTXID])
const hex = (bytes) => Utils.toHex(bytes)
const internal = (display) => Utils.toArray(display, 'hex').reverse()

function header(h) {
  const le = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]
  return [...le(h.version), ...internal(h.prev), ...internal(h.merkleroot), ...le(h.time), ...le(parseInt(h.bits, 16)), ...le(h.nonce)]
}

function merkleRoot(txid, { index, nodes }) {
  let hash = internal(txid)
  for (const [depth, node] of nodes.entries()) {
    const sibling = node === '*' ? hash : internal(node)
    hash = Hash.hash256((index >> depth) & 1 ? [...sibling, ...hash] : [...hash, ...sibling])
  }
  return hex(hash.reverse())
}

function spend(t, index) {
  const input = t.inputs[index]
  const source = parentOf(input).outputs[input.sourceOutputIndex]
  return {
    source,
    run: new Spend({
      sourceTXID: input.sourceTXID,
      sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: source.satoshis,
      lockingScript: source.lockingScript,
      transactionVersion: t.version,
      otherInputs: t.inputs.filter((_, i) => i !== index),
      outputs: t.outputs,
      inputIndex: index,
      unlockingScript: input.unlockingScript,
      inputSequence: input.sequence,
      lockTime: t.lockTime,
    }),
  }
}

const isToken = (script) => hex(script.chunks[0]?.data ?? []).startsWith('626e74')

test('SPV: each token transaction is in a block whose header meets its proof of work', () => {
  let height = 0
  for (const role of ROLES) {
    const { txid, proof } = evidence.txs[role]
    assert.equal(tx[role].id('hex'), txid, `${role} bytes hash to its txid`)
    const h = evidence.headers[proof.block]
    const hash = hex(Hash.hash256(header(h)).reverse())
    assert.equal(hash, proof.block, `${role}: header hashes to its block`)
    const bits = parseInt(h.bits, 16)
    const target = BigInt(bits & 0xffffff) << BigInt(8 * ((bits >>> 24) - 3))
    assert.ok(BigInt('0x' + hash) <= target, `${role}: block meets its target`)
    assert.equal(merkleRoot(txid, proof), h.merkleroot, `${role}: merkle path reaches the header's root`)
    assert.ok(h.height >= height, `${role} is mined no earlier than its parent`)
    height = h.height
  }
})

test('Links: the split spends the deploy output and the merge spends both split outputs', () => {
  const outpoints = (t) => t.inputs.map((i) => `${i.sourceTXID}:${i.sourceOutputIndex}`)
  assert.ok(outpoints(tx.split).includes(`${evidence.txs.deploy.txid}:0`))
  for (const vout of [0, 1]) assert.ok(outpoints(tx.merge).includes(`${evidence.txs.split.txid}:${vout}`))
})

test('Scripts: every input of every token transaction validates against the output it spends', () => {
  for (const role of ROLES) {
    tx[role].inputs.forEach((_, index) => {
      assert.equal(spend(tx[role], index).run.validate(), true, `${role} input ${index}`)
    })
  }
})

test('One key: each token input is unlocked by one signature against one holder key', () => {
  let checked = 0
  for (const role of ['split', 'merge']) {
    tx[role].inputs.forEach((input, index) => {
      const { source } = spend(tx[role], index)
      if (!isToken(source.lockingScript)) return
      const chunks = source.lockingScript.chunks
      const lastDrop = chunks.findLastIndex((c) => c.op === OP.OP_2DROP || c.op === OP.OP_DROP)
      const clause = chunks.slice(lastDrop + 1)
      assert.equal(clause.length, 2, `${role} input ${index}: clause is <key> OP_CHECKSIG`)
      assert.equal(clause[0].data.length, 33)
      assert.equal(clause[1].op, OP.OP_CHECKSIG)
      const unlock = input.unlockingScript.chunks
      assert.equal(unlock.length, 1, `${role} input ${index}: unlock is one push`)
      const scope = unlock[0].data.at(-1)
      assert.ok(scope & 0x40 && (scope & 0x1f) === 1, `${role} input ${index}: signed ALL with FORKID, so every output is fixed`)
      checked++
    })
  }
  assert.equal(checked, 3)
})

test('Issuer: the deploy spends a coin locked to the key anyone derives from the payload iss, signed ALL | FORKID', () => {
  // The payload is DAG-CBOR; a single issuer is text "iss" then a 33-byte string.
  const payload = hex(tx.deploy.outputs[0].lockingScript.chunks[2].data)
  const at = payload.indexOf('6369737358' + '21')
  assert.ok(at >= 0, 'the payload names one issuer')
  const identity = payload.slice(at + 12, at + 12 + 66)
  const issuerKey = PublicKey.fromString(identity).deriveChild(new PrivateKey(1), '2-bnt issuer-1').toString()
  const signed = tx.deploy.inputs.filter((input, index) => {
    const chunks = spend(tx.deploy, index).source.lockingScript.chunks
    return chunks.length === 2 && hex(chunks[0].data ?? []) === issuerKey && chunks[1].op === OP.OP_CHECKSIG && input.unlockingScript.chunks[0].data.at(-1) === 0x41
  })
  assert.equal(signed.length, 1, `one input spends <${issuerKey}> OP_CHECKSIG`)
})

test('Walk time: parsing the three hops, their SPV and every input script, merge back to the deploy', (t) => {
  const walk = () => {
    for (const role of ROLES) {
      const { hex: raw, proof } = evidence.txs[role]
      const parsed = Transaction.fromHex(raw)
      const h = evidence.headers[proof.block]
      assert.equal(hex(Hash.hash256(header(h)).reverse()), proof.block)
      assert.equal(merkleRoot(parsed.id('hex'), proof), h.merkleroot)
      parsed.inputs.forEach((_, index) => assert.equal(spend(parsed, index).run.validate(), true))
    }
  }
  walk()
  const runs = Array.from({ length: 21 }, () => {
    const started = performance.now()
    walk()
    return performance.now() - started
  }).sort((a, b) => a - b)
  t.diagnostic(`walk of 3 hops: median ${runs[10].toFixed(1)} ms over ${runs.length} runs`)
})

test('Miners do not check amounts: a script that writes more units than it spends still validates', async () => {
  const asset = Utils.toArray('626e74' + evidence.asset, 'hex')
  const held = (amount, key) =>
    new LockingScript(new Script().writeBin(asset).writeNumber(amount).writeOpCode(OP.OP_2DROP).writeBin(key.toPublicKey().encode(true)).writeOpCode(OP.OP_CHECKSIG).chunks)
  const holder = PrivateKey.fromRandom()
  const parent = new Transaction(1, [], [{ satoshis: 1, lockingScript: held(1000, holder) }], 0)
  const child = new Transaction(1, [{ sourceTransaction: parent, sourceOutputIndex: 0, sequence: 0xffffffff }], [{ satoshis: 1, lockingScript: held(1001, PrivateKey.fromRandom()) }], 0)
  const signed = await new P2PKH().unlock(holder).sign(child, 0)
  child.inputs[0].unlockingScript = new UnlockingScript([signed.chunks[0]])
  const run = new Spend({
    sourceTXID: parent.id('hex'),
    sourceOutputIndex: 0,
    sourceSatoshis: 1,
    lockingScript: parent.outputs[0].lockingScript,
    transactionVersion: 1,
    otherInputs: [],
    outputs: child.outputs,
    inputIndex: 0,
    unlockingScript: child.inputs[0].unlockingScript,
    inputSequence: 0xffffffff,
    lockTime: 0,
  })
  assert.equal(run.validate(), true, '1000 in, 1001 out: the script accepts it, so the recipient must refuse it')
})
