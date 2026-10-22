// BRC-253 test script: the §2 clause and §9 beacon under the @bsv/sdk interpreter, §2 holder keys, §11 resolution.
import { Hash, LockingScript, OP, P2PKH, PrivateKey, Spend, TransactionSignature, UnlockingScript } from '@bsv/sdk'

const { SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, SIGHASH_FORKID } = TransactionSignature
const HOLDER = SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID
const SALE = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID
const ISSUER = SIGHASH_ALL | SIGHASH_FORKID
const MARKER = [0x69, 0x70, 0x74]

const key = () => PrivateKey.fromRandom()
const pub = (k) => k.toPublicKey().encode(true)
const [holder, issuer, stranger, buyer] = [key(), key(), key(), key()]
const cosigners = [key(), key(), key()]
const custodians = [key(), key(), key()]
const secret = Hash.sha256([...'release secret'].map((c) => c.charCodeAt(0)))
const assetId = Hash.hash160([...new Array(32).fill(1), 0])

const release = (s) => s.writeOpCode(OP.OP_HASH160).writeBin(Hash.hash160(secret)).writeOpCode(OP.OP_EQUAL)
const multisig = (s, m, keys) => {
  s.writeOpCode(OP.OP_1 + m - 1)
  for (const k of keys) s.writeBin(pub(k))
  return s.writeOpCode(OP.OP_1 + keys.length - 1).writeOpCode(OP.OP_CHECKMULTISIG)
}
const single = (s) => s.writeBin(pub(issuer)).writeOpCode(OP.OP_CHECKSIG)
const shared = (s) => multisig(s, 2, cosigners)
const keySet = (s) => multisig(s, 2, custodians)

function held(holderKey, amount, { iss = single, rel = release } = {}) {
  const s = new LockingScript()
    .writeBin([...MARKER, ...assetId]).writeBin(amount).writeOpCode(OP.OP_2DROP)
    .writeBin(pub(holderKey)).writeOpCode(OP.OP_CHECKSIGVERIFY).writeOpCode(OP.OP_IF)
  iss(s)
  s.writeOpCode(OP.OP_ELSE)
  rel(s)
  return s.writeOpCode(OP.OP_ENDIF)
}
function beacon({ iss = single, rel = release } = {}) {
  const s = new LockingScript().writeOpCode(OP.OP_IF)
  iss(s)
  s.writeOpCode(OP.OP_ELSE)
  rel(s)
  return s.writeOpCode(OP.OP_ENDIF)
}

const out = (lockingScript, satoshis = 1) => ({ satoshis, lockingScript })
const plain = (k, satoshis = 1) => out(new P2PKH().lock(k.toAddress()), satoshis)
const coin = (n) => ({ sourceTXID: n.toString(16).padStart(64, '0'), sourceOutputIndex: 0, sequence: 0xffffffff })

function ctx(lock, outputs, otherInputs = [coin(1)], sats = 1) {
  return {
    sourceTXID: 'ab'.repeat(32), sourceOutputIndex: 0, sourceSatoshis: sats, transactionVersion: 1,
    otherInputs, inputIndex: 0, outputs, inputSequence: 0xffffffff, lockTime: 0, lockingScript: lock,
  }
}
function sig(k, scope, c) {
  const s = k.sign(Hash.sha256(TransactionSignature.format({ ...c, subscript: c.lockingScript, scope })))
  return new TransactionSignature(s.r, s.s, scope).toChecksigFormat()
}
function valid(c, unlockingScript) {
  try {
    return new Spend({ ...c, unlockingScript }).validate()
  } catch {
    return false
  }
}
const u = (...items) => {
  const s = new UnlockingScript()
  for (const i of items) typeof i === 'number' ? s.writeOpCode(i) : s.writeBin(i)
  return s
}

const amount = [0x40, 0x42, 0x0f]
const lock = held(holder, amount)
const outputs = [out(held(buyer, amount))]
const c = ctx(lock, outputs)
const accepted = u(sig(issuer, ISSUER, c), OP.OP_1, sig(holder, HOLDER, c))
const checks = [
  ['§2 holder and issuer spend', true, valid(c, accepted)],
  ['§2 holder alone cannot spend', false, valid(c, u(OP.OP_1, sig(holder, HOLDER, c)))],
  ['§2 issuer alone cannot spend', false, valid(c, u(sig(issuer, ISSUER, c), OP.OP_1, sig(stranger, HOLDER, c)))],
  ['§2 stranger cannot countersign', false, valid(c, u(sig(stranger, ISSUER, c), OP.OP_1, sig(holder, HOLDER, c)))],
  ['§2 false spent amount fails', false, valid(ctx(lock, outputs, [coin(1)], 2), accepted)],
  ['§2 false clause fails', false, valid(ctx(held(holder, amount, { rel: keySet }), outputs), accepted)],
  ['§2 changing an output after countersigning fails', false, valid(ctx(lock, [plain(stranger)]), accepted)],
  ['§2 changing an input after countersigning fails', false, valid(ctx(lock, outputs, [coin(2)]), accepted)],
  ['§2 release secret with holder spends', true, valid(c, u(secret, OP.OP_0, sig(holder, HOLDER, c)))],
  ['§2 wrong secret fails', false, valid(c, u(Hash.sha256(secret), OP.OP_0, sig(holder, HOLDER, c)))],
  ['§2 release secret without holder fails', false, valid(c, u(secret, OP.OP_0, sig(stranger, HOLDER, c)))],
  ['§2 issuer cannot use the release branch', false, valid(c, u(sig(issuer, ISSUER, c), OP.OP_0, sig(holder, HOLDER, c)))],
  ['§15 held lock is 125 bytes', true, lock.toBinary().length === 125],
  ['§15 accepted unlock is at most 147 bytes', true, accepted.toBinary().length <= 147],
]

const sharedLock = held(holder, amount, { iss: shared })
const sc = ctx(sharedLock, outputs)
const cs = (i) => sig(cosigners[i], ISSUER, sc)
checks.push(
  ['§2 shared set: two cosigners in key order spend', true, valid(sc, u(OP.OP_0, cs(0), cs(2), OP.OP_1, sig(holder, HOLDER, sc)))],
  ['§2 shared set: one cosigner fails', false, valid(sc, u(OP.OP_0, cs(1), OP.OP_1, sig(holder, HOLDER, sc)))],
)

const ksLock = held(holder, amount, { rel: keySet })
const kc = ctx(ksLock, outputs)
const rs = (i) => sig(custodians[i], ISSUER, kc)
checks.push(
  ['§2 key-set release: two custodians with holder spend', true, valid(kc, u(OP.OP_0, rs(0), rs(1), OP.OP_0, sig(holder, HOLDER, kc)))],
  ['§2 key-set release: one custodian fails', false, valid(kc, u(OP.OP_0, rs(0), OP.OP_0, sig(holder, HOLDER, kc)))],
  ['§2 key-set release: custodians without holder fail', false, valid(kc, u(OP.OP_0, rs(0), rs(1), OP.OP_0, sig(stranger, HOLDER, kc)))],
)

const feeA = [coin(10)]
const feeB = [coin(11)]
const holderSig = sig(holder, HOLDER, ctx(lock, outputs, feeA))
const replaced = ctx(lock, outputs, feeB)
checks.push(
  ['§6 replacement: holder signature survives a new fee input', true, valid(replaced, u(sig(issuer, ISSUER, replaced), OP.OP_1, holderSig))],
  ['§6 replacement that changes an output fails', false,
    valid(ctx(lock, [plain(stranger)], feeB), u(sig(issuer, ISSUER, ctx(lock, [plain(stranger)], feeB)), OP.OP_1, holderSig))],
)

const price = plain(holder, 5000)
const saleSig = sig(holder, SALE, ctx(lock, [price], []))
const bought = ctx(lock, [price, out(held(buyer, amount))], [coin(20)])
const cheap = ctx(lock, [plain(holder, 4000), out(held(buyer, amount))], [coin(20)])
checks.push(
  ['§6 sale signed 0xC3 before a buyer, completed by buyer and issuer', true, valid(bought, u(sig(issuer, ISSUER, bought), OP.OP_1, saleSig))],
  ['§6 lowering the price after the seller signed fails', false, valid(cheap, u(sig(issuer, ISSUER, cheap), OP.OP_1, saleSig))],
)

const bl = beacon()
const next = [out(bl)]
const bc = ctx(bl, next)
checks.push(
  ['§9 issuer refreshes the beacon', true, valid(bc, u(sig(issuer, ISSUER, bc), OP.OP_1))],
  ['§9 release secret spends the beacon', true, valid(bc, u(secret, OP.OP_0))],
  ['§9 issuer cannot use the beacon release branch', false, valid(bc, u(sig(issuer, ISSUER, bc), OP.OP_0))],
  ['§9 secret cannot use the beacon issuer branch', false, valid(bc, u(secret, OP.OP_1))],
)

const sender = key()
const invoice = '2-ipt holder-prefix suffix'
const holderPriv = holder.deriveChild(sender.toPublicKey(), invoice)
const holderPub = holder.toPublicKey().deriveChild(sender, invoice)
const linkage = Hash.sha256hmac(sender.deriveSharedSecret(holder.toPublicKey()).encode(true), invoice)
const linked = holder.toPublicKey().add(new PrivateKey(linkage).toPublicKey())
const childLock = held(holderPriv, amount)
const cc = ctx(childLock, outputs)
checks.push(
  ['§2 recipient derives the holder key its sender wrote', true, holderPriv.toPublicKey().toString() === holderPub.toString()],
  ['§2 holder key is not the identity key', false, holderPub.toString() === holder.toPublicKey().toString()],
  ['§5 identityKey + linkage·G is the holder key', true, linked.encode(true, 'hex') === holderPub.toString()],
  ['§2 derived holder key spends under countersignature', true, valid(cc, u(sig(issuer, ISSUER, cc), OP.OP_1, sig(holderPriv, HOLDER, cc)))],
)

const CLAUSE = 'deploy clause'
function resolve({ inputs, outputs: outs }, { item = false, released = false } = {}) {
  if (inputs.length === 0) return false
  if (outs.some((o) => o.clause !== CLAUSE)) return false
  if (inputs.some((i) => i.branch === 'release') && !released) return false
  const sum = (rows) => rows.reduce((t, r) => t + r.amount, 0)
  if (sum(inputs) !== sum(outs)) return false
  return !item || sum(outs) === 1
}
const row = (amount, branch = 'issuer', clause = CLAUSE) => ({ amount, branch, clause })
checks.push(
  ['§11 token transfer resolves', true, resolve({ inputs: [row(100)], outputs: [row(60), row(40)] })],
  ['§11 inflating transfer refused', false, resolve({ inputs: [row(100)], outputs: [row(100), row(1)] })],
  ['§11 item written twice refused', false, resolve({ inputs: [row(1)], outputs: [row(1), row(1)] }, { item: true })],
  ['§11 deploy paid straight to a recipient refused', false, resolve({ inputs: [], outputs: [row(100)] })],
  ['§11 output under another clause refused', false, resolve({ inputs: [row(100)], outputs: [row(100, 'issuer', 'other')] })],
  ['§11 release-branch input refused while no release is mined', false, resolve({ inputs: [row(100, 'release')], outputs: [row(100)] })],
  ['§11 release-branch input resolves once the release is mined', true, resolve({ inputs: [row(100, 'release')], outputs: [row(100)] }, { released: true })],
)

function audit(tx, deploy, seen = new Set()) {
  if (tx === deploy || seen.has(tx)) return true
  seen.add(tx)
  if (!resolve(tx, { released: true })) return false
  return tx.inputs.every((i) => audit(i.from, deploy, seen))
}
const spend = (from, amount, outs) => ({ inputs: [{ ...row(amount), from }], outputs: outs.map((a) => row(a)) })
const deployTx = { inputs: [], outputs: [row(100)] }
const honest = spend(spend(deployTx, 100, [60, 40]), 60, [30, 30])
const counterfeit = { inputs: [], outputs: [row(1000)] }
const laundered = spend(counterfeit, 1000, [500, 500])
checks.push(
  ['§11 audit passes an honest history back to the deploy', true, audit(honest, deployTx)],
  ['§11 resolver alone accepts a transfer of counterfeit units', true, resolve(laundered)],
  ['§11 audit catches the counterfeit units', false, audit(laundered, deployTx)],
)

let failed = 0
for (const [name, want, got] of checks) {
  const ok = want === got
  if (!ok) failed += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`)
}
console.log(`lock bytes: held ${lock.toBinary().length}, unlock ${accepted.toBinary().length}`)
process.exit(failed ? 1 : 0)
