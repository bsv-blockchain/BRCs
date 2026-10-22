// BRC-255 test script: the §1 clause under the @bsv/sdk interpreter, §3 issuer key derivation.
import { Hash, LockingScript, OP, P2PKH, PrivateKey, Spend, Transaction, TransactionSignature, UnlockingScript } from '@bsv/sdk'

const MARKER = [0x62, 0x6e, 0x74]
const HOLDER_SCOPE = TransactionSignature.SIGHASH_ALL | TransactionSignature.SIGHASH_ANYONECANPAY | TransactionSignature.SIGHASH_FORKID

const holder = PrivateKey.fromRandom()
const stranger = PrivateKey.fromRandom()
const assetId = Hash.hash160([...new Array(32).fill(1), 0])

const held = new LockingScript()
  .writeBin([...MARKER, ...assetId]).writeBin([0x40, 0x42, 0x0f]).writeOpCode(OP.OP_2DROP)
  .writeBin(holder.toPublicKey().encode(true)).writeOpCode(OP.OP_CHECKSIG)

function verifies(lock, unlock) {
  const parent = new Transaction()
  parent.addInput({ sourceTXID: '00'.repeat(32), sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff })
  parent.addOutput({ satoshis: 1, lockingScript: lock })
  const tx = new Transaction()
  tx.addInput({ sourceTransaction: parent, sourceOutputIndex: 0, sequence: 0xffffffff })
  tx.addOutput({ satoshis: 1, lockingScript: new P2PKH().lock(holder.toAddress()) })
  const common = {
    sourceTXID: parent.id('hex'), sourceOutputIndex: 0, sourceSatoshis: 1, transactionVersion: tx.version,
    otherInputs: [], inputIndex: 0, outputs: tx.outputs, inputSequence: 0xffffffff, lockTime: tx.lockTime,
  }
  const sign = (key, scope) => {
    const s = key.sign(Hash.sha256(TransactionSignature.format({ ...common, subscript: lock, scope })))
    return new TransactionSignature(s.r, s.s, scope).toChecksigFormat()
  }
  try {
    return new Spend({ ...common, lockingScript: lock, unlockingScript: unlock(sign) }).validate()
  } catch {
    return false
  }
}

const u = () => new UnlockingScript()
const checks = [
  ['§1 holder spends', true, verifies(held, (s) => u().writeBin(s(holder, HOLDER_SCOPE)))],
  ['§1 stranger cannot spend', false, verifies(held, (s) => u().writeBin(s(stranger, HOLDER_SCOPE)))],
  ['§1 held prefix push is 23 bytes and starts "bnt"', true,
    held.chunks[0].data.length === 23 && held.chunks[0].data.slice(0, 3).every((b, i) => b === MARKER[i])],
]

const identity = PrivateKey.fromRandom()
const anyone = new PrivateKey(1)
const byIssuer = identity.deriveChild(anyone.toPublicKey(), '2-bnt issuer-1').toPublicKey().toString()
const byReader = identity.toPublicKey().deriveChild(anyone, '2-bnt issuer-1').toString()
checks.push(['§3 issuer key derivable from iss', true, byIssuer === byReader])

let failed = 0
for (const [name, want, got] of checks) {
  const ok = want === got
  if (!ok) failed += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}`)
}
console.log(`lock bytes: held ${held.toBinary().length}`)
process.exit(failed ? 1 : 0)
