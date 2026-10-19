// BRC-232 executable documentation fixtures. PUBLIC TEST KEYS; no network I/O.
// npm ci --ignore-scripts; node transaction-delivery.mjs [--write]
// --write regenerates transaction-delivery-vectors.json (encryption uses fresh nonces).
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import canonicalize from 'canonicalize'
import * as cbor from '@ipld/dag-cbor'
import { PrivateKey, ProtoWallet, KeyDeriver, Transaction, MerklePath, LockingScript,
  UnlockingScript, P2PKH, EncryptedMessage } from '@bsv/sdk'

let checks = 0
const ok = (b, message) => { assert(b, message); checks++ }
const equal = (a, b) => { assert.deepEqual(a, b); checks++ }
const fails = fn => { assert.throws(fn); checks++ }
const bytes = hex => [...Buffer.from(hex, 'hex')]
const hex = data => Buffer.from(data).toString('hex')
const sha = data => createHash('sha256').update(data).digest('hex')
const alice = new PrivateKey(11), bob = new PrivateKey(22), deliverer = new PrivateKey(33), attester = new PrivateKey(5555)
const identities = Object.fromEntries(Object.entries({ alice, bob, deliverer, attester }).map(([k,v]) => [k,v.toPublicKey().toString()]))
const A = new KeyDeriver(alice), B = new KeyDeriver(bob)
const aliceWallet = new ProtoWallet(alice), delivererWallet = new ProtoWallet(deliverer), attesterWallet = new ProtoWallet(attester)
const verifier = new ProtoWallet('anyone')
const p2pkh = new P2PKH()
const PREFIX = 'AQ==', SUFFIX = 'Ag=='
const colorProtocol = assetId => [2, `p color ${assetId === 'ISSUE' ? 'issue' : assetId.replace('_','v')} 41513d3d 41673d3d`]
const paymentProtocol = [2, '3241645161d8']
const paymentKeyId = `${PREFIX} ${SUFFIX}`
const fundingKey = A.derivePrivateKey(paymentProtocol, paymentKeyId, 'anyone')
const payerTokenKey = A.derivePrivateKey(colorProtocol('ISSUE'), 'color', 'anyone')
const bobKey = id => B.derivePrivateKey(colorProtocol(id), 'color', identities.alice)
const satoshiKey = B.derivePrivateKey(paymentProtocol, paymentKeyId, identities.alice)
const roots = new Map()
let height = 100000
function funding() {
  // Synthetic mature coinbase. Its Merkle root is accepted ONLY by this fixture tracker.
  const h = height++
  const t = new Transaction(1, [{sourceTXID:'00'.repeat(32),sourceOutputIndex:0xffffffff,
    unlockingScript:new UnlockingScript().writeNumber(h),sequence:0xffffffff}],
    [{satoshis:1000,lockingScript:p2pkh.lock(fundingKey.toPublicKey().toAddress())}],0)
  t.merklePath = new MerklePath(h, [[{offset:0,hash:t.id('hex'),txid:true}]])
  roots.set(h,t.id('hex')); return t
}
const tracker = { isValidRootForHeight: async (root,h) => roots.get(h)===root, currentHeight: async()=>100200 }
function colorScript(id,amount,key,req) {
  const s = new LockingScript().writeBin(id === 'ISSUE' ? [] : [...Buffer.from(id.split('_')[0],'hex').reverse()]).writeNumber(amount).writeOpCode(109)
  if(req) s.writeBin([...cbor.encode({req})]).writeOpCode(117)
  for(const chunk of p2pkh.lock(key.toPublicKey().toAddress()).chunks) s.chunks.push(chunk)
  return s
}
async function spend(inputs, outputs) {
  const tx=new Transaction(1,[],[],0)
  for(const [sourceTransaction,key] of inputs) tx.addInput({sourceTransaction,sourceOutputIndex:0,
    sequence:0xffffffff,unlockingScriptTemplate:p2pkh.unlock(key,'all',false)})
  for(const o of outputs)tx.addOutput(o)
  await tx.sign(); ok(await tx.verify(tracker),'fixture transaction and SPV chain must verify'); return tx
}
async function lifecycle(tx,anchor) {
  const statement={version:1,network:'mainnet',rootTXID:tx.id('hex'),anchor:`${anchor.id('hex')}.0`,mode:'never',value:null}
  const data=[...Buffer.from('BRC177-LIFECYCLE-V1\n'+JSON.stringify(statement))]
  const args={protocolID:[2,'p nosend lifecycle'],keyID:'1',counterparty:'anyone',data}
  const {signature}=await aliceWallet.createSignature(args)
  ok((await verifier.verifySignature({...args,counterparty:identities.alice,forSelf:false,signature})).valid,'lifecycle derived signature')
  return {statement,signer:identities.alice,signature:hex(signature)}
}
const ATT='https://brc.dev/207/attested', RESOURCE='https://brc.dev/209'
const reqAtt={[ATT]:{version:1,params:{trustMode:'any'}}}
const reqResource={[RESOURCE]:{version:1,params:null}}
async function deploy(amount,req) {
  const anchor=funding()
  // Large optional display payload tests the profile-scoped >1000-byte receipt.
  let script=colorScript('ISSUE',amount,payerTokenKey,req)
  if(req?.[RESOURCE]) {
    const payload={req,note:'Public synthetic fixture display metadata. '.repeat(18)}
    script=new LockingScript().writeBin([]).writeNumber(amount).writeOpCode(109).writeBin([...cbor.encode(payload)]).writeOpCode(117)
    script.chunks.push(...p2pkh.lock(payerTokenKey.toPublicKey().toAddress()).chunks)
  }
  const tx=await spend([[anchor,fundingKey]],[{satoshis:900,lockingScript:script}])
  return {tx,id:`${tx.id('hex')}_0`,req}
}
async function admission(parent) {
  const message=`1color-admit:v1:tm_color_${parent.id}:${parent.tx.id('hex')}:0`
  const args={protocolID:[2,'color admission attestation'],keyID:'1',counterparty:'anyone',data:[...Buffer.from(message)]}
  const {signature}=await attesterWallet.createSignature(args)
  ok((await verifier.verifySignature({...args,counterparty:identities.attester,forSelf:false,signature})).valid,'admission derived signature')
  return {txid:parent.tx.id('hex'),outputs:[0],signer:identities.attester,signature:hex(signature)}
}
const MIME='Content-Type: application/vnd.metanet.transaction+cbor\r\nContent-Transfer-Encoding: binary\r\n\r\n'
function validateShape(body) {
  assert.equal(body.version,1)
  assert(body.txid instanceof Uint8Array && body.txid.length===32)
  assert(body.beef instanceof Uint8Array && body.beef.length>0)
  assert(Array.isArray(body.outputs)&&body.outputs.length>0)
  assert(Array.isArray(body.lifecycles))
  assert(Object.keys(body).every(k=>['version','txid','beef','outputs','lifecycles','memo','profileData'].includes(k)))
  const tx=Transaction.fromBEEF([...body.beef],hex(body.txid))
  assert.equal(tx.id('hex'),hex(body.txid))
  let prev=-1, instructionBytes=0
  for(const output of body.outputs){
    assert(Number.isInteger(output.outputIndex)&&output.outputIndex>prev&&output.outputIndex<tx.outputs.length);prev=output.outputIndex
    if(output.protocol==='wallet payment') {
      assert.deepEqual(Object.keys(output).sort(),['outputIndex','paymentRemittance','protocol'])
      assert(output.paymentRemittance.senderIdentityKey.length===33)
    } else {
      assert.equal(output.protocol,'basket insertion')
      assert.deepEqual(Object.keys(output).sort(),['insertionRemittance','outputIndex','protocol'])
      const rem=output.insertionRemittance, inst=JSON.parse(rem.customInstructions)
      assert.equal(inst.version,1)
      const id=inst.assetId==='ISSUE'?`${tx.id('hex')}_0`:inst.assetId
      const target=`p color ${id.replace('_','v')}`
      assert(rem.basket===target||rem.basket===`${target} authority`)
      // These fixtures use binary deploys at output zero. Authenticate the
      // applicable descriptor from the actual deploy, not another receipt's leaf.
      const declaration=inst.assetId==='ISSUE'?tx:Transaction.fromBEEF([...body.beef],id.split('_')[0])
      assert.equal(declaration.id('hex'),id.split('_')[0])
      const script=declaration.outputs[0].lockingScript.chunks
      const req=script[3]?.data&&script[4]?.op===117?cbor.decode(new Uint8Array(script[3].data)).req:undefined
      const extended=(req?.[RESOURCE]?.version===1&&req[RESOURCE].params===null)||req?.[ATT]?.version===1
      const length=Buffer.byteLength(rem.customInstructions)
      assert(length<=(extended?16*1024*1024:1000),'authenticated per-receipt instruction bound')
      instructionBytes+=length
    }
  }
  assert(instructionBytes<=16*1024*1024,'aggregate instruction bound')
  return tx
}
function decode(mime,expectedHash){
  assert.equal(sha(mime),expectedHash)
  const cut=mime.indexOf(Buffer.from('\r\n\r\n'));assert(cut>=0&&cut<8192)
  assert.equal(mime.subarray(0,cut+4).toString(),MIME)
  const body=cbor.decode(mime.subarray(cut+4))
  assert.equal(hex(cbor.encode(body)),hex(mime.subarray(cut+4)))
  validateShape(body);return body
}
function walletOutputs(body){return body.outputs.map(o=>o.protocol==='wallet payment'?{...o,paymentRemittance:{...o.paymentRemittance,senderIdentityKey:hex(o.paymentRemittance.senderIdentityKey)}}:structuredClone(o))}
const fixtures=[]
async function record(name,tx,receipts,anchor,profileData,expectedPolicy) {
  const life=await lifecycle(tx,anchor)
  const body={version:1,txid:new Uint8Array(bytes(tx.id('hex'))),beef:new Uint8Array(tx.toBEEF()),outputs:receipts,lifecycles:[life]}
  if(profileData)body.profileData=profileData
  const mime=Buffer.concat([Buffer.from(MIME),cbor.encode(body)])
  equal(decode(mime,sha(mime)),cbor.decode(cbor.encode(body)))
  const encrypted=EncryptedMessage.encrypt([...mime],deliverer,bob.toPublicKey())
  equal(EncryptedMessage.decrypt(encrypted,bob),[...mime])
  const meta={metanetHandles:'1.0',recipient:{handle:'receiver',domain:'receiver.example'},
    sender:{identityKey:identities.deliverer},created:'2026-10-14T00:00:00Z',payment:null,contentHash:sha(mime)}
  const sigArgs={protocolID:[2,'metanet handles envelope'],keyID:'send',counterparty:'anyone',data:[...Buffer.from(canonicalize(meta))]}
  const {signature}=await delivererWallet.createSignature(sigArgs)
  ok((await verifier.verifySignature({...sigArgs,counterparty:identities.deliverer,forSelf:false,signature})).valid,'outer derived signature')
  const atom=Transaction.fromBEEF([...body.beef],hex(body.txid)).toAtomicBEEF()
  const outputs=walletOutputs(body)
  equal(outputs.map(o=>o.outputIndex),receipts.map(o=>o.outputIndex))
  const request={type:'CWI',isInvocation:true,id:Buffer.from(name).toString('base64'),call:'internalizeAction',args:{tx:atom,outputs,description:`Receive ${name} fixture`}}
  const response={type:'CWI',isInvocation:false,id:request.id,status:'success',result:{accepted:true}}
  fixtures.push({name,txid:tx.id('hex'),expectedPolicy,bodyCborHex:hex(cbor.encode(body)),mimeHex:hex(mime),
    contentHash:sha(mime),outerMetadata:meta,outerSignature:hex(signature),brc78CiphertextHex:hex(encrypted),lifecycles:[life],request,response})
  fails(()=>decode(Buffer.concat([mime,Buffer.from([0])]),sha(mime)))
  const changed=structuredClone(body);changed.outputs.push(changed.outputs[0]);fails(()=>validateShape(changed))
  const wrong=structuredClone(body);wrong.txid=new Uint8Array(32);fails(()=>validateShape(wrong))
  const unknown=structuredClone(body);unknown.accept=true;fails(()=>validateShape(unknown))
}
const payReceipt=index=>({outputIndex:index,protocol:'wallet payment',paymentRemittance:{derivationPrefix:PREFIX,derivationSuffix:SUFFIX,senderIdentityKey:new Uint8Array(bytes(identities.alice))}})
function colorReceipt(index,id,authority=false,profileData,actualId=id){
  const inst={version:1,assetId:id,derivationPrefix:PREFIX,derivationSuffix:SUFFIX,senderIdentityKey:identities.alice}
  if(profileData)inst.profileData=profileData
  return {outputIndex:index,protocol:'basket insertion',insertionRemittance:{basket:`p color ${actualId.replace('_','v')}${authority?' authority':''}`,customInstructions:JSON.stringify(inst)}}
}
let anchor=funding()
let tx=await spend([[anchor,fundingKey]],[{satoshis:900,lockingScript:p2pkh.lock(satoshiKey.toPublicKey().toAddress())}])
await record('ordinary-payment',tx,[payReceipt(0)],anchor,undefined,'Processor acceptance before internalization; BRC29 custody; deliverer differs from derivation sender.')
for(const [name,amount,req] of [['token-value',50,undefined],['token-authority',0,undefined],['resource',1,reqResource],['attested-token',50,reqAtt]]) {
  const parent=await deploy(amount,req);anchor=funding()
  tx=await spend([[parent.tx,payerTokenKey],[anchor,fundingKey]],[{satoshis:1800,lockingScript:colorScript(parent.id,name==='resource'?9:amount,bobKey(parent.id))}])
  let profileData
  if(name==='resource')profileData={[RESOURCE]:{[parent.id]:{declarationTx:parent.tx.toHex()}}}
  if(name==='attested-token')profileData={[ATT]:{[parent.id]:{declarationTx:parent.tx.toHex(),transactions:[parent.tx.toHex()],attestations:[await admission(parent)],lifecycles:[await lifecycle(tx,anchor)]}}}
  const receipt=colorReceipt(0,parent.id,amount===0,profileData)
  if(name==='resource')ok(Buffer.byteLength(receipt.insertionRemittance.customInstructions)>1000,'resource fixture exercises exception')
  await record(name,tx,[receipt],anchor,profileData,
    name==='resource'?'Bitcoin processing; no token overlay/lineage/conservation; restricted resource, no unit credit.':
    name==='attested-token'?'Fixture trusts attester; complete token frontier; deferred receipt without publication; color_offline, never lifecycle.':
    'Configured fixture overlays independently establish historical sources and current receipt admission before wallet call.')
}
anchor=funding()
tx=await spend([[anchor,fundingKey]],[{satoshis:900,lockingScript:colorScript('ISSUE',50,bobKey('ISSUE'))}])
await record('issue-receipt',tx,[colorReceipt(0,'ISSUE',false,undefined,`${tx.id('hex')}_0`)],anchor,undefined,'Completed deploy and actual admission; preserve ISSUE derivation, final-ID basket.')
const mixedToken=await deploy(50), mixedResource=await deploy(1,reqResource)
anchor=funding()
tx=await spend([[mixedToken.tx,payerTokenKey],[mixedResource.tx,payerTokenKey],[anchor,fundingKey]],[
  {satoshis:1000,lockingScript:colorScript(mixedToken.id,50,bobKey(mixedToken.id))},
  {satoshis:1000,lockingScript:colorScript(mixedResource.id,9,bobKey(mixedResource.id))},
  {satoshis:700,lockingScript:p2pkh.lock(satoshiKey.toPublicKey().toAddress())}
])
const mixedEvidence={[RESOURCE]:{[mixedResource.id]:{declarationTx:mixedResource.tx.toHex()}}}
await record('mixed-token-resource-satoshis',tx,[colorReceipt(0,mixedToken.id),
  colorReceipt(1,mixedResource.id,false,mixedEvidence),payReceipt(2)],anchor,mixedEvidence,
  'Preflight all three receipts. Bitcoin processing and baseline token overlay admission precede receipt. Resource leg uses its declaration without a token overlay or conserved quantity. Wallet independently validates every leg; 50 token units, restricted resource, and 700 payment satoshis are distinct effects.')
const invalidMixed=cbor.decode(new Uint8Array(bytes(fixtures.at(-1).bodyCborHex)))
invalidMixed.outputs[0]=colorReceipt(0,mixedToken.id,false,mixedEvidence)
fails(()=>validateShape(invalidMixed)) // An adjacent resource cannot enlarge a baseline receipt.
// Exact token and wallet-payment conversion cannot normalize remittance strings.
equal(fixtures[0].request.args.outputs[0].paymentRemittance.senderIdentityKey,identities.alice)
ok(identities.alice!==identities.deliverer,'delivery identity is not derivation identity')
const out={notice:'PUBLIC SYNTHETIC TEST MATERIAL. Never broadcast these transactions. Wallet/overlay acceptance results are fixture expectations, not observed network calls.',
  identities,chainRoots:[...roots].map(([height,root])=>({height,root})),fixtures}
const outputPath=new URL('./transaction-delivery-vectors.json',import.meta.url)
if(process.argv.includes('--write'))writeFileSync(outputPath,JSON.stringify(out,null,2)+'\n')
else {
  const saved=JSON.parse(readFileSync(outputPath,'utf8'))
  for(const sample of saved.fixtures) {
    equal(sha(Buffer.from(sample.mimeHex,'hex')),sample.contentHash)
    equal(EncryptedMessage.decrypt(bytes(sample.brc78CiphertextHex),bob),bytes(sample.mimeHex))
    decode(Buffer.from(sample.mimeHex,'hex'),sample.contentHash)
    ok((await verifier.verifySignature({protocolID:[2,'metanet handles envelope'],keyID:'send',counterparty:identities.deliverer,forSelf:false,
      data:[...Buffer.from(canonicalize(sample.outerMetadata))],signature:bytes(sample.outerSignature)})).valid,'committed signed envelope')
  }
  equal(saved.fixtures.map(f=>f.contentHash),out.fixtures.map(f=>f.contentHash))
  equal(saved.fixtures.map(f=>f.request),out.fixtures.map(f=>f.request))
  equal(saved.fixtures.map(f=>f.response),out.fixtures.map(f=>f.response))
}
console.log(JSON.stringify({fixtures:fixtures.length,checks,output:fileURLToPath(outputPath),syntheticChain:true},null,2))
