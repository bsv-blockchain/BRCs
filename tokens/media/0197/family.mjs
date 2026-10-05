// Frozen Bitcoin Script encoder and off-chain witness builder for BRC-197.
// The normative programs are literal active.hex and activation.hex.
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {createHmac} from 'node:crypto'
import {
  Transaction,TransactionSignature,Script,LockingScript,UnlockingScript,
  Spend,PrivateKey,PublicKey,KeyDeriver,P2PKH,Hash
} from '../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js'
import {hash256,varint,digest,identity,u64,closed} from '../../../overlays/media/0192-0199/protocol.mjs'
export {Transaction,LockingScript,UnlockingScript,PrivateKey,P2PKH,Hash}
const N=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const P=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const R2=0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n
const R3=0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9n
const invoice='2-3241645161d8-brc197 authority'
const manifest=JSON.parse(readFileSync(new URL('./artifact.json',import.meta.url),'utf8'))
export const activeProgram=Buffer.from(readFileSync(new URL('./active.hex',import.meta.url),'utf8').trim(),'hex')
export const activationProgram=Buffer.from(readFileSync(new URL('./activation.hex',import.meta.url),'utf8').trim(),'hex')
assert.equal(activeProgram.length,manifest.programs.active.bytes)
assert.equal(activationProgram.length,manifest.programs.activation.bytes)
const deriver=new KeyDeriver('anyone')
const mod=(v,m)=>((v%m)+m)%m
function inverse(v,m){
  let [a,b,x,y]=[mod(v,m),m,1n,0n]
  while(b){const q=a/b;[a,b]=[b,a-q*b];[x,y]=[y,x-q*y]}
  assert.equal(a,1n)
  return mod(x,m)
}
export const le=(n,size)=>{
  const b=Buffer.alloc(size);let v=BigInt(n)
  assert(v>=0n&&v<(1n<<BigInt(size*8)))
  for(let i=0;i<size;i++){b[i]=Number(v&255n);v>>=8n}
  return b
}
export const pub=k=>k.toPublicKey().toString()
export const pkh=k=>Buffer.from(Hash.hash160(k.toPublicKey().encode(true)))
export const ys=k=>Buffer.from(k.toPublicKey().getY().toArray('be',32))
export const output=(s,script)=>({satoshis:Number(s),lockingScript:script})
export const serializeOutput=o=>Buffer.concat([le(o.satoshis,8),varint(o.lockingScript.toBinary().length),Buffer.from(o.lockingScript.toBinary())])
function point(identityHex){identity(identityHex);return PublicKey.fromString(identityHex)}
export function child(identityHex){
  return deriver.derivePublicKey([2,'3241645161d8'],'brc197 authority',point(identityHex)).toString()
}
function scheduleBytes(schedule){
  closed(schedule,['recipients'])
  const list=schedule.recipients
  assert(list.length>=1&&list.length<=8)
  let last='',sum=0
  const slots=list.map(r=>{
    closed(r,['identity','weight'])
    point(r.identity);assert(r.identity>last);last=r.identity
    assert(Number.isInteger(r.weight)&&r.weight>=1&&r.weight<=10000)
    sum+=r.weight
    return Buffer.concat([Buffer.from(r.identity,'hex'),Buffer.from(child(r.identity),'hex'),le(r.weight,4)])
  })
  assert(sum>=1&&sum<=10000)
  return Buffer.concat([Buffer.from([list.length]),...slots,Buffer.alloc((8-list.length)*70)])
}
export const stateBytes=scheduleBytes
function metadata(descriptor,schedule){
  point(descriptor.seller)
  assert.equal(descriptor.scriptFamily,'https://bsv.brc.dev/tokens/0197#revenue-listing-v1')
  for(const name of ['purchasePrice','reserve'])assert(u64(descriptor[name])>=1n&&u64(descriptor[name])<=2100000000000000n)
  assert(Number.isInteger(descriptor.expiryHeight)&&descriptor.expiryHeight>=1&&descriptor.expiryHeight<500000000)
  assert.equal(descriptor.initialRevenue.recipients.length,schedule.recipients.length)
  assert.deepEqual(schedule,descriptor.initialRevenue)
  const data=Buffer.concat([
    Buffer.from('ROSL'),Buffer.from([1,1]),
    Buffer.from(digest('sale-listing',descriptor),'hex'),
    Buffer.from(descriptor.termsDigest,'hex'),
    le(descriptor.purchasePrice,8),le(descriptor.reserve,8),le(descriptor.expiryHeight,4),
    Buffer.from(descriptor.seller,'hex'),Buffer.from(child(descriptor.seller),'hex'),
    scheduleBytes(schedule)
  ])
  assert.equal(data.length,717)
  return data
}
export function encode(descriptor,schedule=descriptor.initialRevenue,stage='activation'){
  assert(stage==='activation'||stage==='active')
  const raw=Buffer.concat([Buffer.from('4dcd02','hex'),metadata(descriptor,schedule),Buffer.from([0x75]),
    stage==='activation'?activationProgram:activeProgram])
  assert.equal(raw.length,manifest.programs[stage].lockingBytes)
  return LockingScript.fromHex(raw.toString('hex'))
}
export function decode(script,descriptor){
  const raw=Buffer.from(script.toBinary())
  for(const stage of ['activation','active']){
    if(raw.equals(Buffer.from(encode(descriptor,descriptor.initialRevenue,stage).toBinary())))
      return descriptor.initialRevenue
  }
  throw new Error('descriptor, metadata or program mismatch')
}
export function preimage(tx,index){
  const input=tx.inputs[index],previous=input.sourceTransaction.outputs[input.sourceOutputIndex]
  return Buffer.from(TransactionSignature.format({
    sourceTXID:input.sourceTXID??input.sourceTransaction.id('hex'),
    sourceOutputIndex:input.sourceOutputIndex,sourceSatoshis:previous.satoshis,
    transactionVersion:tx.version,
    otherInputs:tx.inputs.filter((_,i)=>i!==index).map(x=>({
      sourceTXID:x.sourceTXID??x.sourceTransaction.id('hex'),sourceOutputIndex:x.sourceOutputIndex,
      sequence:x.sequence,unlockingScript:x.unlockingScript
    })),
    outputs:tx.outputs,inputIndex:index,subscript:Script.fromHex(previous.lockingScript.toHex()),
    inputSequence:input.sequence,lockTime:tx.lockTime,scope:0x41
  }))
}
function scriptNumber(value){
  let n=BigInt(value);assert(n>=0n)
  if(n===0n)return Buffer.alloc(0)
  const bytes=[]
  while(n>0n){bytes.push(Number(n&255n));n>>=8n}
  if(bytes.at(-1)&128)bytes.push(0)
  return Buffer.from(bytes)
}
function push(bytes){
  const n=bytes.length
  if(n===0)return Buffer.from([0])
  if(n===1&&bytes[0]>=1&&bytes[0]<=16)return Buffer.from([0x50+bytes[0]])
  if(n===1&&bytes[0]===129)return Buffer.from([0x4f])
  return Buffer.concat([n<=75?Buffer.from([n]):n<=255?Buffer.from([76,n]):
    n<=65535?Buffer.concat([Buffer.from([77]),le(n,2)]):Buffer.concat([Buffer.from([78]),le(n,4)]),bytes])
}
function big(v){let b=BigInt(v).toString(16);if(b.length%2)b='0'+b;return Buffer.from(b,'hex')}
function derInt(v){let b=big(v);while(b.length>1&&b[0]===0)b=b.subarray(1);if(b[0]&128)b=Buffer.concat([Buffer.from([0]),b]);return b}
function fixedSignature(k,z,d){
  const r=k===2n?R2:R3
  let s=mod(inverse(k,N)*(z+r*d),N)
  assert(s>0n)
  if(s>N/2n)s=N-s
  const rb=derInt(r),sb=derInt(s)
  return Buffer.concat([Buffer.from([0x30,rb.length+sb.length+4,0x02,rb.length]),rb,
    Buffer.from([0x02,sb.length]),sb,Buffer.from([0x41])])
}
function coordinates(key){return [BigInt(key.getX().toString(10)),BigInt(key.getY().toString(10))]}
function linkage(identityHex,z){
  const R=point(identityHex)
  const t=mod(BigInt('0x'+createHmac('sha256',Buffer.from(identityHex,'hex')).update(invoice,'utf8').digest('hex')),N)
  assert(t>0n)
  const Q=point(child(identityHex))
  // t is the public HMAC tweak. This never constructs or exports a wallet child key.
  const D=new PrivateKey(t).toPublicKey()
  const [xr,yr]=coordinates(R),[xq,yq]=coordinates(Q),[xd,yd]=coordinates(D)
  assert(xq!==xr)
  const slope=mod((yq+yr)*inverse(xq-xr,P),P)
  return [Buffer.from(D.encode(true)),t,fixedSignature(2n,z,t),fixedSignature(3n,z,t),
    xr,yr,xq,yq,slope,xd,yd]
}
function asPush(value){return push(Buffer.isBuffer(value)?value:scriptNumber(value))}
export function unlock(tx,index,args){
  assert.equal(index,0)
  const pre=preimage(tx,index)
  const prevouts=Buffer.concat(tx.inputs.map(i=>Buffer.concat([
    Buffer.from(i.sourceTXID??i.sourceTransaction.id('hex'),'hex').reverse(),le(i.sourceOutputIndex,4)])))
  const z=mod(BigInt('0x'+Buffer.from(hash256(pre)).toString('hex')),N)
  const operation=args.operation
  let ids=Array(2).fill(Buffer.alloc(32)),buyerKey=Buffer.alloc(33),buyerX=0n,buyerY=0n
  if(operation===1){
    const rec=Buffer.from(args.receipt.toBinary())
    assert.equal(rec.length,171)
    ids=[rec.subarray(42,74),rec.subarray(74,106)]
    buyerKey=rec.subarray(106,139)
    const buyer=point(buyerKey.toString('hex'))
    ;[buyerX,buyerY]=coordinates(buyer)
  }
  const common=[pre,prevouts,operation,...ids,buyerKey,buyerX,buyerY,
    args.units??args.splitAmount??0,args.changeHash??Buffer.alloc(20),args.changeAmount??0,
    args.adminSignature??Buffer.alloc(0),z,fixedSignature(2n,z,1n),fixedSignature(3n,z,1n)]
  let values=common
  if(operation===0){
    const descriptor=args.descriptor
    assert(descriptor)
    values=[...linkage(descriptor.seller,z)]
    for(const recipient of descriptor.initialRevenue.recipients)
      values.push(...linkage(recipient.identity,z))
    for(let i=descriptor.initialRevenue.recipients.length;i<8;i++)
      values.push(...Array(11).fill(0))
    values.push(...common)
  }
  return UnlockingScript.fromHex(Buffer.concat(values.map(asPush)).toString('hex'))
}
export function evaluate(tx,index){
  const inp=tx.inputs[index],src=inp.sourceTransaction.outputs[inp.sourceOutputIndex]
  const spend=new Spend({
    sourceTXID:inp.sourceTXID??inp.sourceTransaction.id('hex'),
    sourceOutputIndex:inp.sourceOutputIndex,sourceSatoshis:src.satoshis,
    lockingScript:LockingScript.fromHex(src.lockingScript.toHex()),transactionVersion:tx.version,
    otherInputs:tx.inputs.filter((_,i)=>i!==index).map(x=>({...x,sourceTXID:x.sourceTXID??x.sourceTransaction.id('hex')})),
    outputs:tx.outputs,inputIndex:index,unlockingScript:UnlockingScript.fromHex(inp.unlockingScript.toHex()),
    inputSequence:inp.sequence,lockTime:tx.lockTime,memoryLimit:128*1024*1024
  })
  return spend.validate()
}
