import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {gunzipSync} from 'node:zlib'
import {Transaction,LockingScript,UnlockingScript,Spend} from '../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js'

const read = name => readFileSync(new URL(name,import.meta.url))
const graph=JSON.parse(read('lineage-vectors.json'))
const transactions=[Transaction.fromHex(graph.genesis),...graph.funding.map(x=>Transaction.fromHex(x))]
const byId=new Map(transactions.map(tx=>[tx.id('hex'),tx]))
function check(tx,index,source){
  const input=tx.inputs[index]
  const spend=new Spend({sourceTXID:input.sourceTXID,sourceOutputIndex:input.sourceOutputIndex,
    sourceSatoshis:source.satoshis,lockingScript:LockingScript.fromHex(source.lockingScript.toHex()),
    transactionVersion:tx.version,
    otherInputs:tx.inputs.filter((_,j)=>j!==index).map(x=>({...x,sourceTXID:x.sourceTXID})),
    outputs:tx.outputs,inputIndex:index,unlockingScript:UnlockingScript.fromHex(input.unlockingScript.toHex()),
    inputSequence:input.sequence,lockTime:tx.lockTime,memoryLimit:128*1024*1024})
  try{return spend.validate()}catch{return false}
}
for(const record of graph.records){
  const tx=Transaction.fromHex(record.tx)
  let funds=0
  for(let index=0;index<tx.inputs.length;index++){
    const input=tx.inputs[index]
    const parent=byId.get(input.sourceTXID)
    assert(parent,`${record.name} source ${index}`)
    const source=parent.outputs[input.sourceOutputIndex]
    assert(source)
    funds+=source.satoshis
    assert(check(tx,index,source),`${record.name} input ${index}`)
  }
  assert.equal(funds-tx.outputs.reduce((sum,o)=>sum+o.satoshis,0),record.fee)
  byId.set(tx.id('hex'),tx)
  console.log(record.name,'all inputs valid')
}
for(const [name,stage] of [['negative.json.gz',false],['stage_negative.json.gz',true]]){
  const cases=JSON.parse(gunzipSync(read(name)))
  for(const item of cases){
    const tx=Transaction.fromHex(item.transaction??item.tx)
    const locking=LockingScript.fromHex(item.locking)
    tx.inputs[0].unlockingScript=UnlockingScript.fromHex(item.unlocking??item.unlock)
    const source={satoshis:stage?1:item.value,lockingScript:locking}
    assert.equal(check(tx,0,source),item.expected,item.name)
  }
  console.log(name,cases.length,'expected results')
}
const max=JSON.parse(gunzipSync(read('max8-activation.json.gz')))
const maxTx=Transaction.fromHex(max.transaction)
maxTx.inputs[0].unlockingScript=UnlockingScript.fromHex(max.unlocking)
const maxGenesis=Transaction.fromHex(max.genesis),maxFunder=Transaction.fromHex(max.funding)
assert.equal(maxGenesis.outputs[0].lockingScript.toHex(),max.locking)
for(const [index,source] of [maxGenesis.outputs[0],maxFunder.outputs[0]].entries())
  assert(check(maxTx,index,source),`max8 activation input ${index}`)
console.log('eight-recipient activation valid with complete funding input')
const maxActive=JSON.parse(gunzipSync(read('max8-active.json.gz')))
const maxParents=new Map([maxActive.parent,...maxActive.funding]
  .map(raw=>{const tx=Transaction.fromHex(raw);return [tx.id('hex'),tx]}))
for(const name of ['purchase','payout']){
  const tx=Transaction.fromHex(maxActive[name])
  let funds=0
  assert.equal(tx.inputs.length,2)
  for(let index=0;index<2;index++){
    const input=tx.inputs[index]
    const source=maxParents.get(input.sourceTXID)?.outputs[input.sourceOutputIndex]
    assert(source,`${name} source ${index}`)
    funds+=source.satoshis
    assert(check(tx,index,source),`${name} input ${index}`)
  }
  assert(funds>tx.outputs.reduce((sum,out)=>sum+out.satoshis,0))
  if(name==='payout')assert.equal(tx.outputs.length,11)
  maxParents.set(tx.id('hex'),tx)
}
console.log('eight-recipient purchase and payout valid with complete funding inputs')
console.log('SDK family verification passed')
