// Pins the mainnet evidence for the E2E test token: the deploy, split and merge,
// every transaction they spend, their merkle paths and their block headers.
//
//     node experiment/fetch.mjs        writes experiment/mainnet.json

import { writeFileSync } from 'node:fs'

const WOC = 'https://api.whatsonchain.com/v1/bsv/main'
const ASSET = '2d57a85607ed4233597dafe8ed18cd55762142ad'
const TOKEN = {
  deploy: 'f357dd8299ad2c2fc94aa48f231b6d8b6d0d16da961de6d7f5e6ba111f4a895b',
  split: '42128ed2c4dabef2b8b0d1b76ba7b9e6b06d232f947dc6f26821020e5a738fc5',
  merge: '0f9c13ade73d3708b850a316a69352bc83a7638eb8b8558295336cd2f9a5ed21',
}

const pause = () => new Promise((resolve) => setTimeout(resolve, 400))

async function get(path, as = 'json') {
  for (let attempt = 0; attempt < 4; attempt++) {
    await pause()
    const res = await fetch(WOC + path)
    if (res.ok) return as === 'json' ? res.json() : (await res.text()).trim()
    if (res.status !== 429 && res.status < 500) throw new Error(`${path}: HTTP ${res.status}`)
  }
  throw new Error(`${path}: no answer`)
}

/** Input outpoints of a raw transaction, as display txids. */
function inputs(hex) {
  const raw = Buffer.from(hex, 'hex')
  let at = 4
  const varint = () => {
    const first = raw[at++]
    if (first < 0xfd) return first
    const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8
    const value = Number(raw.readUIntLE(at, Math.min(size, 6)))
    at += size
    return value
  }
  const count = varint()
  const out = []
  for (let i = 0; i < count; i++) {
    out.push(Buffer.from(raw.subarray(at, at + 32)).reverse().toString('hex'))
    at += 36
    const unlock = varint()
    at += unlock + 4
  }
  return out
}

const txs = {}
const parents = {}
const headers = {}
for (const [role, txid] of Object.entries(TOKEN)) {
  const hex = await get(`/tx/${txid}/hex`, 'text')
  const [proof] = await get(`/tx/${txid}/proof/tsc`)
  if (!proof || proof.txOrId !== txid) throw new Error(`${role}: no merkle path`)
  txs[role] = { txid, hex, proof: { index: proof.index, nodes: proof.nodes, block: proof.target } }
  if (!headers[proof.target]) {
    const b = await get(`/block/hash/${proof.target}`)
    headers[proof.target] = {
      height: b.height,
      version: b.version,
      prev: b.previousblockhash,
      merkleroot: b.merkleroot,
      time: b.time,
      bits: b.bits,
      nonce: b.nonce,
    }
  }
  for (const parent of inputs(hex)) {
    parents[parent] ??= await get(`/tx/${parent}/hex`, 'text')
  }
}

const out = new URL('./mainnet.json', import.meta.url)
writeFileSync(out, JSON.stringify({ fetched: new Date().toISOString(), source: WOC, asset: ASSET, txs, parents, headers }, null, 2) + '\n')
console.log(`wrote ${out.pathname}: 3 token transactions, ${Object.keys(parents).length} parents, ${Object.keys(headers).length} headers`)
