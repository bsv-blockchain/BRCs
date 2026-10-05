import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { Script } from '../../../overlays/media/0192-0199/node_modules/@bsv/sdk/dist/esm/mod.js'

const root = new URL('./', import.meta.url)
const manifest = JSON.parse(readFileSync(new URL('artifact.json', root), 'utf8'))
function scriptNumber(value) {
  let n = BigInt(value)
  if (n === 0n) return 'OP_0'
  const negative = n < 0n
  if (negative) n = -n
  const bytes = []
  while (n > 0n) { bytes.push(Number(n & 255n)); n >>= 8n }
  if (bytes.at(-1) & 128) bytes.push(negative ? 128 : 0)
  else if (negative) bytes[bytes.length - 1] |= 128
  return Buffer.from(bytes).toString('hex')
}
function binaryFromSource(source) {
  const words = source.split(/\s+/).filter(Boolean)
  const normalized = words.map(word => word.startsWith('x:') ? minimalPush(word.slice(2))
    : /^-?\d+$/.test(word) ? scriptNumber(word) : word)
  return Buffer.from(Script.fromASM(normalized.join(' ')).toBinary())
}
function assemble(name) {
  const source = readFileSync(new URL(`${name}.asm`, root), 'utf8')
  const artifact = manifest.programs[name]
  assert.equal(createHash('sha256').update(source).digest('hex'), artifact.assemblyFileSHA256)
  const words = source.split(/\s+/).filter(Boolean)
  const binary = binaryFromSource(source)
  const parts = [], partWords = []
  let byteStart = 0, wordStart = 0
  for (const component of artifact.components) {
    assert(component.path.startsWith('components/') && !component.path.includes('..'))
    const partSource = readFileSync(new URL(component.path, root), 'utf8')
    const currentWords = partSource.split(/\s+/).filter(Boolean)
    const bytes = binaryFromSource(partSource)
    assert.equal(component.wordStart, wordStart, `${name}: ${component.path} word start`)
    assert.equal(component.wordCount, currentWords.length, `${name}: ${component.path} word count`)
    assert.equal(component.byteStart, byteStart, `${name}: ${component.path} byte start`)
    assert.equal(component.bytes, bytes.length, `${name}: ${component.path} byte length`)
    assert.equal(createHash('sha256').update(bytes).digest('hex'), component.sha256,
      `${name}: ${component.path} SHA-256`)
    partWords.push(...currentWords)
    parts.push(bytes)
    wordStart += currentWords.length
    byteStart += bytes.length
  }
  assert.deepEqual(partWords, words, `${name}: component opcode composition`)
  assert(Buffer.concat(parts).equals(binary), `${name}: component byte composition`)
  const expected = readFileSync(new URL(`${name}.hex`, root), 'utf8').trim()
  const actual = binary.toString('hex')
  if (actual !== expected) {
    let at = 0
    while (at < actual.length && at < expected.length && actual[at] === expected[at]) at++
    throw new Error(`${name}: independent SDK assembly differs at hex character ${at}: ${actual.slice(at, at + 40)} versus ${expected.slice(at, at + 40)}`)
  }
  const sha256 = createHash('sha256').update(binary).digest('hex')
  assert.equal(binary.length, artifact.bytes)
  assert.equal(sha256, artifact.programSHA256)
  assert.equal(binary.length + manifest.metadataBytes + 4, artifact.lockingBytes)
  return { bytes: binary.length, sha256 }
}
function minimalPush(hex) {
  if (hex === '') return 'OP_0'
  if (hex === '81') return 'OP_1NEGATE'
  if (/^(0[1-9a-f]|10)$/.test(hex)) return `OP_${parseInt(hex, 16)}`
  return hex
}
for (const name of ['active', 'activation']) console.log(name, assemble(name))
