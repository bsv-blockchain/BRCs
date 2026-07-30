# BRC-XXX: Fountain-Coded Air-Gap Transport for Arbitrary Payloads

BSV Association / community contribution

> The BRC number above is a placeholder to be assigned on acceptance.

## Abstract

This standard defines a payload-agnostic, one-directional optical transport that carries an arbitrary byte string across an air gap as a sequence of QR codes. Each QR decodes to a single US-ASCII string beginning with the fixed prefix `air-gap:`, followed by unpadded URL-safe base64 of a binary header and one fixed-size block. Parts are produced by a systematic Luby-transform fountain: the first *K* sequence numbers are the source blocks themselves, and later sequence numbers are deterministic XOR mixtures of those blocks. A receiver may assemble the payload from any sufficient set of distinct parts (in any order, with duplicates tolerated), so a missed camera frame does not force a full animation cycle of waiting. Integrity is checked with the IEEE CRC-32 of the complete payload, carried in every part header and re-verified before bytes are emitted. The scheme is deliberately independent of payment, signing, or wallet semantics: applications supply and interpret the payload. Symbol rendering, camera capture, and animation cadence are out of scope.

## Motivation

Air-gapped and phone-to-phone workflows share a common constraint: there is no bidirectional socket, only a screen on one device and a camera on the other. Realistic payloads (unsigned extended transactions, AtomicBEEF, cosigning envelopes, BRC-100 call blobs) routinely exceed the capacity of a single QR symbol. Prior art on BSV includes:

- **BRC-225 (TKQR1)** — fixed-order indexed frames with a truncated SHA-256 set tag. Simple and fully deterministic, but every missed frame costs a full cycle until that exact index reappears.
- **Application demos** (for example colon-delimited `CHUNK:` string splitters) — workable for small demos, but non-interoperable, non-byte-oriented, and without a strong integrity gate.
- **BC-UR** on other chains — fountain-capable animated QR using bytewords and CBOR; no shared wire format with this BRC.

This BRC standardises the **fountain** approach for general air-gap use: miss-tolerant reassembly, a single wire prefix for every payload size (including the single-part case *K* = 1), tunable block size for different screens and error-correction budgets, and a small binary header that is easy to implement in multiple languages. It is a **peer alternative** to BRC-225, not a revision of it. Implementations MAY support both; they MUST NOT treat the wire formats as interchangeable.

The reference TypeScript package is `@bsv/air-gap` (codec only: no camera, no QR renderer). Applications such as mobile wallets, air-gapped signers, and payment demos own presentation and scanning.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119.

### 1. Terminology

- **Payload**: the arbitrary sequence of bytes to be transported. This BRC imposes no structure on the payload. Authenticity and confidentiality are the responsibility of the enclosed payload.
- **Block**: a fixed-length slice of the payload (zero-padded on the final source block).
- **Part**: one QR-decodable US-ASCII string encoding one fountain part (header plus one block-sized body).
- **K** (*block count*): `ceil(msgLen / blockBytes)`, the number of source blocks.
- **seq**: the part sequence number. Values `0 .. K-1` are systematic; values `≥ K` are coded.
- **blockBytes**: the fixed body size of every part for a given encode. Tunable by the application; not carried as an explicit header field (it is inferred from the decoded body length).

### 2. Wire grammar

A part is:

```
part = PREFIX base64url( header ‖ body )
PREFIX = "air-gap:"   ; literal US-ASCII, case-sensitive
header = seq ‖ K ‖ msgLen ‖ crc32   ; 14 octets, big-endian (see §3)
body   = blockBytes octets          ; see §4–§5
```

Requirements:

- The part MUST be a single line with no surrounding whitespace in the canonical form. A decoder SHOULD strip leading and trailing whitespace before parsing.
- `base64url` is RFC 4648 §5 (URL- and filename-safe alphabet). Encoders MUST omit `=` padding. Decoders MUST accept both padded and unpadded input.
- The part uses characters outside the QR alphanumeric set (`:`, lowercase in the base64 alphabet as encoded, `-`, `_`), so symbols MUST be rendered in **QR byte mode**.
- A decoder MUST reject (soft-fail: no state change for a well-formed session) any string that does not begin with the literal prefix `air-gap:`.

### 3. Binary header

All multi-byte integers are **big-endian**.

| Offset | Type | Field | Description |
|--------|------|-------|-------------|
| 0 | `uint32` | `seq` | Part sequence number |
| 4 | `uint16` | `K` | Source block count |
| 6 | `uint32` | `msgLen` | Payload length in octets |
| 10 | `uint32` | `crc32` | IEEE CRC-32 of the full payload (§6) |
| 14 | … | `body` | Exactly `blockBytes` octets |

Header length is always 14 octets. `blockBytes` is not stored in the header: it equals `len(decoded_bytes) - 14` and MUST be identical for every part of one session.

### 4. Chunking and source blocks

Input: `payload` (bytes), `blockBytes` (integer).

1. `blockBytes` MUST be ≥ 1.
2. If `len(payload) = 0`, the encoder MUST fail (empty payloads are not representable). Applications that need a typed empty record MUST wrap it in a non-empty envelope.
3. If `len(payload) > maxMessageBytes`, the encoder MUST fail. Conforming implementations MUST enforce `maxMessageBytes = 65536` unless a profile document specifies a lower bound; implementations MUST NOT raise the bound above 65536 without a new BRC revision.
4. `K = ceil(len(payload) / blockBytes)`. When `blockBytes ≥ len(payload)`, `K = 1` and a single systematic part carries the entire payload (zero-padded to `blockBytes`).
5. Source block *i* for `i` in `0 .. K-1` is a `blockBytes`-octet buffer: copy `payload[i·blockBytes : min((i+1)·blockBytes, len)]` into the start of the buffer; remaining octets are `0x00`.

Default `blockBytes` SHOULD be **1200** unless the application has measured reasons to differ (smaller screens, higher ECC, logo overlays). Applications MAY expose `blockBytes` as a tunable. Smaller blocks yield more parts but lower per-symbol density; larger blocks reduce part count but push QR capacity.

### 5. Fountain part construction

Part body for sequence number `seq`:

- If `seq < K`: body is source block `seq` (as constructed in §4).
- If `seq ≥ K`: body is the XOR of source blocks whose indices are `blocksForPart(seq, K)` (§5.1).

The complete part bytes are `header ‖ body` with `seq`, `K`, `msgLen`, and `crc32` set as in §3, then base64url-encoded and prefixed with `air-gap:`.

`seq` MAY grow without bound. Encoders used for animation typically emit `seq = 0, 1, 2, …` in a loop. Receivers need any sufficient set of distinct parts (the systematic set `0 .. K-1` alone is enough if none are missed).

#### 5.1. `blocksForPart(seq, K)` (normative)

Used only when `seq ≥ K`. Pseudo-code:

```
makeRng(seed):
  x ← seed as uint32
  if x = 0: x ← 0x6d2b79f5
  return function:
    x ← x XOR (x << 13); x as uint32
    x ← x XOR (x >> 17); x as uint32
    x ← x XOR (x << 5);  x as uint32
    return x

blocksForPart(seq, K):
  rng ← makeRng( (seq * 0x9e3779b1) as uint32 )
  open01 ← () → ((rng() >> 9) + 1) / 2^23     // in (0, 1]
  half01 ← () → (rng() >> 9) / 2^23            // in [0, 1)
  if K = 1:
    degree ← 1
  else if open01() ≤ 1/K:
    degree ← 1
  else:
    degree ← min(K, ceil(1 / open01()))
  pool ← [0, 1, …, K-1]
  for i in 0 .. degree-1:
    j ← i + floor(half01() * (K - i))
    swap pool[i], pool[j]
  return pool[0 .. degree-1]
```

All arithmetic on `x` and `seq * 0x9e3779b1` is modulo 2³² (uint32 wrap). Multiplications and shifts match common two's-complement uint32 behaviour in C, Java, Kotlin, and JavaScript (`>>> 0`).

### 6. CRC-32

`crc32` is the IEEE CRC-32 (ISO 3309 / ITU-T V.42 / Ethernet polynomial `0xEDB88320` reflected), as produced by the standard table algorithm with initial value `0xFFFFFFFF` and final XOR `0xFFFFFFFF`. The well-known check value is:

```
CRC32(ASCII "123456789") = 0xCBF43926
```

The field covers the **entire payload** (all `msgLen` bytes), not individual blocks.

### 7. Reassembly (decode)

A receiver maintains session state. The reference models this as a stateful decoder.

**Per-part ingest (`accept`):**

1. If the string is not a well-formed `air-gap:` part (wrong prefix, invalid base64url, length ≤ 14), return soft failure and leave state unchanged. A decoder used with a live camera MUST NOT throw on stray scans.
2. Parse header fields and body. Let `blockBytes = len(body)`.
3. Reject if `K = 0`, `msgLen = 0`, or `msgLen > maxMessageBytes`.
4. Reject if `ceil(msgLen / blockBytes) ≠ K` (header and body disagree on message shape).
5. Session key is the triple `(K, msgLen, crc32)`. If the key differs from the current session, **reset** and begin a new session with that key (a new stream wins).
6. On the first accepted part of a session, pin `blockBytes`. Later parts whose body length differs MUST be rejected (soft-fail) without changing solved state.
7. If `seq` was already seen in this session, ignore the duplicate.
8. Determine block indices: if `seq < K`, indices = `{seq}`; else indices = `blocksForPart(seq, K)`.
9. Ingest via peeling: XOR out already-solved blocks from the body; if one index remains, solve that block; cascade until fixpoint.

**Completeness:** the session is complete when all *K* source blocks are solved.

**Finalize (`message`):**

1. If incomplete, return no payload.
2. Concatenate solved blocks `0 .. K-1` and trim to `msgLen`.
3. Recompute CRC-32 over the trimmed bytes and require equality with the session `crc32`. On mismatch, reset the session and return no payload (the sender is expected to still be looping).
4. Return the trimmed bytes.

A conforming decoder MUST NOT emit a truncated or blended payload.

### 8. Mixed-stream and fail rules (normative summary)

| Condition | Behaviour |
|-----------|-----------|
| Not `air-gap:` / bad base64 / short | Soft-reject; no state change |
| `K`, `msgLen` out of range | Soft-reject |
| `ceil(msgLen/blockBytes) ≠ K` | Soft-reject |
| Different `(K, msgLen, crc32)` | Reset; start new session |
| Body length ≠ pinned `blockBytes` | Soft-reject |
| Duplicate `seq` | Ignore |
| Finalize with incomplete set | No emit |
| Final CRC mismatch | Reset; no emit |

### 9. Presentation guidance (non-normative)

- Animation cadence is **not** part of this BRC. Applications commonly use ~200 ms per part (~5/s) on phone cameras; slower is more reliable under motion blur.
- For *K* = 1, applications MAY show a single static QR (never advance `seq`).
- Centre logos and colour styling consume error-correction budget; prefer ECC level M or higher and reduce `blockBytes` if overlays are used.
- A version-40 QR at ECC M holds about 2331 bytes; with base64 expansion, keep the full part string comfortably under ~2200 characters for phone-sized symbols. Default `blockBytes = 1200` yields roughly 1628 characters of part text.

### 10. Interoperability contract

Two implementations are interoperable if and only if, for the same `(payload, blockBytes)`, they produce identical part strings for every `seq`, and each can reassemble the other's stream to the exact original payload. Determinism is total: there is no randomness, timestamp, or locale dependence. Shared test vectors are the conformance oracle.

## Test Vectors

### Vector A — CRC-32 check value

- Input: ASCII `123456789`
- Output: `crc32 = 0xCBF43926`

### Vector B — Single-part (*K* = 1)

- Payload: ASCII `Hello, air-gap!` (15 bytes)
- `blockBytes = 64`
- `K = 1`, `msgLen = 15`, `crc32 = 0x8614FD1F`
- Systematic part `seq = 0` (body is 15 payload bytes then 49 zero bytes):

```
air-gap:AAAAAAABAAAAD4YU_R9IZWxsbywgYWlyLWdhcCEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Reassembly: accept that single part → payload 15 bytes; CRC matches.

### Vector C — Two systematic parts

- Payload: ASCII `Hello, air-gap!` (15 bytes)
- `blockBytes = 8`
- `K = 2`, `msgLen = 15`, `crc32 = 0x8614FD1F`
- Source blocks: `Hello, a` and `ir-gap!\0`

```
air-gap:AAAAAAACAAAAD4YU_R9IZWxsbywgYQ
air-gap:AAAAAQACAAAAD4YU_R9pci1nYXAhAA
```

Reassembly in either order, with optional duplicates, yields the original 15 bytes. Presenting only one part MUST NOT emit a payload.

### Vector D — Behavioural (implementation tests)

Conforming decoders MUST:

1. Soft-reject strings that are not `air-gap:` parts.
2. Complete from the systematic set alone when no frames are missed.
3. Complete when some systematic parts are missing but enough coded parts (`seq ≥ K`) arrive to peel the remainder.
4. Reset when a part arrives whose `(K, msgLen, crc32)` differs from the current session.
5. Soft-reject a part whose body length differs from the first accepted part of the session.
6. On final CRC mismatch (for example after a body bit-flip with header left intact), discard the assembly and continue accepting.

## Implementations

- **Reference (TypeScript):** `@bsv/air-gap` — pure codec (`AirGapEncoder` / `AirGapDecoder`), no camera or QR dependencies. Intended for browsers, React Native, and Node.
- Operational precursor: the Luby-transform fountain previously embedded in BSV mobile wallet code for oversized nearby-payment frames (payment-specific prefixes; not part of this wire format).

## Mathematical basis

**Systematic fountain.** The first *K* parts are an exact partition of the (padded) payload. Coded parts are linear combinations over GF(2) of whole blocks. The peel decoder solves degree-1 equations and substitutes, which recovers the source whenever the collected set spans the message — in practice after roughly *K* distinct parts for this degree distribution when losses are moderate.

**CRC-32** detects accidental corruption and distinguishes unrelated streams with low cost on constrained devices. It is not an authenticator: an adversary who can inject frames can forge a consistent CRC. Payload authenticity MUST be provided by the application layer (signatures, MACs, or verified transaction structure).

## Security Considerations

- **No authenticity.** CRC-32 does not authenticate the sender. Sign or encrypt at the payload layer when required.
- **No confidentiality.** Parts are plaintext on a screen. Sensitive material MUST be encrypted before framing.
- **Fail closed.** Decoders MUST NOT return partial payloads. Mixed streams reset or soft-reject; CRC failure discards the assembly.
- **Resource bounds.** Enforce `maxMessageBytes` and reasonable `K` to avoid memory exhaustion from hostile headers.
- **No freshness.** Duplicate-tolerant reassembly implies anti-replay lives in the payload (nonces, request IDs, expiry).
- **Optical threat model.** Shoulder-surfing and nearby cameras can capture the stream; treat the channel as public.

## Relationship to other standards

| Standard | Relationship |
|----------|----------------|
| BRC-225 TKQR1 | Peer alternative (indexed frames). No shared wire format. |
| BRC-100 | Online wallet interface; this BRC is the optical path when that channel is unavailable. |
| BRC-62 BEEF | Example payload this transport can carry. |
| BC-UR (Blockchain Commons) | Prior art on another chain; no shared format. |

## References

- BRC-225, Animated-QR Air-Gap Transport for Arbitrary Payloads (TKQR1).
- BRC-100, Wallet-to-Application Interface.
- BRC-62, Background Evaluation Extended Format (BEEF).
- RFC 4648, Base16/32/64 encodings (§5 URL-safe base64).
- ISO/IEC 18004, QR Code symbology (byte mode; Reed-Solomon levels).
- RFC 2119, Key words for use in RFCs.
- Luby, M. "LT Codes." *Proceedings of the 43rd Symposium on Foundations of Computer Science*, 2002 (fountain degree distribution inspiration; this BRC specifies an ideal-soliton-style draw, not a full LT standard).
- Blockchain Commons, UR: Uniform Resources (BCR-2020-005), cited as prior art only.
- IEEE CRC-32 / ISO 3309.
