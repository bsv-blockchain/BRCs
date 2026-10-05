# BRC-197 Script components and size profile

The normative programs remain the exact bytes in `activation.hex` and `active.hex`. The opcode source is split into literal Bitcoin Script fragments under [`components/`](./components/). [artifact.json](./artifact.json) specifies each fragment's order, word and byte offsets, byte length and SHA-256. Concatenating their opcodes gives the complete `activation.asm` or `active.asm` listing; assembling either form gives the same frozen program. There are no source-language macros, contract compiler, hidden code generation or runtime `eval`. A fragment is a review unit, not a separately spendable Script.

## Ordered assembly

Each program begins with its own exact stack-depth fragment: [stage depth](./components/activation/00-depth.asm) requires 114 stack items (4 bytes) and [active depth](./components/active/00-depth.asm) requires 15 stack items (3 bytes). They then share these three fragments:

| Component | Bytes | Purpose |
| --- | ---: | --- |
| [`00-authenticate-preimage.asm`](./components/shared/00-authenticate-preimage.asm) | 1,229 | Authenticate the caller's `0x41` preimage against the actual transaction using two fixed-nonce generator signatures; reject zero and ambiguous digest scalars. |
| [`01-parse-preimage.asm`](./components/shared/01-parse-preimage.asm) | 191 | Check input-zero prevouts, canonical scriptCode length, input amount, sequence, locktime, hash type and hashOutputs fields. |
| [`02-parse-metadata.asm`](./components/shared/02-parse-metadata.asm) | 199 | Read the executed script's metadata and check marker, profile, positive price/reserve, expiry and recipient count. |

Activation then concatenates [`00-enter.asm`](./components/activation/00-enter.asm), [`10-seller-link.asm`](./components/activation/10-seller-link.asm), eight ordered [`recipient-*.asm`](./components/activation/20-recipient-1.asm) branches, [`90-weight-sum.asm`](./components/activation/90-weight-sum.asm), and [`99-create-active.asm`](./components/activation/99-create-active.asm). Entry requires operation 0 and exactly the reserve value. The seller and each used recipient branch check the root/child curve coordinates, the point-addition slope, public BRC-42 HMAC tweak and two fixed-nonce signatures for `D=tG`. An unused recipient branch requires a zero metadata slot. The final fragment checks the aggregate weight and constructs the exact active output plus optional change. It embeds the frozen 4,906-byte active program; that explains most of its 5,186 bytes.

The active program first checks its exact depth, then concatenates [`10-purchase.asm`](./components/active/10-purchase.asm), [`20-split.asm`](./components/active/20-split.asm), [`30-payout.asm`](./components/active/30-payout.asm), [`40-retire.asm`](./components/active/40-retire.asm) and [`99-finish.asm`](./components/active/99-finish.asm) after the shared prefix. Each route fragment contains its selector and exact output reconstruction. The final fragment rejects every other operation and closes the nested selectors. The route fragments are respectively 592, 461, 1,099, 1,125 and 7 bytes. The complete active program is 4,906 bytes.

```text
activation = stage.depth || shared.authenticate || shared.parse-preimage || shared.parse-metadata
          || stage.enter || stage.seller-link || stage.recipient-link[1..8]
          || stage.weight-sum || stage.create-active

active     = active.depth || shared.authenticate || shared.parse-preimage || shared.parse-metadata
          || route.purchase || route.split || route.payout || route.retire
          || route.finish
```

The fragments implement these route assertions after the common authenticated-preimage checks:

| Fragment | Required authorization and output invariant |
| --- | --- |
| `stage.enter` | Operation is 0 and stage input value equals reserve. |
| `stage.seller-link` | Seller `R` and `Q` are encoded curve points; slope equations bind `D=Q−R`; public HMAC gives `t`; both signatures bind `D=tG`. |
| Each `stage.recipient-link[i]` | When slot `i` is used, apply the same linkage checks and require weight 1–10,000; otherwise require its 70 metadata bytes to be zero. |
| `stage.weight-sum` | Aggregate recipient weight `W` is 1–10,000. |
| `stage.create-active` | Output zero has the identical metadata and reserve with the exact frozen active program; only optional final P2PKH change can follow. |
| `route.purchase` | No seller signature; output zero keeps the active Script and adds exactly price; output one is the buyer/request-bound receipt. |
| `route.split` | Seller-child signature; two active successors each retain reserve and sum exactly to the old listing value. |
| `route.payout` | No seller signature; `q>0`, all recipients receive `q×weight[i]` to `HASH160(Q[i])`, and output zero retains old value minus `qW` above reserve. |
| `route.retire` | Seller-child signature or authenticated expiry locktime and nonfinal input sequence; every recipient receives `ceil(oldValue/W)×weight[i]`, with exact external top-up. |

Each route also hashes the complete reconstructed output vector against the authenticated transaction's `hashOutputs`. The common prefix limits the listing to input zero in a two-to-eight-input transaction with `SIGHASH_ALL|FORKID`; Bitcoin independently enforces value conservation. Descriptor signatures, lineage and prepared-purchase association are [domain checks](../../0197.md#6-lineage-and-domain-checks) outside these components.

The activation proof uses the off-chain witness approach: its builder computes public point coordinates, slopes and fixed-nonce signatures; Script checks those claims and the public HMAC rather than performing scalar multiplication. It verifies the link **once** before the smaller active covenant can receive purchases. The [proof note](./README.md#linkage-proof-boundary) explains why both signatures are needed and which exceptional values are rejected. The exact stack inputs are the [BRC-197 unlocking ABI](../../0197.md#5-unlocking-abi); fragment offsets and hashes are machine checked against that complete program.

Activation executes two transaction binders plus two linkage signature checks for the seller and each used recipient: 6 checks with one recipient, up to 20 with eight. An active purchase or payout executes only the two transaction binders; split and seller-authorized early retirement add one seller-child authorization check. These counts exclude external funding inputs. This is the deliberate one-time verification cost of the public child links.

## Byte requirements

| Item | Bytes | Status |
| --- | ---: | --- |
| Metadata push and drop | 721 | Exact family framing: 4-byte push/drop overhead and 717 metadata bytes. |
| Activation program / complete lock | 33,406 / 34,127 | Exact frozen v1 bytes. |
| Active program / complete lock | 4,906 / 5,627 | Exact frozen v1 bytes. |
| Eight-recipient activation unlocking Script | 38,703 | Observed largest corpus witness; not a universal maximum for every valid encoding. |
| Eight-recipient activation transaction | 44,575 | Observed complete two-input corpus transaction. |
| Ordinary active purchase unlocking Script / transaction | 6,235 / 12,287 | Observed two-input corpus transaction; size varies with signatures and change. |

The [Genesis specification](https://github.com/bitcoin-sv-specs/protocol/blob/master/updates/genesis-spec.md) removes the fixed consensus Script-size ceiling; transaction size, stack memory and node policy still matter. The published [BSV node policy defaults](https://github.com/bitcoin-sv/bitcoin-sv/wiki/Consensus-Limits) are **500 KB per Script** and **10 MB per transaction** for relay/mining, not universal consensus guarantees. These examples are below those defaults, but target miner acceptance, fee rate, execution time and wallet construction require direct qualification. The corpus's small synthetic fees are arithmetic fixtures, not a production fee recommendation.

Run `node tokens/media/0197/verify-assembly.mjs` and `python tokens/media/0197/verify-script.py` as described in the [family guide](./README.md). The SDK and BitcoinX assemblers independently check every fragment, its offsets and hash, the concatenation, the full opcode listing and the frozen hex. Both interpreters then execute the complete transactions and rejection cases.
