# BRC-192–199 specification packet and validation

These eight proposals specify separable, opt-in contracts for application output
knowledge and extensible overlay services. Existing finite lookups, BEEF, STEAK,
lookup context and plugin interfaces keep their existing meaning. Selecting a new
profile adds its explicit guarantees; an unavailable required profile fails before
payment or admission. The conceptual discussion remains separately reviewable as
[BRC-186 / PR #277](https://github.com/bsv-blockchain/BRCs/pull/277).

## Reading order

1. [BRC-192](../../../apps/0192.md): evidence, assessments, source/store/projection
   ports, coherent acceptance and common representations.
2. [BRC-193](../../0193.md): bounded snapshots, retained replay, live long polling
   and session/authentication boundaries.
3. [BRC-194](../../0194.md): capability selection, exact profile parameters and
   isolated non-final proposals with a concrete document policy.
4. [BRC-195](../../0195.md): protected publication, paid lookup, exact funding
   identity and durable recovery obligations.
5. [BRC-196](../../0196.md): prepared purchases, STEAK/POTATOES, attributable release
   evidence and explicit local uncertainty.
6. [BRC-197](../../../tokens/0197.md): exact reserve-stage and active Bitcoin Scripts,
   public child-key linkage, permissionless revenue payout and checked lineage.
7. [BRC-198](../../../apps/0198.md): both complete LCH acquisition bindings,
   standing Offers, settlement and authenticated content playback.
8. [BRC-199](../../0199.md): independent root-host advertisement suppression,
   restoration, audit history and current serving fences.

[REVIEW-RESPONSES.md](./REVIEW-RESPONSES.md) maps every numbered review finding to
its specification change and evidence. [registry.json](./registry.json) pins the
normative dependency files at commit
`8f36bdf2eca8298ed1a269054f8c5054156dae95`, their SHA-256 hashes, immutable profile
identifiers, digest domains and test dependencies. Later dependency revisions do
not silently change committed bytes or selected behavior. A compatibility change
requires explicit review and, where semantics change, a new profile version.
Descriptive labels and fixture service rules are not global protocol registrations.

## Decisions and boundaries

The first live transport uses complete bounded authenticated HTTP bodies with
long polling. Clients authenticate a whole response before publishing its data;
progressive ingestion occurs between bounded batches. The core ports remain
transport independent. A future framed transport must define equivalent integrity,
authorization, replay and cancellation guarantees. Received, accepted and projected
revisions are distinct, so durable pending verification cannot expose half of an
atomic spend/successor group.

Private publication, funding and delivery have explicit durable identities and
states. BRC-197 purchase recovery groups independently verified txid variants by the full authenticated purchase preimage digest while retaining exact historical release evidence. A lost wallet or admission reply does not authorize another payment.
An expired catalogue or rotated discovery manifest cannot erase an already
accepted recovery obligation. Local rejection does not prove that a signed
transaction can never be mined elsewhere. Delivery and usable decryption are
separate outcomes; no atomic fair-exchange guarantee is claimed.

BRC-197 registers literal activation and active Bitcoin Scripts. The 34,127-byte
stage lock verifies BRC-42/BRC-29-shaped public root-to-child links once and
creates the 5,627-byte active lock. Purchase, split, permissionless payout and
retirement execute in two interpreters. Payouts retain remainders; expiry permits
anyone to retire with an exact external top-up. No root identity transaction
signature, seller-only payout, merge or amendment path exists. Full signed-genesis
provenance remains a separate domain check. See the [family guide](../../../tokens/media/0197/README.md).

LCH keeps its deterministic CBOR IDs and signed object types. The critical standing
Offer profile binds the buyer in the signed Request, allowing successive buyers
on an unchanged listing lineage. Outer retries preserve the original complete
signed request bytes. Accumulation fulfills the agreed collector duty, with
Script-enforced later distribution; it does not pretend every recipient has
already received or collected a payout.

Root suppression remains a local serving decision, distinct from chain spending
or global erasure. Restoring one decision does not lift another active decision.
Every serving path checks the current fence before enqueueing bytes; historical
replay must reset when it cannot preserve continuity and current disclosure rules.

## Reproduce the frozen corpus

From the repository root, use Node.js 22.13 or later and Python 3.11 or later:

```sh
npm ci --prefix overlays/media/0192-0199 --ignore-scripts
python3 -m venv overlays/media/0192-0199/.venv
overlays/media/0192-0199/.venv/bin/python -m pip install -r overlays/media/0192-0199/requirements-lock.txt
npm test --prefix overlays/media/0192-0199
node tokens/media/0197/verify-assembly.mjs
overlays/media/0192-0199/.venv/bin/python overlays/media/0192-0199/verify-independent.py
overlays/media/0192-0199/.venv/bin/python overlays/media/0192-0199/verify-proposal-query.py
overlays/media/0192-0199/.venv/bin/python overlays/media/0192-0199/verify-traces.py
overlays/media/0192-0199/.venv/bin/python overlays/media/0192-0199/verify-reconciliation.py
overlays/media/0192-0199/.venv/bin/python tokens/media/0197/verify-script.py
```

Node dependencies are locked to @bsv/sdk 2.8.10. Python uses BitcoinX 0.9,
cryptography 46.0.3 and cbor2 5.7.1, with the full resolved versions recorded in
requirements-lock.txt. The test scripts perform no network calls, wallet
transactions, broadcasts or deployments. All private scalars, CEKs, nonces and
funding outputs in the corpus are **public test material**.

The normative family programs are literal Bitcoin Script opcode listings, independently
assembled against frozen hex. Test execution never regenerates expected transactions.
Generators are separate fixture authoring tools: `generate.mjs`,
`generate-reconciliation.mjs`, `generate-proposal-query.mjs`,
`generate-digests.py` and `tokens/media/0197/generate-vectors.py`. Signature
randomness means regeneration may change corpus bytes; review the new bytes and
re-run both independent verifiers before committing them. The published family
program cannot be silently replaced under its existing IRI.

## What the artifacts exercise

[wire-manifest.json](./wire-manifest.json) hashes the lossless compressed
wire-vectors.json.gz archive and records its decoded size, clock, selected chain
and counts. The archive is an aggregate of separate messages; its approximately
18 MiB decoded size is not one permitted network response. Individual messages,
BEEF and CBOR contexts are checked against their own bounds. The corpus contains:

- 24 signed BRC-192 packets, 11 signed LCH object rows and 20 BRC-104 request or
  response transcripts, including handshake material and complete signed bodies.
- Actual BEEF/Atomic BEEF, alternate valid proof bytes, verified spend links,
  private publication, exact BRC-29 funding and admission-linked recovery.
- The shared BRC-192 reconciliation corpus imports the signed BRC-197
  permissionless expiry-retirement transaction and verifies both inputs in the
  SDK and BitcoinX. Two durable traces check that its listing remains unspent
  before maturity and is consumed at the first eligible height under both
  `nonFinal` settings. The height contexts are finality test inputs, not claims
  of a mined retirement or a production chain view.
- Three content acquisitions: two different buyers purchasing successive outputs
  under one standing Offer, and a BRC-105 paid lookup. Each includes authority,
  Header/Asset/Offer/Policy, signed Request, settlement, License/Agreement,
  recipient-bound BRC-78 grants, AES-256-GCM ciphertext and expected plaintext.
- A concrete anchorless proposal and finalization transaction, plus signed
  SHIP/SLAP evidence and two roots with independent suppression/restoration results.

The test chain has an explicitly configured easy proof-of-work target and synthetic
checkpoint, inclusion and competing headers. These demonstrate byte verification,
selected-view inclusion and reassessment, not mainnet inclusion or a consensus
node implementation. The independent BEEF reader intentionally supports the
corpus's BEEF v1/Atomic form and single-leaf proofs; unsupported formats fail rather
than being treated as verified. A production BEEF adapter must implement the full
formats and bounds it advertises.

The local `urn:brc-fixture:catalogue-rules:1` selection contract and fixture chain
policy are installed test rules, not suggested universal application semantics.
Fixture clocks, actor roles and exact selections are recorded alongside the wire
messages. HTTP transcripts verify cryptographic bytes without running an HTTP
server or a browser/proxy. Semantic rejection mutations run after cryptographic
decoding when necessary to isolate one binding rule; they are not misreported as
independently signed negative messages.

[digest-vectors.json](./digest-vectors.json) covers every registered BRC-192 digest
domain using an explicit encoding probe, including UTF-16 key ordering and UTF-8
bytes. It is not a typed protocol message. The independent Python generator freezes
expected preimages/digests, consumed by both implementations. Complete typed signed
examples are in the wire archive. Parser tests additionally cover duplicate escaped
keys, malformed UTF-8, integer spellings, overflow, base64 pad bits, invalid curve
points, nested unknown fields, critical extensions and bounds.

[trace-vectors.json](./trace-vectors.json) supplies 23 ordered state scenarios with
explicit complete public-state expectations. `verify-traces.py` executes each
against a memory adapter and SQLite WAL adapter. Seven SQLite schedules terminate
a child process before or after multi-row commit and reopen the database. They
exercise group acceptance, replay, projection recovery, context fences, session
expiry, proposal finalization, uncertain wallet recovery and root serving fences.
The commands and expected states are portable fixture contracts. Adapter models
are test code; a trace named cache, live or reindex does not certify a deployed
HTTP cache, retained feed or GASP index. Production adapters must be run through
the corresponding actual delivery paths.

[reconciliation-vectors.json](./reconciliation-vectors.json) and
[reconciliation-traces.json](./reconciliation-traces.json) close the BRC-192/193
cross-source acceptance-order contract. The transaction corpus contains 27 frozen
raw transactions, 40 input Script checks, 113 synthetic headers, and actual Atomic
BEEF inclusion proofs. SDK and BitcoinX independently derive input edges, execute
signatures, verify values, parse proof bytes and check selected header ancestry.
The new independent proof reader supports this corpus's one- and two-leaf paths;
it is not a general BEEF reader. Inclusion on the competing branch is rejected.
Fifteen finality cases cover below/equal/above height and time cutoffs, the
500000000 threshold and zero-locktime/all-final exceptions. Eleven vector
comparisons cover exact ordered-input, componentwise replacement eligibility.

Two separately written JavaScript/Python reducers run 32 manually specified
reconciliation scenarios with 52 named state checkpoints. They cover reversed
verification completion, first-ready versus incomplete evidence, same-batch
ancestry ties, cross-host successor-before-parent delivery, current-chain override,
reorg/descendant rollback, non-final replacement and later maturation, finalization,
disabled non-final priority, and source withdrawal/re-entry/generation fences.
The Python runner executes every scenario against both memory and SQLite WAL
journals (64 adapter runs, 104 checkpoints, 42 restart comparisons), plus two
actual subprocess exits before/after the journal-and-projection commit. Frozen
expectations are authored separately from either reducer; test execution never
regenerates expected results. A restart compares the entire saved/rebuilt model
projection, not only the named assertions.

These are bounded executable specification models. Their compact event vocabulary
uses fixture transaction names, safe small integer positions and watched outpoints;
it is not a new network encoding or the full language binding. A verified-event
marker reveals the independently checked result for the frozen bytes; dependency
availability and delayed completion are reconciled separately. The displayed
`current` set means selected outputs with no known selected spend within the
fixture's evidence, never universal proof of unspentness. Models exercise a
conservative component barrier, retained contexts and replacement reservations;
they do not qualify production scheduling, arbitrary dependency graphs, consensus
validation, authorization or provider I/O. Source membership events start after
transport/scope validation, whose separate byte/trace tests remain required.

The family Script corpus has five connected valid transactions and a separate
eight-recipient purchase/payout pair, each with two fully checked inputs, plus
29 active/activation acceptance or rejection vectors.
Both SDK and BitcoinX execute the same immutable bytes. The connected graph
covers stage activation, purchase, split, payout and expiry retirement with exact
fees and a retirement top-up. Rejections include underpayment, payout redirection,
missing child authority and forged public key links. The signed genesis packet,
BEEF lineage and prepared-purchase domain association remain separate checks.

[proposal-query-vectors.json](./proposal-query-vectors.json) adds three frozen
BRC-77 signed proposal heads and four frozen selection digests for the optional
BRC-194 `proposal-channel-heads-v1` query. The JavaScript and independent Python
verifiers check signatures and digests, then execute 16 manually specified query
mapping scenarios and 10 malformed-query rejections, including the 256-channel
boundary. Snapshot ordering, private filtering, unknown predecessor history,
atomic replacement, state-only expiry, retention removal, no-op writes and
visibility resets are explicit. The `head` names in model expectations refer to
the complete signed objects in that file; they are fixture notation, not an
alternative observation wire format. A row's `readable` flag models an already
evaluated host-access decision. These models do not validate a production
policy implementation, durable journal/index/log transaction, history pin,
authenticated transport or current disclosure gate. Those require the real
provider/client qualification described in BRC-194 section 7.

## Conformance claims

A claim must identify its BRC, immutable profile, dependency baseline, selected
policies, limits and relevant evidence. The following levels are distinct:

- **Representation**: exact encodings, field validation, digest/signature domains
  and rejection behavior. This does not imply storage or live service guarantees.
- **Behavioral port**: the relevant source, evidence, knowledge-store or projection
  contract, including ordering, cancellation, replay and observable outcomes.
  Volatile storage may qualify only for that explicitly narrower claim.
- **Durable runtime**: behavioral ports composed with atomic receipts/pending work,
  restart, generation isolation and a recoverable projection. Run the common
  fixtures against the actual store and two independent source adapters.
- **Live provider**: BRC-193 plus its BRC-194 selection, actual snapshot/log storage,
  authenticated transport, current authorization, bounds and restart/expiry races.
- **Acquisition provider**: specifically BRC-195 and/or BRC-196 profiles and selected
  release policies, with protected storage, real wallet/admission reconciliation,
  durable recovery obligations and recipient isolation.
- **Covenant family**: exact activation and active bytes, inverse parsing, ABI and
  all four routes, independently executed transitions and domain evidence checks.
  Purchase alone cannot claim complete BRC-197 support.
- **LCH binding**: explicit usage, payment, settlement, encryption and key-delivery
  mechanisms, authority checks and authenticated decryption for the selected mode.
- **Integrated application**: actual user journeys, wallet permissions, compatible
  persisted data, intended runtime adapters and deployment acceptance evidence.

The supplied corpus establishes the recorded representation/crypto/Script examples
and model-store traces. It is not certification of a durable runtime, live or
acquisition provider, funding wallet, production security review or application.
Passing a narrow corpus does not automatically satisfy every required case in the
normative BRC. Conversely, a narrow independent port need not implement content
playback or every other BRC to make its appropriately limited conformance claim.

## Implementation qualification still required

Reference implementations must exercise BRC-100 createAction/signAction using an
actual supported funding wallet, preserving final input/output order, signatures,
fees and all required positions. Direct fixture-key signatures are not that test.
Multi-party transaction consent needs explicit supported authority; BRC-77 message
signatures cannot replace seller/recipient Bitcoin signatures. Qualify miner
resource/fee policy for the large covenant and bounded lineage packages before
exposing purchases. Independent review remains required for the preimage binder,
economic rules, curve witnesses and every enabled route.

Runtime qualification must use the real storage, browser, wallet and Overlay
Express paths, including both admission storage paths. Test crashes, concurrent
finalization, cancellation, reorganization, authorization changes, response loss,
expired cursors, key availability, backpressure and caches at their actual boundaries.
Protected result capacity and key/replica backups must honor recovery promises.
Show source-to-server-to-client live updates and two roots with independent current
fences through lookup, snapshot, replay, admission and GASP reindex.

Migration guides must explain selection, old/new client/server combinations,
rollback, data/rights preservation and the exact weaker guarantees of any explicit
fallback. Existing exports, constructors, finite routes, token formats, STEAK
validators, persisted records and wallet permissions need compatibility checks.
Application names, deployment choices, domain token schemas and rollout plans
belong in implementation guides, not these neutral protocol contracts.

## Source baseline

The additive boundaries were checked against TS Stack commit
[`4b9ef9764f50ae6379e0c7e06d690dae04d61d82`](https://github.com/bsv-blockchain/ts-stack/tree/4b9ef9764f50ae6379e0c7e06d690dae04d61d82),
including `LookupService.ts`, `TopicManager.ts`, `Engine.ts`,
`TransactionEvidence.ts` and `specs/overlay/persistence-v1.md`. Existing admission
persistence is a foundation, not itself a public retained subscription log.

Private off-chain values and lookup context predate this packet. The historical
[Overlay Services change](https://github.com/bsv-blockchain/overlay-services/commit/29361ad7ed24e474636488e9eb87511b8d97bf8d)
and [SDK companion](https://github.com/bsv-blockchain/ts-sdk/commit/cb86b4f1767cf4878ac8728e8871acb0b9532908)
introduced that pattern. BRC-81 is background rather than a replacement for the
existing interfaces and explicit protected lifecycle defined here.


The spend reconciliation profile pins the Genesis replacement section and BSV
node implementation in [registry.json](./registry.json), including exact source
SHA-256 values. The Genesis prose's greater-or-equal locktime boundary differs
from the node's strict comparison; BRC-192 deliberately selects the latter.
Synthetic fixture branch selection is explicit caller context, not a claim of
mainnet most-work chain tracking. Current projection uses historical replacement
reservations plus today's dependency/finality checks; maturation cannot revive a
replaced version, and a locktime-reversing reorg removes unusable descendants.
