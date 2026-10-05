# Response to the BRC-192–199 specification review

This record addresses the [review of commit 58fa88d](https://github.com/bsv-blockchain/BRCs/pull/284#issuecomment-5877088711).
It records specification changes and their evidence, not a claim of a deployed
implementation or a substitute for upstream review. The former 68 arithmetic/state
illustrations have been replaced with frozen cryptographic/transaction artifacts,
two Script interpreters and reusable memory/SQLite traces. Commands, dependency
pins and the precise conformance taxonomy are in the [packet guide](./README.md).

The specifications now make the decisions described below. The corpus demonstrates
named cases; real wallet, server, browser, production-store and application
qualification remains a separately identified implementation requirement. In
particular, signed HTTP transcripts are not a running service, SQLite fixture
models are not production adapters, and direct fixture-key funding is not a
BRC-100 wallet integration. Those boundaries must remain visible in review.

## BRC-192

**192.1 — Complete structural ports.** [Sections 8–9](../../../apps/0192.md#8-structural-port-contract)
define VerificationContext, scoped outcomes, coverage, assessments, revisions,
mutations, group identity and stable keys. Variant bytes, immutable transaction
facts and context-dependent assessments have distinct IDs. Source-reported
unspentness retains provider/scope/expiry. The trace corpus compares complete
observable results across memory and SQLite adapters; production port substitution
must additionally exercise actual independent source/verifier implementations.

**192.2 — Trusted provenance.** Observation scope must match the authenticated
source/session and locally assigned partition/generation. Remote invalidation is
limited to that source's assessments and cannot replace a local chain context.
Spend evidence must consume the named outpoint. The wire verifier checks a real
spend and rejects a foreign nested scope and unrelated asserted predecessor;
context-change traces fence queued work without erasing immutable history.

**192.3 — Coherent acceptance.** SourceBatch preserves Group boundaries. Receiving
an entire group and pending work may advance received revision; accepted revision
advances only when the whole group passes. Unresolved, invalid, limited and cancelled
members cannot publish a partial transition. Projection is a separately recoverable
stage. Traces cover delayed/invalid successors, restart, stale context and
knowledge-commit/projection separation.

**192.4 — Exact representation.** Recursive closed objects, duplicate decoded
keys, UTF-8, JCS number spellings, canonical base64 pad bits, curve membership,
limits and critical extensions are explicit. Changed BEEF bytes require a new
observation identity while remaining eligible as an evidence variant. Node parser
rejections cover these boundaries; every registered digest domain has independently
authored Python preimages consumed by both implementations. Complete signed JSON
and deterministic CBOR examples also have independent verification.

**192.5 — Replaceability and retention.** Deterministic projector input order,
received/accepted/projected revisions, getMutation reconciliation, replay before
CAS, key collision, generation changes, cancellation publication gates, revision
exhaustion, retention and expiry-driven reassessment are specified. Memory/SQLite
traces include actual process loss around commits. Runtime qualification still
must exercise account switching, watches and jobs in its actual client/store.

## BRC-193

**193.1 — Complete session lifecycle.** [Section 8](../../0193.md#8-session-state-clock-and-transport-contract)
fixes open replay, anonymous request-ID capability, retained fences, close/read
races and exact exclusive deadlines. Retry never silently takes a new snapshot.
Signed open/read/close transcripts and clock-driven lost-open/expiry/closed-poll
traces exercise the selected contract.

**193.2 — Verifiable batch structure.** Groups carry sequence, stable identities
and scope-consistent observations. Snapshot/live identity namespaces, replay under
changed limits and atomicity boundaries are defined. Sparse sequence numbers are
provider completeness assertions, not cryptographic proof of absence. The corpus
contains actual bounded snapshot/live messages, an empty snapshot and a coherent
spend/successor group; the verifier rejects mismatched nested scope.

**193.3 — Time and current disclosure.** The snapshot fixes its evaluation instant
and watermark; timer transitions enter the retained log. Current authorization or
serving suppression overrides historical disclosure and causes reset where needed.
Check again at the send-queue boundary. Traces cover authorization/fence changes;
real providers must also run timer and serialization races through their storage
and transport adapters.

**193.4 — Bounds and progress.** Complete encoded JSON body accounting, identity
Content-Encoding, independent header/BEEF/work bounds, minimum error envelope,
selected versus permanent group limits and fixed session/replay deadlines are
specified. A group beyond the hard maximum cannot be repaired by an impossible
limit increase. Recovery choices and provider capability obligations are explicit.
Byte-size checks operate on the actual fixture messages and contexts.

**193.5 — Authentication and durability.** The client store, not a read-only server
cursor, enforces commit before checkpoint advancement. No application publication
precedes complete BRC-104 verification. Response no-store handling, browser header
exposure, proxy long-poll behavior and queue linearization are required. Twenty
real request/response transcripts verify independently, with body-corruption
rejections; actual browser/proxy and server crash qualification is still required.

## BRC-194

**194.1 — Selectable registry.** [Section 6](../../0194.md#6-selection-registry-and-complete-proposal-lifecycle)
fixes service-kind/profile combinations, structured release policy variants,
recovery-duration relationships and digest preimages for installed rules/policy
schemas. Exact versioned identifiers and dependency bytes are registered. The
complete signed capability fixture advertises concrete parameters and explicit
LCH mechanisms rather than an ambiguous release-policy label.

**194.2 — Endpoint and recovery contracts.** Canonical bases specify DNS/IDNA,
IPv6, ports, percent escapes and prefix-preserving suffix joining. Discovery uses
an authenticated bootstrap, selection failures cannot invoke payment/fallback,
and recovery resolves the retained old selection before freshness rejection.
Old-manifest and late-delivery traces preserve the accepted contract. Identity or
endpoint rotation must retain a compatible recovery path.

**194.3 — Proposal lifecycle events.** BRC-192 adds proposal-state and
proposal-remove observations keyed by proposal/channel identity. Providers can
report finalized, expired and visibility-removed states without forging an author
signature or inventing an outpoint. The corpus includes an anchorless signed
document, its actual finalization transaction and corresponding state event.

**194.4 — Finalization operations.** A separate operationId, retained
finalization-pending/failed states, exact txid reservation and admission intent
serialize finalization against update, withdrawal and expiry. Lost admission
results reconcile before another operation; empty duplicate STEAK is not evidence
of failure. Finalized is historical after reorganization. Traces include a crash
after admission before linking and rejection of competing channel operations.

**194.5 — Terminal identities and policy.** Permanent minimal terminal fences
prevent resurrection after payload expiry; current authorization gates reads.
The installed author-document-v1 policy fixes author/recipient permissions,
canonical payload, optional anchor, finalization output and terminal behavior.
This concrete off-chain example does not claim support for arbitrary partially
signed transactions. Production authorization and terminal-retention tests remain
required for an implementing service.

## BRC-195

**195.1 — Exact funding and reconciliation.** [Section 7](../../0195.md#7-complete-publication-and-acquisition-contract)
selects one exact BRC-29 lock/amount, rejects duplicate matching locks, identifies
funding by chain/txid/outputIndex and adapts BRC-105 replay only for its original
acquisition. A durable uniqueness ledger and wallet-funding operation precede
wallet effects. internalizeOnce/getInternalization must prove reconciliation;
a mutex or ordinary internalizeAction alone is insufficient. The corpus contains
actual derived funding, alternate proof bytes and lost-wallet-reply traces.

**195.2 — Complete recovery states.** Quoted, funding-pending, funded,
delivery-pending, delivered and retained terminal outcomes are distinct. Publication
has pending, ready, rejected, expired and failed outcomes. Result/decision/funding
field presence is explicit. Missing payment is distinguishable from uncertain
internalization or failed fulfillment; the exact accepted transaction remains
recoverable without a second purchase.

**195.3 — Frozen acceptance and deadlines.** Challenge freezes acceptance policy,
rules selection and payable/recovery deadlines before payment. Exact late-first
candidate pinning takes precedence over later catalogue/Offer expiry, and accepted
unfinished delivery retains its obligation beyond the request deadline. Clock
traces test the last accepted instant, exact expiry, old manifest and interrupted
fulfillment. Processor and mined release fixtures provide actual evidence bytes.

**195.4 — Protected publication and capacity.** Publication equivalence excludes
only evidence.beef; asset/output/schema/private bytes stay committed. Equal bindings
share protected material, conflicting replacements fail, and failed admission or
readiness loss has an explicit retained state. Quotes reserve result capacity and
material; payment headers have separate bounds. Cache/log handling, replicas,
key backups and deletion obligations are required. Deployment-specific storage and
backup qualification is not claimed by this offline corpus.

## BRC-196

**196.1 — Local outcomes and global uncertainty.** [Section 5](../../0196.md#5-reservation-release-and-recovery-details)
retains the selected txid, purchase commitment, reason/evidence, policy and globalOutcome=unknown after local failure.
A timeout, missing result or local conflict does not authorize automatic repayment
or prove global impossibility. Replacement risk requires explicit buyer authority.
The protocol separates recovery of an equivalent verified purchase candidate from a new preparation;
chain-currentness changes do not erase historical delivery.

**196.2 — Ordered lifecycle and bindings.** Preparation, validation, candidate
reservation, admission intent, topical result and private delivery are one explicit
state machine. It binds every chain/seller/recipient/topic/listing/asset/request/
terms/domain field before reservation. Invalid-before-reservation candidates do
not bind a purchase commitment; pinned uncertain work does. Private fulfillment reservation is
not exclusive UTXO reservation. The registered listing-purchase-v1 domain selects
the concrete revenue-listing-v1 family and portable lineage package.

**196.3 — Verifiable release evidence.** Required/forbidden fields and acceptedAt
are defined for each policy. Mined mode needs a selected header/chain-tracker view,
ancestry/work checks and bounded unresolved handling. Processor-attestation-v1
has exact signed bytes and signer/transaction/policy bindings. The corpus verifies
real processor signatures, BEEF, synthetic inclusion headers and a competing tip;
it makes no mainnet or processor-service claim.

**196.4 — Delivery versus usability.** A delivered result may still be unusable to
the buyer. Recovery preserves exact entitlement/settlement and original release
evidence while allowing only defined signature/encryption reissue variation.
Later reorganization is a currentness reassessment, not a demand to re-purchase or
re-satisfy historical release before recovering an issued capability. Independent
playback checks verify grants, commitments and authenticated plaintext; failures
do not imply an automatic refund or fair-exchange mechanism.

**196.5 — Transaction ID malleability and recovery.** A valid external input
unlocking Script can change a purchase txid without changing its outputs or the
authenticated listing-input preimage. BRC-196 now reserves the full 32-byte
purchase commitment and retains independently verified txid aliases, while
keeping signed release evidence tied to its actual historical transaction. A
mined alias can be admitted and selected before mined-policy release. A later
mined alias under a weaker prior release changes currentness without reissuing
rights or rewriting the signed License. Unconfirmed alias caps cannot strand a
verified selected-chain variant.

## BRC-197

**197.1 — Concrete family.** [Sections 1–5](../../../tokens/0197.md#1-descriptor-derivation-and-genesis)
register two literal Bitcoin Script programs, metadata/inverse encoding, the
activation proof and fifteen-argument active ABI. Independent assemblers reproduce
the frozen bytes. Both interpreters execute five connected complete transactions,
an eight-recipient purchase/payout pair and 37 active/activation rejection cases. The family
remains subject to independent security
review and production wallet/miner qualification.

**197.2 — Wallet boundary.** Receipts carry **one satoshi**. Two-phase
createAction/signAction fixes input/output positions and requires exact final
revalidation. The seller's transaction authority and recipient payout locks use
one publicly derived child per identity; root identity scalars never sign raw
transactions or receive payments. Public fixtures use separate funding scalars.
Protected BRC-100 signer/consumer separation and fixed-child remittance remain
explicit integration qualification. Exporting any such child scalar reveals its
root and is prohibited.

**197.3 — Script versus domain.** Activation Script verifies public BKDS child
links once, and active Script checks actual prevouts, amounts, exact outputs and
receipts, purchase recipient curve point, child signatures where needed and route
exclusivity. Genesis/asset authority, full ancestry, currentness and prepared
request association remain domain checks. A purchase for another valid recipient
is Script-valid but wrong for the original acquisition. Negative transactions use
fresh preimages and signatures to exercise the economic and linkage predicates.

**197.4 — Portable lineage.** [Section 6](../../../tokens/0197.md#6-lineage-and-domain-checks)
requires a bounded package carrying the descriptor, signed reserve-stage genesis,
activation and every predecessor on the target's branch. Partial BEEFs resolve as
one deduplicated graph before validation. A copied active Script or direct active
output is not an authorized listing. The common packet exercises signed genesis,
activation and successive purchases; the family graph adds split, payout and
retirement. Missing ancestry remains unresolved rather than accepted by a matching
Script prefix.

**197.5 — Complete revenue consequences.** Every active listing supports
permissionless payout; no payout-less administration mode exists. Split conserves
constrained value and requires the protected seller child. Payout distributes exact
quanta to verified children without seller cooperation. Early retirement requires
that child; after the committed height anyone can retire with an externally funded
exact top-up. Merge and amendment are invalid in v1; a changed schedule needs a
new signed lineage. Balance or ancestry exhaustion stops new offers without
deleting historical rights. Every enabled route has two-interpreter execution.

**197.6 — Exact stack and unused fields.** Both programs require their exact
entry depth. Purchase rejects nonzero `units` and `adminSignature`; routes that
do not use buyer fields require canonical zero or empty values; unused activation
proof slots are empty. Eight new rejection cases exercise these guards. Positive three-txid vectors change the external funding unlock or add a
stack-neutral listing-input opcode pair and prove why exact transaction identity
cannot be inferred from this Script. Full commitment,
transaction and lineage verification remain mandatory for any alias.

## BRC-198

**198.1 — Standing Offer.** [Section 5](../../../apps/0198.md#5-standing-offers-retry-identity-and-verification-closure)
defines critical S for C only: buyer is forbidden in the standing requirement,
and the signed buyer Request supplies late binding. Ordinary BRC-170 Offers are
unchanged. Two different authenticated buyers purchase successive outputs under
one unchanged Offer/listing, with independently verified licenses and playback.

**198.2 — Byte-stable retry.** Persist and resend the exact complete original
signed Request, including signature order. Re-signing preserves the inner LCH ID
but changes the outer digest and conflicts; it never authorizes another charge.
The corpus contains two independently valid signatures demonstrating that exact
boundary. Recovery by acquisition ID remains available.

**198.3 — Endpoints and recovery.** All operational endpoints are absolute URLs
formed by appending the defined suffix to the canonical selected base, retaining
its path prefix. Service kind/name matches lookup or topic as selected. Challenge,
Terms and settlement honor the maximum inherited/advertised/Offer recovery period.
Later Offer withdrawal/expiry cannot revoke the frozen existing obligation.

**198.4 — Verification closure.** Typed evidence has permitted signing domains,
canonical order, uniqueness and authority/work limits. PurchaseEvidence carries
the complete lineage, purchase, signed preparation and release package. Individual
role/ID/amount/policy equalities and pre-payment E/C/S/family advertisement are
explicit. Actual LCH authority and packet signatures are independently verified;
semantic mutations isolate wrong role, service, endpoint, subject and policy.

**198.5 — Exact compensation.** Both bindings support exactly one compensation
duty and no additional unmet prerequisite duties. P defines paid-lookup settlement
and fulfillment explicitly; C represents collection, with the Script-enforced
revenue terms in section 6, rather than immediate separate beneficiary payments.
Extra duty, wrong collector, wrong profile and incorrect amount substitutions are
rejected. Paid mode does not claim C's Script-enforced payout guarantees.

**198.6 — Complete cryptographic acquisitions.** Frozen examples include all signed
Header-related objects, Request/outer IDs, actual funding/purchase evidence,
settlement, License/Agreement, BRC-78 grants, ciphertext and plaintext for both
modes. Python independently reconstructs CBOR/signature preimages, transaction
inputs, key derivation and authenticated AES-GCM playback. Mutations include wrong
recipient, key commitment/period, ciphertext authentication and unknown mechanisms.
Reissue preserves historical rights and settlement; an application/service
integration still must exercise its actual issuance and retrieval adapters.

## BRC-199

**199.1 — Action and effective state.** [Sections 3 and 7](../../0199.md#3-local-decisions-and-acknowledgement)
separate actionStatus/affectedDecisionIds from aggregate serving status. Accepted
suppression creates an independent basis even when already suppressed. Signed
A/B suppressions and restore-A/restore-B results record the precise action; root B
can legitimately reject the same requester under its own policy.

**199.2 — Original evidence and restoration.** Every target supplies original
advertisement Evidence, including spent and operator-policy requests. Restoration
binds root/service/outpoint/digest and authority to the precise local decision;
knowledge of its ID alone grants nothing. Missing dependencies are bounded pending
work with expiry, not a guess about locally absent records. Actual SHIP/SLAP locks
and authorship signatures are included in the corpus.

**199.3 — Current serving fence.** The durable revision gates admission, lookup,
cache, snapshot, live replay and GASP reindex before send-queue enqueue. Old rows
cannot bypass current prohibition; reset reports lost continuity honestly. Shared
memory/SQLite traces exercise stale cached/snapshot/live/reindex views and crash
boundaries. Actual HTTP/cache/index/replication adapters must run these races at
implementation qualification; the model is not presented as their end-to-end test.

**199.4 — Audit, revisions and privacy.** Revisions, no-ops, retries, partial targets,
expiry and policy changes have fixed allocation rules. Immutable decision history
is distinct from current effective status and request evaluation policy. Nonempty
sorted targets, checked deadlines, bounds, retained request fences and current
read/retry authorization are explicit. The signed trace verifies ordered targets,
independent roots and later restoration without rewriting original results.

## Cross-cutting disposition

The packet guide defines representation, behavioral-port, durable-runtime,
live-provider, acquisition-provider, particular-family/routes, LCH-mechanism and
integrated-application conformance separately. Immutable registrations and exact
normative dependency bytes are recorded; unsupported required profiles fail
explicitly. Product names and application-specific schemas remain outside the
core contracts. The next implementation checkpoint must add the actual BRC-100,
Overlay Express, browser/store, source, cache and replication integrations and
record their evidence against these already specified decisions.

## Follow-up: deterministic Bitcoin spend reconciliation

This section addresses the [follow-up on revision 4a6f5a8](https://github.com/bsv-blockchain/BRCs/pull/284#issuecomment-5879410779).
It extends the original finding map; it does not imply that the reviewer has
approved this revision or that the subsequent implementation checkpoint is complete.

**F1 — Actual spends across sources.** BRC-192 section 10 derives consumption from
verified transaction inputs, with dependencies, Script/value checks, selected-chain
context and separate domain lineage. A late parent or catalogue re-entry cannot
resurrect a consumed output. A domain-invalid successor can still consume a real
input; BRCs 197/198 explicitly apply this to the funded-copy merge boundary. The
existing complete lineage corpus remains unchanged. The new cross-host and
same-batch ancestry traces use actual signed parent/child transactions.

**F2 — Durable first-seen and eligibility.** The local journal supplies trusted
positions before workers start; raw receipt, complete support, selectable frontier
and provider sequence are distinct. Source timestamps and worker completion do not
choose winners. Earlier complete but unfinished evidence blocks its affected
component, while genuinely incomplete evidence has no earlier eligible priority.
The total order, historical contexts, inherited replacement reservations and
current compatible graph are explicit. BRC-192's ports carry reconciled state and
replacement history; projections cannot reconstruct chronology from presentation
sorting. Traces reverse worker order, restart, isolate independent components,
retain a stale prior choice and distinguish incomplete from unfinished evidence.

**F3 — Non-final replacement and finality.** Exact ordered outpoints, unsigned
pairwise nondecrease and at least one increase are required. Equal, reordered,
partial, extra-input and incomparable vectors fail; a large scalar elsewhere and
a locktime-only change do not replace. Finalization, the disabled policy, historical
replacement before maturation and finality-reversing reorgs are specified and
exercised. A child cannot attach to a version already replaced while non-final.
The Genesis and BSV node sources are pinned and hashed in registry.json. Their
locktime equality discrepancy is explicitly resolved in favor of the node's strict
comparison, using tip+1 height and selected-chain MTP. Fifteen boundary cases and
eleven replacement comparisons supplement the stateful traces. BRC-194 proposals
are not verified spends; BRC-197 remains final-sequence/zero-locktime only and its
program hash has not changed.

**F4 — Accepted-chain override and reorg.** Inclusion must resolve to the selected
verified header chain; it supersedes conflicting unconfirmed choices and their
dependent projections. A proof on the competing branch fails. Ancestor inclusion
does not defeat a forward spend. Reorg retains raw facts, original order and
historical rights while rebuilding compatible descendants in the new context.
SDK and BitcoinX independently verify the new transaction/proof bytes and both
reducers reproduce contrary inclusion, reorg rollback and locktime-reversing reorg.
BRCs 195/196/198 prevent provisional selection from becoming release evidence or
an automatic second charge; BRC-199 keeps serving policy separate.

**F5 — Source membership and durable replay.** BRC-193 section 9 requires retained
snapshot page/group order, ascending live sequence, atomic groups, staged reset
and closed-generation fences. Withdrawal affects one source; later re-entry does
not change the spend graph. Traces cover output/withdraw/re-entry, stale replay,
two sources, delayed membership verification, multiple snapshot groups sharing W,
ordered changes within a group and old work after generation replacement. Both
journal and projection are committed atomically in the SQLite model.

Validation is reproducible with the packet guide commands: 27 frozen raw
transactions, 40 input Script checks, 113 synthetic headers, actual Atomic BEEF,
32 reconciliation scenarios and 52 named checkpoints in each reducer. Python adds
64 memory/SQLite adapter runs, 104 checkpoints, 42 full-state restart comparisons
and two actual subprocess crash boundaries. Expected observations are manually
specified separately from the reducers. These bounded models complement the prior
wire, crypto, covenant and crash suites; they do not certify arbitrary production
adapters, miner policy, browser transports or wallet integration. The next
checkpoint must run these contracts through those actual implementation paths.
