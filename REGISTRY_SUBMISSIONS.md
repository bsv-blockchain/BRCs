# Requesting and maintaining registry descriptions

ProtoMap, BasketMap and CertMap help wallets explain protocol identifiers, output baskets and certificate types. Their records are optional descriptions signed by individual registry publishers. A listing does not approve an application, confer ownership of an identifier, grant wallet permissions or establish trust in a certificate issuer.

[BRC-184: Optional Metadata Registries and Their Stewardship](./wallet/0184.md) proposes the ecosystem framework, including wallet behavior and governance boundaries. It remains a proposal subject to review. This page is the practical submission guide and the initial Metanet Trust Services stewardship policy; it does not speak for other operators.

## Start with the BRC process

1. Open a BRC proposal describing your protocol, or improve the relevant existing BRC. Follow the [contribution process](./README.md#contributing) and current numbering rules. Include the exact BRC-43 tuples, basket identifiers, certificate type and field names that applications actually use, plus permission semantics, security considerations, implementation references and compatibility/versioning details.
2. On the BRC pull request, or a linked [issue](https://github.com/bsv-blockchain/BRCs/issues/new/choose) or [discussion](https://github.com/bsv-blockchain/BRCs/discussions), ask for registry inclusion and tag the relevant maintainer. For **Metanet Trust Services**, tag **@ty-everett**. State the desired publisher and network so a request is not mistaken for a universal assignment.
3. Use the **Registry metadata request or correction** issue form for a new listing, an update, a proposed withdrawal or a dispute. Link an existing conversation rather than opening duplicate requests. A draft BRC can be discussed before merge; clearly state its status.
4. Respond to requests for evidence or clearer wording. After publication, help check the record through wallet lookup and report stale documentation, inaccessible images or changed behavior in the same public thread.

For **genuinely urgent or long-time unresolved matters**, email the BRC author at **[ty@projectbabbage.com](mailto:ty@projectbabbage.com)** with links to the public history where appropriate. The BRC issue/discussion process is the normal route. Do not post private keys, wallet recovery material, user certificate contents or sensitive incident details publicly; arrange a private channel for those matters.

There is no automatic pipeline from a BRC merge to a registry transaction, no automatic forwarding to every registry operator, and no guaranteed review deadline. BRC publication and registry publication are separate decisions. This is an early process that will improve through experience and public feedback, not a claim of a fully formal accreditation or appeals system. **It is not a prerequisite to building, distributing or using your protocol.**

## What to include

| Information | Useful detail |
| --- | --- |
| Request | Create, update, withdrawal, correction or dispute; target publisher and mainnet/testnet |
| Exact identity | Protocol `[securityLevel, protocolString]`, basket string, or certificate type as canonical base64; do not supply only a friendly name or BRC number |
| Specification | BRC/PR link and status, version or commit, compatibility notes |
| Implementation evidence | Public source, example application or interoperable implementation using that exact identity; distinguish deployed use from an experiment |
| Proposed description | Short name, plain explanation of what the operation/data means, and important limits; avoid endorsements and marketing claims |
| Public resources | Stable documentation and a retrievable icon with appropriate reuse rights; do not publish signed or credential-bearing URLs |
| Certificate schema | Exact field spelling/case, friendly labels, meaning, display type and icon if supplied; type metadata is separate from issuer trust |
| Existing record | Publisher key, network and outpoint if known, exact disputed/current content, proposed correction and evidence |
| Maintenance | Public contact, expected changes, deprecation or migration information, and relevant conflicts of interest |

A single BRC may document several related identifiers. Conversely, do not invent a wildcard record for a dynamic identifier family or publish user-specific counterparties just to fill a catalogue. Explain those families in the protocol documentation.

## Initial Metanet Trust Services stewardship policy

Metanet Trust Services intends to perform a neutral coordination role comparable in purpose to IANA's stewardship of service names and ports: make identifiers understandable and reduce conflicting descriptions. This is an analogy, not an IANA affiliation or import of IANA's allocation powers. Metanet Trust Services controls its own signed descriptions; it does not control who uses a protocol or what an application may request from a user.

The operator commits to the following editorial practice:

- Apply the same accuracy, evidence, clarity and resource-quality criteria to competing projects. Inclusion must not depend on buying an operator service, supporting its views or abandoning a competitor. Any future fee or prioritization policy will be disclosed before applying it; payment cannot purchase misleading descriptions.
- Keep decisions and reasons in the linked BRC issue, discussion or PR, identifying source revisions and resulting record outpoints when published. Do not mark a request published merely because a proposal was accepted for discussion.
- Distinguish draft, experimental, deployed, deprecated and disputed information. Avoid repurposing an established identifier silently. Document incompatible real-world uses rather than pretending a listing grants exclusive technical or legal ownership.
- Accept corrections and disputes through the same public BRC process. Give affected parties a chance to provide evidence, disclose conflicts and seek an uninvolved reviewer where practicable. Record when an independent reviewer is unavailable.
- Publish a reasoned outcome and allow reconsideration with new evidence. Follow the dispute procedures adopted as the process matures. No independent tribunal, fixed appeal deadline or universal adjudication authority is being claimed today.
- Handle urgently misleading or unsafe display material narrowly, with an explanation and subsequent review. Withdrawing metadata must never be treated as a protocol ban or certificate revocation.
- Publish material process changes with effective dates and invite feedback. Keep the public history useful while avoiding unnecessary personal data and sensitive disclosures.

Useful public statuses are **received**, **needs evidence**, **prepared**, **published**, **deferred**, **disputed** and **withdrawn**, each with an explanation. These are editorial status descriptions in the public discussion, not new fields in the on-chain token format or a promise that an automated queue already exists.

## Wallets and independent operators

Wallets adopting BRC-184 must continue their normal permission flow with exact identifiers if a description is missing, disputed, invalid or unavailable. A friendly listing cannot grant permissions, and an absent listing cannot impose a protocol veto or extra approval barrier. Normal user choices, transaction rules and supported-module checks remain in force.

Different wallets and communities can select different publishers or disable optional metadata. Public on-chain records can be independently verified and replicated where transaction data is available, preserving the original signature and attribution. Replication does not convey the signing key or the ability to change another publisher's outputs. Linked documentation and icons need separate preservation; blockchain publication alone does not guarantee their availability.

See [Registrant](https://github.com/bsv-blockchain/registrant) for publishing tools and [TS Stack](https://github.com/bsv-blockchain/ts-stack) for client, wallet and overlay implementations. Creating a record with your own wallet creates your own publisher's statement; it does not put it under Metanet Trust Services or automatically add you to another wallet's selected sources.
