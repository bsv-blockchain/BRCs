# BRC: Bitcoin Request for Comments

A repository for submitting, discussing, sharing, and indexing technical proposals for use across the Bitcoin ecosystem. Data models, user interfaces, script templates, encoding formats, communication protocols, and constructive critique of existing industry practice are all welcome. The goal is to provide a platform for sharing ideas without any bureaucratic overhead.

## Contributing

Contributions from all builders are welcome and encouraged. To propose a new BRC, fork the repo and create a new markdown file using [EXAMPLE.md](./EXAMPLE.md) as the template. The common structure is outlined below, which is a guideline to aid you rather than a strict requirement. Once your proposal is ready to share, submit a pull request so that others can review and discuss it.

To participate in discussions about existing proposals, simply open an issue and link back to the BRC file in question.

## Iterative improvement

We believe in encouraging discussion and iterative improvement of proposals, resulting in incremental improvement within the bounds of the Bitcoin protocol. We welcome suggestions for improvement and are committed to working with contributors to improve proposals and ensure that they align with our guidelines.

**Note** that substantial revisions to standards (beyond fixing typos, adding context or wording) should go into a new standard that extends or revises the old one, so as not to disrupt existing implementations.

We look forward to your contributions and helping to create a world where transactions are seamlessly formed, and applications interact with each other with ease.

Read more about areas of interest on [OpenStandards.cash](https://openstandards.cash)

## Current implementation map

The standards in this repository are vendor-neutral. Current BSV Association reference implementations include:

- `@bsv/sdk` for TypeScript SDK primitives, transactions, identities, overlays, storage, and the BRC-100 `WalletClient` interface.
- `@bsv/wallet-toolbox` for BRC-100 wallet storage, services, signing, monitoring, and wallet implementation tooling.
- BSV Desktop and BSV Browser as BSV Association reference wallet/browser applications for the BRC-100 interface.
- Overlay service implementations in `bsv-blockchain/overlay-services`, `bsv-blockchain/overlay-express`, and related overlay example repositories.

Vendor distributions can implement the same standards with their own branding and hosted service defaults. Examples include Babbage's Metanet Desktop / Metanet Explorer as well as the Hudos Browser built by Matt Archbold.

## Structure

The BRCs repository is organized into directories, each representing a different category of proposal. Categories may include, but are not limited to:

- Transaction Templates
- Bitcoin Script Templates
- Communication Protocols

Each proposal should be written as a markdown file and should loosely adhere to the following:

- **Title:** A descriptive title for the standard being defined.
- **Author(s):** Who wrote the standard and where did it come from? How can they be reached?
- **Abstract:** A brief description of the proposed standard or template.
- **Motivation:** The reasoning behind the proposal and why it is needed.
- **Specification:** A detailed technical specification of the proposal.
- **Implementations:** Information on how the proposal has been or can be implemented.
- **References:** Any relevant literature or external resources related to the proposal.

**Note** that additional relevant content, identifiers or other information may be added to the document. Documents that already existed before the repository may not follow these requirements.

Things that help depict and understand the document, such as media, may also be added in a media subdirectory where appropriate.

Refer to the [Banana-Powered Bitcoin Wallet Control Protocol](./EXAMPLE.md) for a fun example template you can copy when proposing your own standards.

## Interpreting the Repository

This repository contains both active interoperability specifications and historical design context.

Use the directory README files and in-spec status notes to determine which documents currently define interoperable behavior in a given area. Where a newer BRC narrows, extends, or authoritatively re-specifies behavior, implementers should follow the newer normative document rather than inferring precedence from chronology alone.

## Standards

BRC | Standard
-----|------------------
0    | [Banana-Powered Bitcoin Wallet Control Protocol](./EXAMPLE.md)
1    | [Transaction Creation](./wallet/0001.md)
2    | [Data Encryption and Decryption](./wallet/0002.md)
3    | [Digital Signature Creation and Verification](./wallet/0003.md)
4    | [Input Redemption](./wallet/0004.md)
5    | [HTTP Wallet Communications Substrate](./wallet/0005.md)
6    | [XDM Wallet Communications Substrate](./wallet/0006.md)
7    | [Window Wallet Communication Substrate](./wallet/0007.md)
8    | [Everett-style Transaction Envelopes](./transactions/0008.md)
9    | [Simplified Payment Verification](./transactions/0009.md)
10   | [Merkle proof standardised format](./transactions/0010.md)
11   | [TSC Proof Format with Heights](./transactions/0011.md)
12   | [Raw Transaction Format](./transactions/0012.md)
13   | [TXO Transaction Object Format](./transactions/0013.md)
14   | [Bitcoin Script Binary, Hex and ASM Formats](./scripts/0014.md)
15   | [Bitcoin Script Assembly Language](./scripts/0015.md)
16   | [Pay to Public Key Hash](./scripts/0016.md)
17   | [Pay to R Puzzle Hash](./scripts/0017.md)
18   | [Pay to False Return](./scripts/0018.md)
19   | [Pay to True Return](./scripts/0019.md)
20   | [There is no BRC-20](./tokens/0020.md)
21   | [Push TX](./scripts/0021.md)
22   | [Overlay Network Data Synchronization](./overlays/0022.md)
23   | [Confederacy Host Interconnect Protocol (CHIP)](./overlays/0023.md)
24   | [Overlay Network Lookup Services](./overlays/0024.md)
25   | [Confederacy Lookup Availability Protocol (CLAP)](./overlays/0025.md)
26   | [Universal Hash Resolution Protocol](./overlays/0026.md)
27   | [Direct Payment Protocol (DPP)](./payments/0027.md)
28   | [Paymail Payment Destinations](./payments/0028.md)
29   | [Simple Authenticated BSV P2PKH Payment Protocol](./payments/0029.md)
30   | [Transaction Extended Format (EF)](./transactions/0030.md)
31   | [Authrite Mutual Authentication](./peer-to-peer/0031.md)
32   | [BIP32 Key Derivation Scheme](./key-derivation/0032.md)
33   | [PeerServ Message Relay Interface](./peer-to-peer/0033.md)
34   | [PeerServ Host Interconnect Protocol](./peer-to-peer/0034.md)
35   | [Layered Key-Value Store for Wallets and Overlay Services](./overlays/0035.md)
36   | [Format for Bitcoin Outpoints](./outpoints/0036.md)
37   | [Basket and Custom Instructions Extension for Bitcoin Outpoints](./outpoints/0037.md)
38   | [User Wallet Data Format](./outpoints/0038.md)
39   | [User Wallet Data Format Encryption Extension](./outpoints/0039.md)
40   | [User Wallet Data Synchronization](./outpoints/0040.md)
41   | [PacketPay HTTP Payment Mechanism](./payments/0041.md)
42   | [BSV Key Derivation Scheme (BKDS)](./key-derivation/0042.md)
43   | [Security Levels, Protocol IDs, Key IDs and Counterparties](./key-derivation/0043.md)
44   | [Admin-reserved and Prohibited Key Derivation Protocols](./key-derivation/0044.md)
45   | [Definition of UTXOs as Bitcoin Tokens](./tokens/0045.md)
46   | [Wallet Transaction Output Tracking (Output Baskets)](./wallet/0046.md)
47   | [Bare Multi-Signature](./scripts/0047.md)
48   | [Pay to Push Drop](./scripts/0048.md)
49   | [Users should never see an address](./opinions/0049.md)
50   | [Submitting Received Payments to a Wallet](./wallet/0050.md)
51   | [List of user experiences](./opinions/0051.md)
52   | [Identity Certificates](./peer-to-peer/0052.md)
53   | [Certificate Creation and Revelation](./wallet/0053.md)
54   | [Hybrid Payment Mode for DPP](./payments/0054.md)
55   | [HTTPS Transport Mechanism for DPP](./payments/0055.md)
56   | [Unified Abstract Wallet-to-Application Messaging Layer](./wallet/0056.md)
57   | [Legitimate Uses for mAPI](./opinions/0057.md)
58   | [Merkle Path JSON format](./transactions/0058.md)
59   | [Security and Scalability Benefits of UTXO-based Overlay Networks](./opinions/0059.md)
60   | [Simplifying State Machine Event Chains in Bitcoin](./state-machines/0060.md)
61   | [Compound Merkle Path Format](./transactions/0061.md)
62   | [Background Evaluation Extended Format (BEEF) Transactions](./transactions/0062.md)
63   | [Genealogical Identity Protocol](./peer-to-peer/0063.md)
64   | [Overlay Network Transaction History Tracking](./overlays/0064.md)
65   | [Transaction Labels and List Actions](./wallet/0065.md)
66   | [Output Basket Removal and Certificate Deletion](./wallet/0066.md)
67   | [Simplified Payment Verification](./transactions/0067.md)
68   | [Publishing Trust Anchor Details at an Internet Domain](./peer-to-peer/0068.md)
69   | [Revealing Key Linkages](./key-derivation/0069.md)
70   | [Paymail BEEF Transaction](./payments/0070.md)
71   | [Merkle Path Binary Format](./transactions/0071.md)
72   | [Protecting BRC-69 Key Linkage Information in Transit](./key-derivation/0072.md)
73   | [Group Permissions for App Access](./wallet/0073.md)
74   | [BSV Unified Merkle Path (BUMP) Format](./transactions/0074.md)
75   | [Mnemonic For Master Private Key](./key-derivation/0075.md)
76   | [Graph Aware Sync Protocol](./transactions/0076.md)
77   | [Message Signature Creation and Verification](./peer-to-peer/0077.md)
78   | [Serialization Format for Portable Encrypted Messages](./peer-to-peer/0078.md)
79   | [Token Exchange Protocol for UTXO-based Overlay Networks](./tokens/0079.md)
80   | [Improving on MLD for BSV Multicast Services](./opinions/0080.md)
81   | [Private Overlays with P2PKH Transactions](./overlays/0081.md)
82   | [Defining a Scalable IPv6 Multicast Protocol for Blockchain Transaction Broadcast and Update Delivery](./peer-to-peer/0082.md)
83   | [Scalable Transaction Processing in the BSV Network](./transactions/0083.md)
84   | [Linked Key Derivation Scheme](./key-derivation/0084.md)
85   | [Proven Identity Key Exchange (PIKE)](./peer-to-peer/0085.md)
86   | [Bidirectionally Authenticated Derivation of Privacy Restricted Type 42 Keys](./key-derivation/0086.md)
87   | [Standardized Naming Conventions for BRC-22 Topic Managers and BRC-24 Lookup Services](./overlays/0087.md)
88   | [Overlay Services Synchronization Architecture](./overlays/0088.md)
89   | [Web 3.0 Standard (at a high level)](./opinions/0089.md)
90   | [Thoughts on the Mandala Network](./opinions/0090.md)
91   | [Outputs, Overlays, and Scripts in the Mandala Network](./opinions/0091.md)
92   | [Mandala Token Protocol](./tokens/0092.md)
93   | [Limitations of BRC-69 Key Linkage Revelation](./key-derivation/0093.md)
94   | [Verifiable Revelation of Shared Secrets Using Schnorr Protocol](./key-derivation/0094.md)
95   | [Atomic BEEF Transactions](./transactions/0095.md)
96   | [BEEF V2 Txid Only Extension](./transactions/0096.md)
97   | [Extensible Proof-Type Format for Specific Key Linkage Claims](./wallet/0097.md)
98   | [P Protocols: Allowing future wallet protocol permission schemes](./wallet/0098.md)
99   | [P Baskets: Allowing Future Wallet Basket and Digital Asset Permission Schemes](./wallet/0099.md)
100  | [Unified, Vendor-Neutral, Unchanging, and Open BSV Blockchain Standard Wallet-to-Application Interface](./wallet/0100.md)
101  | [Diverse Facilitators and URL Protocols for SHIP and SLAP Overlay Advertisements](./overlays/0101.md)
102  | [The deployment-info.json Specification](./apps/0102.md)
103  | [Peer-to-Peer Mutual Authentication and Certificate Exchange Protocol](./peer-to-peer/0103.md)
104  | [HTTP Transport for BRC-103 Mutual Authentication](./peer-to-peer/0104.md)
105  | [HTTP Service Monetization Framework](./payments/0105.md)
106  | [Bitcoin Script ASM Format](./scripts/0106.md)
107  | [Enhanced Mandala Token Protocol](./tokens/0107.md)
108  | [Identity-Linked Token Protocol](./tokens/0108.md)
109  | [PCW-1 : Peer Cash Wallet Protocol](./wallet/0109.md)
110  | [Zero-Friction, Mobile-First Onboarding for MetaNet-Enabled Apps](./opinions/0110.md)
111  | [P Labels: Allowing Future Wallet Action Label Permission Schemes](./wallet/0111.md)
112  | [Balance Baskets: Backwards-Compatible Basket Balance Queries](./wallet/0112.md)
113  | [Merkle Proof Token](./tokens/0113.md)
114  | [Time Labels: Backwards-Compatible Action Timestamp Filters for List Actions](./wallet/0114.md)
115  | [Identity-Linked Deterministic Token Verification Framework](./tokens/0115.md)
116  | [Wallet Permissions and Counterparty Trust](./wallet/0116.md)
117  | [Proof-of-Indexing Hash-to-Mint Tokens](./tokens/0117.md)
118  | [Multipart Body Transport for BRC-105 Payments](./payments/0118.md)
119  | [SubTree Unified Merkle Path (STUMP) Format](./transactions/0119.md)
120  | [x402 Stateless Settlement-Gated HTTP Protocol](./payments/0120.md)
121  | [Simple 402 Payments](./payments/0121.md)
122  | [Auditable Real-time Inference Architecture (ARIA)](./apps/0122.md)
123  | [Basket Permission Scheme Registry and Governance](./wallet/0123.md)
124  | [Multicast Transaction Frame Format](./transactions/0124.md)
125  | [PeerPay URI Scheme for BRC-29 Payments](./payments/0125.md)
126  | [Multicast Transaction NACK Retransmission Protocol](./transactions/0126.md)
127  | [Multicast Subtree Group Announcement Frame Format](./transactions/0127.md)
128  | [Multicast Extended Transaction Frame Format](./transactions/0128.md)
129  | [IPv6 Multicast Group Address Assignments](./transactions/0129.md)
130  | [Multicast Transaction Frame Fragmentation](./transactions/0130.md)
131  | [Multicast Block Announcement Frame Format](./transactions/0131.md)
132  | [Multicast Subtree Data Frame Format](./transactions/0132.md)
133  | [Multicast Coinbase Transaction Frame Format](./transactions/0133.md)
134  | [Multicast Anchor Transaction Frame Format](./transactions/0134.md)
135  | [Multicast Block Header Frame Format](./transactions/0135.md)
136  | [Block-Anchored Overlay Synchronization via Block-Aligned Sparse Merkle Trees (BASM)](./overlays/0136.md)
137  | [Device-Aware Wallet Onboarding and Fallback Login for BRC-100 Applications](./opinions/0137.md)
138  | [Single-Use Signed Proofs for Request Authentication](./peer-to-peer/0138.md)
139  | [Multicast Shard Manifest Announcement Protocol](./transactions/0139.md)
140  | [Threshold Key Sharing and Backup via Shamir's Secret Sharing Scheme](./key-derivation/0140.md)

## License

Everything in this repository is subject to the [Open BSV License](https://github.com/bitcoin-sv/bitcoin-sv/blob/master/LICENSE).

## Terms and Conditions

[Terms and Conditions](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FfVclCmeRPossA1a4BKh5%2Fuploads%2FjrLiRFSSc78VORRVpyOT%2FTerms%20of%20Use%20BSVA%20Blockchain.pdf?alt=media&token=95fa409e-2017-4503-9b38-f4951b4960df)
