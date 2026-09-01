# Wallet

This directory contains standards for controlling, interfacing with and extending Bitcoin wallets.

Current orientation:

- [BRC-100](./0100.md) is the main wallet-to-application interface specification.
- [BRC-116](./0116.md) authoritatively specifies permission lifecycle behavior and manifest handling for current wallets.
- [BRC-73](./0073.md) should be read as the grouped-permission declaration shape used by current wallets, alongside BRC-116.
- [BRC-98](./0098.md), [BRC-99](./0099.md), [BRC-111](./0111.md), [BRC-112](./0112.md), and [BRC-114](./0114.md) are compatibility-oriented extensions around permission and query behavior.

BRC | Standard
-----|------------------
1    | [Transaction Creation](./0001.md)
2    | [Data Encryption and Decryption](./0002.md)
3    | [Digital Signature Creation and Verification](./0003.md)
4    | [Input Redemption](./0004.md)
5    | [HTTP Wallet Communications Substrate](./0005.md)
6    | [XDM Wallet Communications Substrate](./0006.md)
7    | [Window Wallet Communication Substrate](./0007.md)
46   | [Wallet Transaction Output Tracking (Output Baskets)](./0046.md)
50   | [Submitting Received Payments to a Wallet](./0050.md)
53   | [Certificate Creation and Revelation](./0053.md)
56   | [Unified Abstract Wallet-to-Application Messaging Layer](./0056.md)
65   | [Transaction Labels and List Actions](./0065.md)
66   | [Output Basket Removal and Certificate Deletion](./0066.md)
73   | [Group Permissions for App Access](./0073.md)
97   | [Extensible Proof-Type Format for Specific Key Linkage Claims](./0097.md)
98   | [P Protocols: Allowing Future Wallet Protocol Permission Schemes](./0098.md)
99   | [P Baskets: Allowing Future Wallet Basket and Digital Asset Permission Schemes](./0099.md)
100  | [Unified, Vendor-Neutral, Unchanging, and Open BSV Blockchain Standard Wallet-to-Application Interface](./0100.md)
109  | [PCW-1 : Peer Cash Wallet Protocol](./0109.md)
111  | [P Labels: Allowing Future Wallet Action Label Permission Schemes](./0111.md)
112  | [Balance Baskets: Backwards-Compatible Basket Balance Queries](./0112.md)
114  | [Time Labels: Backwards-Compatible Action Timestamp Filters for List Actions](./0114.md)
116  | [Wallet Permissions and Counterparty Trust](./0116.md)
123  | [Basket Permission Scheme Registry and Governance](./0123.md)
153  | [Action Reference Labels for BRC-100 Wallets](./0153.md)
154  | [Pluggable Backup Services for BRC-140 Share Vaults](./0154.md)
155  | [Pull-Based Receive Discovery](./0155.md)
164  | [Output Identity Tags for BRC-100 Wallets](./0164.md)
177  | [Wallet-Enforced Expiry for `noSend` Actions](./0177.md)
219  | [Wallet Permission Prompt Liveness Contract](./0219.md)
229  | [Wallet-Native Elliptic Curve Point Multiplication as a BRC-98 Module](./0229.md)
