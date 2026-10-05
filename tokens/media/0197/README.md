# BRC-197 revenue-listing-v1 executable family

This directory freezes two literal Bitcoin Script programs: [activation.asm](./activation.asm) and [active.asm](./active.asm). Their exact bytes are [activation.hex](./activation.hex) and [active.hex](./active.hex). The [component guide](./COMPONENTS.md) presents their ordered opcode fragments, byte offsets and size profile for review. [BRC-197](../../0197.md) defines the 717-byte metadata, unlocking ABI, route semantics and domain checks. No contract compiler or generated high-level source is part of this family.

## Reproduction

From the repository root, install the pinned Node and Python dependencies in the [packet guide](../../../overlays/media/0192-0199/README.md), then run:

```sh
node tokens/media/0197/verify-assembly.mjs
node tokens/media/0197/test-family.mjs
overlays/media/0192-0199/.venv/bin/python tokens/media/0197/verify-script.py
```

The assembly check independently assembles every literal component and both complete opcode listings with the BSV SDK, then compares the composition, offsets, bytes, lengths and hashes in [artifact.json](./artifact.json). The Python verifier independently repeats those checks with BitcoinX 0.9 under post-Genesis rules. All examples execute complete transaction inputs, including external P2PKH funding inputs. The fixed-key children match independent BRC-42 derivation for the disclosed fixture roots.

The scripts use ordinary post-Genesis operations including OP_CAT, OP_SPLIT, OP_MUL, OP_MOD, OP_XOR and CHECKSIGVERIFY. They use no OP_CODESEPARATOR, disabled opcode, OP_CHECKLOCKTIMEVERIFY or OP_CHECKSEQUENCEVERIFY. The 34,127-byte activation lock is below the published BSV node default 500 kB post-Genesis script-size policy, but a target miner's current fee, time and resource policy still requires direct qualification. The active lock is 5,627 bytes. Interpreters use a 128 MiB memory bound and 128-byte Script-number bound, disclosed as test limits rather than universal miner settings.

## Linkage proof boundary

The activation witness lists a public compressed root `R`, claimed child `Q`, scalar `t`, difference point `D`, field coordinates and slope for the seller and up to eight recipients. Script verifies the secp256k1 curve equation and compressed encodings for `R` and `Q`, verifies the supplied slope equations for `D=Q−R`, computes `HMAC-SHA256(compressed(R), UTF8("2-3241645161d8-brc197 authority")) mod n` and requires equality to `t`. ECDSA signature validation requires `D` to be a genuine point.

The remaining statement `D=tG` is proved by two fixed-nonce ECDSA checks under `D`. Let `r_i=x(iG) mod n` for `i=2,3`, and let `z` be the transaction's SIGHASH_ALL|FORKID digest scalar. The witness supplies canonical low-S `s_i` equal to either sign of `(z+r_i t)/i mod n`. A valid ECDSA check under some `D=uG` yields `z+r_i u = ±(z+r_i t)`, since the only curve points with the checked x-coordinate are `±iG`. Thus one check permits `u=t` or `u=−t−2z/r_i`. Taking the false branch in both checks requires `z=0`, which Script rejects. Taking one true and one false branch requires `z+r_i t=0` for the false check, also explicitly rejected. Both `r_i` exceed `p−n`, so an alternate x-coordinate `r_i+n` cannot be a field element. This proof is conditional on normal secp256k1/ECDSA and SHA-256d collision/preimage hardness; it does not claim an information-theoretic proof.

The frozen constants are `p=fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f`, `n=fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141`, `r2=c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5`, and `r3=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9` (hex, most significant byte first). `p−n=14551231950b75fc4402da1722fc9baee`.

The supplied preimage is bound to the *actual* transaction with two analogous checks under public generator `G`, taking `d=1`. For each check, the true digest scalar is either supplied `z` or `−z−2r_i`. The two different `r_i` exclude simultaneous false choices; mixed choices require `z=−r_i`, explicitly rejected. The Script also verifies its own SHA-256d(preimage) modulo `n` equals `z`. This makes the introspected input amount, scriptCode, prevouts, sequence, locktime and output hash transaction-authentic under the same cryptographic assumptions. It is essential that **both** binder signatures and **both** linkage signatures remain in the frozen program. A one-signature shortcut is unsound.

The slope equations require `x_Q != x_R`; the vanishingly rare degenerate child cannot be activated under this family. A zero tweak or infinity child also cannot satisfy a valid proof. Builders must preflight the exact activation and use a new descriptor if a degenerate point occurs. Public fixed-nonce signatures reveal no root or child scalar: their signing scalars are the public constants 1 and `t`.

## Corpus and checks

The connected synthetic graph starts with a reserve-only stage output, then activation, purchase, split, permissionless payout and expiry retirement. The two split branches are spent separately. A separate maximum-size graph activates eight recipients, purchases and pays all eight. Both include exact recipient P2PKH scripts, receipts, fees and external funding signatures; retirement includes its exact top-up. Negative vectors rebuild the transaction and preimage before testing underpayment, redirected payout, missing seller-child authority, premature expiry and forged activation links. Both interpreters must agree on each expected result. The malleability vectors require rejection of a changed unused `units` push and an extra listing push, while accepting three complete transaction variants with distinct txids and the same full purchase commitment: the original, a funding-input extra push, and a listing-input `OP_0 OP_DROP` pair.

The corpus is an offline Script and economic-conservation test. A signed BRC-77 genesis packet, BEEF lineage, asset authority, current UTXO set and prepared BRC-196 request require the domain validator. A copied active output can pass local Script checks but is rejected by full lineage. Production use additionally needs a protected signer and a wallet able to internalize and spend the fixed publicly derived child. Exporting that child scalar compromises the identity root because the tweak is public.
