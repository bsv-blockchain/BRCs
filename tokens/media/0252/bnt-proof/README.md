# BNT step proofs

The step program of draft BRC-252 §4: a proof that a transaction's outputs carry
BRC-255 assets validly, made from its parents' proofs, so its size and its
check stay the same however long the history behind it is.

- `crates/bnt-step`: steps in plain Rust. A step reads the transaction, every
  parent, and the parents' claims, and returns the transaction's claim. A batch
  steps many transactions in order and returns the claims of those with an
  asset output no later member spends, so a chain commits only its last.
  Scripts are left to Bitcoin and deploys to the recipient (BRC-252 §4).
- `program`: the SP1 program that proves a batch and verifies the proofs of
  the parents outside it. Build it with the SP1 toolchain (`cargo prove build`).
- `vectors/desktop.json`: scenarios, scripts and payloads that HandCash
  Desktop built and judged with its own BRC-255 rules.

## Check

```sh
cargo test                               # unit tests and the Desktop vectors
cargo run --release --example chain      # step cost against history length
cd script && cargo run --release --bin bnt-step-script  # program cycles: chains of 1 to 1000 transfers in one batch
```

To regenerate the vectors from HandCash Desktop:

```sh
cd ../HANDCASH-DESKTOP
BNT_PROOF_VECTORS=$PWD/../BNT-PROOF/vectors/desktop.json \
  ./node_modules/.bin/vitest run src/wallet/bnt/proofVectors.test.ts
```

## E2E experiment

`sh experiment/run.sh` checks the BNT paper's claims on the test token E2E
(asset `2d57a856…`): deploy `f357dd82`, split `42128ed2`, merge `0f9c13ad`,
all in block 971921. It runs offline on `experiment/mainnet.json`; `--refresh`
pulls the evidence from WhatsOnChain again. It needs only Node and Rust: the
first run installs the pinned `@bsv/sdk` 2.8.11 into `experiment/`.

- `experiment/chain.test.mjs` (Bitcoin, with `@bsv/sdk`): merkle
  paths reach a header that meets its proof of work, every input's script
  validates, each token input is one signature against one holder key, the
  deploy is signed by the key anyone derives from `iss`, and a script that
  writes 1001 units from 1000 still validates.
- `crates/bnt-step/tests/mainnet_e2e.rs` (token rules): the walk from merge to
  deploy credits 1000 units, output bytes match the anatomy, the split is the
  452-byte §12 transfer less 3 bytes (a 72-byte signature, 2-byte amounts), and
  the walk refuses 1001 or 999 units out, a hop whose parent was not walked and
  units from nothing, while a later receipt needs only the new hop.

## Step proofs

`proofs/` holds the first step proofs: the E2E token's split and its merge,
whose proof verifies the split's inside it, each a batch of one, and chains of
synthetic transfers proved as one batch. All are SP1 v6.1.0 compressed proofs
of 1,272,656 bytes, whatever the batch holds.

- `split.proof`, `merge.proof`: the mainnet transactions.
- `batch-10.proof`, `batch-100.proof`: chains of 10 and 100 transfers from a
  synthetic deploy (`script/src/synthetic.rs`), each committing only the
  chain's last claim.
- `bnt-step-program.elf`: the program they prove (SHA-256
  `cfece37e…39b73`), key
  `0x00743a85773cc14bbf0e2e494d6e199bab319550586afe0aba3185ea8aacd3e1`.
- `results.json`: key, sizes and proving times.
- The runs that made them on an Apple M2 with 8 GB, timed with
  `/usr/bin/time -l`:

| Log | Transactions | Time | Per transaction | Peak memory footprint |
| --- | --- | --- | --- | --- |
| `prove.log` | split, then merge | 154.5 s, 350.5 s | about 4 min | 18,497,714,672 bytes |
| `batch-10.log` | 10 | 181.0 s | 18.1 s | 15,754,703,256 bytes |
| `batch-100.log` | 100 | 483.0 s | 4.8 s | 15,175,315,336 bytes |

With SP1's default workers, the 100-transfer batch passed 24 GB and macOS
stopped it; `sh script/prove-small.sh batch 100` runs one shard at a time and
made it.

```sh
cd script && cargo run --release --bin verify
```

checks that the published binary has that key, that each proof verifies under
it and commits the claims `bnt-step` computes from `experiment/mainnet.json`
or from the synthetic chain it names, that each has the size `results.json`
reports, and whether the program built from this source is byte-identical to
the published binary. It needs the SP1 toolchain (`sp1up`).
`cargo run --release --bin prove` remakes the split and merge proofs,
`-- batch 100` proves a chain of 100 transfers, and `-- groth16` wraps the
merge to Groth16, which needs 16 GB of memory or more.

## Claims and their checks

| Claim | Check |
| --- | --- |
| The E2E token's deploy, split and merge are mined and settle by SPV | `experiment/chain.test.mjs` |
| A wallet walks three hops in milliseconds (11.3 ms median on the M2: parsing, SPV and every input script) | `experiment/chain.test.mjs`, "Walk time" |
| The walk credits 1000 units and refuses 999 or 1001 out | `crates/bnt-step/tests/mainnet_e2e.rs` |
| A transfer is about 450 bytes: the split is 449, the BRC-255 §12 model 452 | `crates/bnt-step/tests/mainnet_e2e.rs` |
| A step proof of a mainnet transaction is 1,272,656 bytes compressed | `script` `verify` |
| A step took about four minutes and 19 GB of memory to prove on a laptop | `proofs/prove.log` |
| One proof of a chain of 100 transfers took 483 s, about 5 s per transfer, and commits only the last claim | `proofs/batch-100.log`, `script` `verify` |
| In a batch the program spends about 50,000 cycles per transfer, against 83,776 for a transfer alone | `proofs/cycles.log` (`cd script && cargo run --release --bin bnt-step-script`) |

## Not yet

The proofs are not wrapped to Groth16, so the key is not pinned in BRC-252 and
no wallet checks them yet.
