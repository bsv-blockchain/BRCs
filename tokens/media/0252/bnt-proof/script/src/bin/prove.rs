//! Proves the E2E experiment: the test token's mainnet split, then its merge,
//! whose proof verifies the split's inside it. Each proof is checked, saved to
//! `proofs/`, and its size and proving time go to `proofs/results.json` with
//! the verifying key BRC-252 pins.
//!
//!     cargo run --release --bin prove              # split, then merge
//!     cargo run --release --bin prove -- merge     # reuse proofs/split.proof
//!     cargo run --release --bin prove -- groth16   # reuse proofs/split.proof, wrap the merge
//!     cargo run --release --bin prove -- batch 100 # a chain of 100 synthetic transfers in one proof
//!
//! The Groth16 wrap needs 16 GB of memory or more and Docker, or the sp1-sdk
//! `native-gnark` feature with Go and Clang.

use std::time::Instant;

use bnt_step::{public_values, Claim};
use serde_json::{json, Value};
use sp1_sdk::blocking::prelude::*;
use sp1_sdk::blocking::ProverClient;
use sp1_sdk::{SP1Proof, SP1VerifyingKey};

#[path = "../evidence.rs"]
mod evidence;
use evidence::{root, Evidence};
#[path = "../synthetic.rs"]
#[allow(dead_code)]
mod synthetic;

const STEP_ELF: Elf = include_elf!("bnt-step-program");

struct Made {
    proof: SP1ProofWithPublicValues,
    seconds: f64,
    bytes: u64,
}

struct Batch<'a> {
    name: String,
    txs: Vec<Vec<u8>>,
    others: Vec<Vec<u8>>,
    parents: Vec<(&'a SP1ProofWithPublicValues, Vec<Claim>)>,
    expect: Vec<Claim>,
}

fn prove<P: Prover>(client: &P, pk: &P::ProvingKey, vk: &SP1VerifyingKey, b: &Batch, groth16: bool) -> Made {
    let vkey = vk.hash_u32();
    let mut stdin = SP1Stdin::new();
    stdin.write(&vkey);
    stdin.write(&b.txs);
    stdin.write(&b.others);
    stdin.write(&b.parents.iter().map(|(_, claims)| public_values(&vkey, claims)).collect::<Vec<_>>());
    for (proof, _) in &b.parents {
        let SP1Proof::Compressed(inner) = &proof.proof else { panic!("parent proofs are compressed") };
        stdin.write_proof(*inner.clone(), vk.vk.clone());
    }

    let name = if groth16 { format!("{}.groth16", b.name) } else { b.name.clone() };
    println!("proving {name} ({} transactions)…", b.txs.len());
    let started = Instant::now();
    let request = client.prove(pk, stdin);
    let proof = if groth16 { request.groth16().run() } else { request.compressed().run() }.expect("the batch proves");
    let seconds = started.elapsed().as_secs_f64();
    client.verify(&proof, vk, None).expect("the proof verifies");
    assert_eq!(proof.public_values.as_slice(), public_values(&vkey, &b.expect), "{name}: the proof commits the native claims");

    let path = root().join(format!("proofs/{name}.proof"));
    proof.save(&path).unwrap();
    let bytes = std::fs::metadata(&path).unwrap().len();
    println!("{name}: {seconds:.1} s, {bytes} bytes, verified");
    Made { proof, seconds, bytes }
}

/// The batch `batch-<length>`: a chain of `length` synthetic transfers from a deploy.
fn synthetic_batch<'a>(length: usize) -> Batch<'a> {
    let mut token = synthetic::Token::new(1_000_000);
    let deploy = token.deploy.clone();
    let txs = token.chain(&deploy, 1_000_000, length);
    let expect = bnt_step::batch(&txs, &token.others, &[]).unwrap();
    Batch { name: format!("batch-{length}"), txs, others: token.others, parents: vec![], expect }
}

fn save(results: &Value) {
    std::fs::write(root().join("proofs/results.json"), serde_json::to_string_pretty(results).unwrap() + "\n").unwrap();
    println!("{results:#}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str);
    std::fs::create_dir_all(root().join("proofs")).unwrap();
    let results_path = root().join("proofs/results.json");

    let client = ProverClient::builder().cpu().build();
    let started = Instant::now();
    let pk = client.setup(STEP_ELF).expect("setup");
    let vk = pk.verifying_key().clone();
    println!("setup {:.1} s, key {}", started.elapsed().as_secs_f64(), vk.bytes32());

    if mode == Some("batch") {
        let length: usize = args.get(1).and_then(|n| n.parse().ok()).expect("batch <transactions>");
        let made = prove(&client, &pk, &vk, &synthetic_batch(length), false);
        let mut results: Value = serde_json::from_str(&std::fs::read_to_string(&results_path).expect("prove the split and merge first")).unwrap();
        assert_eq!(results["vkey"].as_str(), Some(vk.bytes32().as_str()), "the split and merge were proved under this key");
        let mut batches: Vec<Value> = results["batches"].as_array().cloned().unwrap_or_default();
        batches.retain(|b| b["txs"].as_u64() != Some(length as u64));
        batches.push(json!({ "txs": length, "seconds": made.seconds, "bytes": made.bytes }));
        batches.sort_by_key(|b| b["txs"].as_u64());
        results["batches"] = json!(batches);
        save(&results);
        return;
    }

    let groth16 = mode == Some("groth16");
    let only_merge = groth16 || mode == Some("merge");
    let e = Evidence::load();
    let split_claim = e.claim("split", &[]);
    let merge_claim = e.claim("merge", &[split_claim.clone()]);
    let single = |role: &str, parents, expect: &Claim| Batch {
        name: role.to_string(),
        txs: vec![e.raw(role)],
        others: e.parents(role),
        parents,
        expect: vec![expect.clone()],
    };

    let split = if only_merge {
        let proof = SP1ProofWithPublicValues::load(root().join("proofs/split.proof")).expect("prove the split first");
        client.verify(&proof, &vk, None).expect("the saved split proof verifies under this key");
        let bytes = std::fs::metadata(root().join("proofs/split.proof")).unwrap().len();
        Made { proof, seconds: f64::NAN, bytes }
    } else {
        prove(&client, &pk, &vk, &single("split", vec![], &split_claim), false)
    };
    let merge = prove(&client, &pk, &vk, &single("merge", vec![(&split.proof, vec![split_claim.clone()])], &merge_claim), groth16);

    if groth16 {
        let mut result: Value = serde_json::from_str(&std::fs::read_to_string(&results_path).expect("compressed results first")).unwrap();
        assert_eq!(result["vkey"].as_str(), Some(vk.bytes32().as_str()), "the compressed proofs were made under this key");
        result["groth16"] = json!({ "txid": e.0["txs"]["merge"]["txid"], "seconds": merge.seconds, "bytes": merge.bytes, "verifies": "split" });
        save(&result);
        return;
    }

    save(&json!({
        "sp1": merge.proof.sp1_version,
        "vkey": vk.bytes32(),
        "mode": "compressed",
        "split": { "txid": e.0["txs"]["split"]["txid"], "seconds": split.seconds, "bytes": split.bytes },
        "merge": { "txid": e.0["txs"]["merge"]["txid"], "seconds": merge.seconds, "bytes": merge.bytes, "verifies": "split" },
    }));
}
