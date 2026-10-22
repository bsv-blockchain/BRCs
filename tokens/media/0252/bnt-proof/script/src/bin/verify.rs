//! Checks the published step proofs: the published program binary has the key
//! `proofs/results.json` names, each proof verifies under that key, commits the
//! claims the plain-Rust step computes from the pinned mainnet transactions or
//! the synthetic batch it names, and has the size `results.json` reports.
//!
//!     cargo run --release --bin verify

use bnt_step::{batch, public_values, Claim};
use serde_json::Value;
use sp1_sdk::blocking::prelude::*;
use sp1_sdk::blocking::ProverClient;

#[path = "../evidence.rs"]
mod evidence;
use evidence::{root, Evidence};
#[path = "../synthetic.rs"]
#[allow(dead_code)]
mod synthetic;

const SOURCE_ELF: Elf = include_elf!("bnt-step-program");

fn main() {
    let results: Value = serde_json::from_str(&std::fs::read_to_string(root().join("proofs/results.json")).unwrap()).unwrap();
    let published = std::fs::read(root().join("proofs/bnt-step-program.elf")).expect("the published program binary");
    println!("program built from this source is byte-identical to the published binary: {}", *SOURCE_ELF == published[..]);

    let client = ProverClient::builder().cpu().build();
    let pk = client.setup(Elf::from(published)).expect("setup");
    let vk = pk.verifying_key();
    assert_eq!(results["vkey"].as_str(), Some(vk.bytes32().as_str()), "the published binary has the published key");
    println!("key {}", vk.bytes32());

    let e = Evidence::load();
    let vkey = vk.hash_u32();
    let split = e.claim("split", &[]);
    let merge = e.claim("merge", &[split.clone()]);

    let check = |file: &str, what: &str, claims: &[Claim], bytes_reported: Option<u64>| {
        let path = root().join("proofs").join(file);
        let proof = SP1ProofWithPublicValues::load(&path).unwrap();
        client.verify(&proof, vk, None).unwrap_or_else(|err| panic!("{file} verifies: {err}"));
        assert_eq!(proof.public_values.as_slice(), public_values(&vkey, claims), "{file} commits the {what} claims");
        let bytes = std::fs::metadata(&path).unwrap().len();
        assert_eq!(bytes_reported, Some(bytes), "{file} has the size results.json reports");
        println!("{file}: verifies, commits the {what} claims, {bytes} bytes");
    };

    for (file, role, claim, entry) in [
        ("split.proof", "split", &split, "split"),
        ("merge.proof", "merge", &merge, "merge"),
        ("merge.groth16.proof", "merge", &merge, "groth16"),
    ] {
        if entry == "groth16" && !root().join("proofs").join(file).exists() {
            println!("{file}: not made yet");
            continue;
        }
        assert_eq!(results[entry]["txid"], e.0["txs"][role]["txid"], "{file} is the proof of the {role}");
        check(file, role, std::slice::from_ref(claim), results[entry]["bytes"].as_u64());
    }

    for entry in results["batches"].as_array().into_iter().flatten() {
        let length = entry["txs"].as_u64().unwrap() as usize;
        let mut token = synthetic::Token::new(1_000_000);
        let deploy = token.deploy.clone();
        let txs = token.chain(&deploy, 1_000_000, length);
        let claims = batch(&txs, &token.others, &[]).unwrap();
        check(&format!("batch-{length}.proof"), &format!("chain of {length}"), &claims, entry["bytes"].as_u64());
    }
}
