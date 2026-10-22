//! Runs the step program in SP1 without proving and reports its cycles: chains
//! of transfers proved as one batch, and a split into 16 then a merge of 16
//! proved one transaction at a time. Parent proofs are not checked here: their
//! cost lands in recursion, not in the program's cycles.
//!
//!     cargo run --release

use bnt_step::{batch, public_values, read_public_values, Claim};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, SP1Stdin};

#[allow(dead_code)]
mod synthetic;
use synthetic::Token;

const STEP_ELF: Elf = include_elf!("bnt-step-program");
const VKEY: [u32; 8] = [7; 8];

/// Batches `txs` natively, then runs the program on the same inputs and checks it commits the same claims.
fn run(client: &impl Prover, label: &str, txs: &[Vec<u8>], others: &[Vec<u8>], proven: &[Claim]) -> Vec<Claim> {
    let claims = batch(txs, others, proven).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write(&VKEY);
    stdin.write(&txs.to_vec());
    stdin.write(&others.to_vec());
    stdin.write(&proven.iter().map(|c| public_values(&VKEY, std::slice::from_ref(c))).collect::<Vec<_>>());
    let (output, report) = client.execute(STEP_ELF, stdin).deferred_proof_verification(false).run().unwrap();
    let (_, committed) = read_public_values(output.as_slice()).unwrap();
    assert_eq!(committed, claims, "{label}: the program and the native batch agree");
    let cycles = report.total_instruction_count();
    println!("{label:<24} {:>5} {:>6} {:>13} {:>11}", txs.len(), proven.len(), cycles, cycles / txs.len() as u64);
    claims
}

fn main() {
    let client = ProverClient::builder().cpu().build();
    println!("{:<24} {:>5} {:>6} {:>13} {:>11}", "batch", "txs", "proofs", "cycles", "per tx");

    for length in [1, 10, 100, 1000] {
        let mut token = Token::new(1_000_000);
        let deploy = token.deploy.clone();
        let txs = token.chain(&deploy, 1_000_000, length);
        run(&client, &format!("chain of {length}"), &txs, &token.others, &[]);
    }

    let width = 16u64;
    let mut token = Token::new(1_000_000);
    let deploy = token.deploy.clone();
    let first = token.chain(&deploy, 1_000_000, 1);
    let first_claims = run(&client, "transfer", &first, &token.others, &[]);
    let split = token.spend(&[(&first[0], 0)], &vec![1_000_000 / width; width as usize]);
    let split_claims = run(&client, "split into 16", std::slice::from_ref(&split), &[token.others.clone(), first.clone()].concat(), &first_claims);
    let branches: Vec<Vec<u8>> = (0..width as u32).map(|b| token.spend(&[(&split, b)], &[1_000_000 / width])).collect();
    let branch_claims = batch(&branches, &[token.others.clone(), vec![split.clone()]].concat(), &split_claims).unwrap();
    let refs: Vec<(&Vec<u8>, u32)> = branches.iter().map(|b| (b, 0)).collect();
    let merge = token.spend(&refs, &[1_000_000]);
    run(&client, "merge of 16", std::slice::from_ref(&merge), &[token.others.clone(), branches.clone()].concat(), &branch_claims);
}
