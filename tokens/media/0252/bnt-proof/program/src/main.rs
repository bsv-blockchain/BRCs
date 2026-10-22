//! The BRC-252 step program: proves a batch of transactions' claims from the
//! proofs of the parents outside the batch. Inputs, in order: this program's
//! verifying key digest, the batch's raw transactions in order, every other
//! parent raw, and the public values of each proof the prover supplies (the
//! proofs ride the proof input stream).

#![no_main]
sp1_zkvm::entrypoint!(main);

use bnt_step::{batch, public_values, read_public_values};
use sha2::{Digest, Sha256};

pub fn main() {
    println!("cycle-tracker-start: read");
    let vkey = sp1_zkvm::io::read::<[u32; 8]>();
    let txs = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let others = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    let proven = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    println!("cycle-tracker-end: read");

    println!("cycle-tracker-start: claims");
    let mut claims = Vec::new();
    for values in &proven {
        sp1_zkvm::lib::verify::verify_sp1_proof(&vkey, &Sha256::digest(values).into());
        let (made_under, made) = read_public_values(values).expect("a proof commits claims");
        assert_eq!(made_under, vkey, "a parent proof was made under another program");
        claims.extend(made);
    }
    println!("cycle-tracker-end: claims");
    println!("cycle-tracker-start: batch");
    let committed = batch(&txs, &others, &claims).expect("the batch reads its transactions");
    println!("cycle-tracker-end: batch");
    sp1_zkvm::io::commit_slice(&public_values(&vkey, &committed));
}
