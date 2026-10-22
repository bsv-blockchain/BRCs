//! How much one step reads and how long it takes natively, as history grows:
//! a chain of transfers, each paying its fee from a fresh coin, and one
//! transaction that merges many branches.
//!
//!     cargo run --release --example chain

use bnt_step::script::{encode, Clause, Output, Rules};
use bnt_step::tx::{asset_id, txid, Tx, TxIn, TxOut, Txid};
use bnt_step::{public_values, step, Claim, Parent};
use std::time::Instant;

fn key(n: u32) -> [u8; 33] {
    let mut k = [0x11; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_le_bytes());
    k
}

fn clause(n: u32) -> Clause {
    Clause { holder: key(n), rules: Rules::Open }
}

/// `{"v": 1, "iss": <key>, "mode": "open"}`
fn payload() -> Vec<u8> {
    let mut p = vec![0xa3, 0x61, b'v', 0x01, 0x63, b'i', b's', b's', 0x58, 0x21];
    p.extend(key(0));
    p.extend([0x64, b'm', b'o', b'd', b'e', 0x64, b'o', b'p', b'e', b'n']);
    p
}

/// An input with a signature-sized unlock (72-byte signature), as a holder's would be.
fn input(prev: Txid, vout: u32) -> TxIn {
    let mut script = vec![72];
    script.extend([0x30; 72]);
    TxIn { prev_txid: prev, prev_vout: vout, script, sequence: u32::MAX }
}

fn p2pkh(n: u32) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend(&key(n)[..20]);
    s.extend([0x88, 0xac]);
    s
}

fn coin(n: u32) -> Tx {
    let mut unlock = vec![72];
    unlock.extend([0x30; 72]);
    unlock.push(33);
    unlock.extend(key(n));
    let prev = [n as u8; 32];
    Tx {
        version: 1,
        inputs: vec![TxIn { prev_txid: prev, prev_vout: 0, script: unlock, sequence: u32::MAX }],
        outputs: vec![TxOut { satoshis: 1000, script: p2pkh(n) }],
        locktime: 0,
    }
}

struct Proven {
    raw: Vec<u8>,
    claim: Claim,
}

/// Step `tx` from `token_parents` (proven) and a fee coin (raw only); returns the step's time and bytes read.
fn prove(tx: &Tx, token_parents: &[&Proven], coin: &Tx) -> (Proven, u128, usize) {
    let raw = tx.encode();
    let coin_raw = coin.encode();
    let mut parents: Vec<Parent> = token_parents.iter().map(|p| Parent::parse(&p.raw).unwrap()).collect();
    parents.push(Parent::parse(&coin_raw).unwrap());
    let claims: Vec<Claim> = token_parents.iter().map(|p| p.claim.clone()).collect();
    let read = raw.len()
        + coin_raw.len()
        + token_parents.iter().map(|p| p.raw.len() + public_values(&[0; 8], std::slice::from_ref(&p.claim)).len()).sum::<usize>();
    let runs = 200;
    let start = Instant::now();
    let mut claim = None;
    for _ in 0..runs {
        claim = Some(step(&raw, &parents, &claims).unwrap());
    }
    let micros = start.elapsed().as_micros() / runs;
    (Proven { raw, claim: claim.unwrap() }, micros, read)
}

fn main() {
    let funding = coin(0);
    let deploy = Tx {
        version: 1,
        inputs: vec![input(txid(&funding.encode()), 0)],
        outputs: vec![TxOut {
            satoshis: 1,
            script: encode(&Output::Deploy { supply: 1_000_000, payload: payload(), clause: clause(1) }).unwrap(),
        }],
        locktime: 0,
    };
    let deploy_raw = deploy.encode();
    let asset = asset_id(&txid(&deploy_raw), 0).unwrap();
    let deploy = Proven { claim: Claim { txid: txid(&deploy_raw), assets: vec![] }, raw: deploy_raw };

    let held = |amount: u64, holder: u32| encode(&Output::Held { asset, amount, clause: clause(holder) }).unwrap();
    let transfer = |prev: &Proven, vouts: &[u32], fee: &Tx, outs: Vec<TxOut>| Tx {
        version: 1,
        inputs: vouts.iter().map(|v| input(txid(&prev.raw), *v)).chain([input(txid(&fee.encode()), 0)]).collect(),
        outputs: outs,
        locktime: 0,
    };

    println!("chain of transfers");
    println!("{:>6} {:>9} {:>11} {:>9} {:>8}", "hop", "tx bytes", "bytes read", "step µs", "claimed");
    let mut prev = deploy;
    let checkpoints = [1usize, 10, 100, 1000, 5000];
    for hop in 1..=5000u32 {
        let fee = coin(hop);
        let tx = transfer(&prev, &[0], &fee, vec![
            TxOut { satoshis: 1, script: held(1_000_000, hop + 1) },
            TxOut { satoshis: 800, script: p2pkh(hop) },
        ]);
        let (proven, micros, read) = prove(&tx, &[&prev], &fee);
        assert_eq!(proven.claim.assets.len(), 1, "hop {hop} keeps the asset");
        if checkpoints.contains(&(hop as usize)) {
            println!("{hop:>6} {:>9} {read:>11} {micros:>9} {:>8}", proven.raw.len(), proven.claim.assets.len());
        }
        prev = proven;
    }

    // Sixteen branches, each its own long history, merged in one transaction.
    let width = 16u32;
    let fee = coin(90_000);
    let split = transfer(&prev, &[0], &fee, (0..width).map(|i| TxOut { satoshis: 1, script: held(1_000_000 / width as u64, 100 + i) }).collect());
    let (split, _, _) = prove(&split, &[&prev], &fee);
    let mut branches: Vec<Proven> = Vec::new();
    for b in 0..width {
        let mut tip = None::<Proven>;
        for hop in 0..200u32 {
            let fee = coin(100_000 + b * 1000 + hop);
            let (from, vout) = match &tip { Some(t) => (t, 0), None => (&split, b) };
            let tx = transfer(from, &[vout], &fee, vec![TxOut { satoshis: 1, script: held(1_000_000 / width as u64, 200 + b) }]);
            tip = Some(prove(&tx, &[from], &fee).0);
        }
        branches.push(tip.unwrap());
    }
    let fee = coin(999_999);
    let merge = Tx {
        version: 1,
        inputs: branches.iter().map(|b| input(txid(&b.raw), 0)).chain([input(txid(&fee.encode()), 0)]).collect(),
        outputs: vec![TxOut { satoshis: 1, script: held(1_000_000, 7) }],
        locktime: 0,
    };
    let refs: Vec<&Proven> = branches.iter().collect();
    let (merged, micros, read) = prove(&merge, &refs, &fee);
    assert_eq!(merged.claim.assets.len(), 1);
    println!("\nmerge of {width} branches, {} transactions of history behind it", 5000 + 1 + width * 200);
    println!("{:>9} {:>11} {:>9} {:>14}", "tx bytes", "bytes read", "step µs", "parent proofs");
    println!("{:>9} {read:>11} {micros:>9} {width:>14}", merged.raw.len());
    println!("\nclaim: {} bytes; public values: {} bytes", merged.claim.encode().len(), public_values(&[0; 8], std::slice::from_ref(&merged.claim)).len());
}
