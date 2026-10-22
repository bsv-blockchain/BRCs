//! The token half of the E2E experiment, on the pinned mainnet evidence in
//! `experiment/mainnet.json`: the recipient's walk from the merge back to the
//! deploy, the output bytes, and tampered copies the walk must refuse. The
//! Bitcoin half (SPV, scripts, the issuer's signature) is
//! `experiment/chain.test.mjs`.

use bnt_step::script::{self, Clause, Output, Rules};
use bnt_step::tx::{asset_id, parse_tx, Tx, TxIn, TxOut, Txid};
use bnt_step::{payload, step, Claim, Parent};
use serde_json::Value;

struct Evidence {
    json: Value,
    asset: [u8; 20],
}

fn evidence() -> Evidence {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../experiment/mainnet.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("run node experiment/fetch.mjs")).unwrap();
    let asset = hex::decode(json["asset"].as_str().unwrap()).unwrap().try_into().unwrap();
    Evidence { json, asset }
}

impl Evidence {
    fn raw(&self, role: &str) -> Vec<u8> {
        hex::decode(self.json["txs"][role]["hex"].as_str().unwrap()).unwrap()
    }

    fn tx(&self, role: &str) -> Tx {
        parse_tx(&self.raw(role)).unwrap()
    }

    /// Every parent of `tx`, raw, from the token transactions or the pinned parents.
    fn parents(&self, tx: &Tx) -> Vec<Parent> {
        let mut out: Vec<Parent> = Vec::new();
        for input in &tx.inputs {
            if out.iter().any(|p| p.txid == input.prev_txid) {
                continue;
            }
            let hex = self.json["parents"][display(&input.prev_txid)].as_str().expect("parent pinned");
            out.push(Parent::parse(&hex::decode(hex).unwrap()).unwrap());
        }
        out
    }
}

fn display(txid: &Txid) -> String {
    let mut id = *txid;
    id.reverse();
    hex::encode(id)
}

fn held(asset: [u8; 20], amount: u64, holder: u8) -> Vec<u8> {
    let mut key = [holder; 33];
    key[0] = 0x02;
    script::encode(&Output::Held { asset, amount, clause: Clause { holder: key, rules: Rules::Open } }).unwrap()
}

fn amounts(tx: &Tx, asset: &[u8; 20]) -> Vec<u64> {
    tx.outputs
        .iter()
        .filter_map(|o| match script::read(&o.script) {
            Some(Output::Held { asset: a, amount, .. }) if a == *asset => Some(amount),
            _ => None,
        })
        .collect()
}

/// The recipient's own check of the deploy (BRC-255 §2): its outpoint hashes to
/// the asset id and its payload is an open asset. The issuer's signature is
/// checked in chain.test.mjs.
fn deploy_checks_out(e: &Evidence) -> u64 {
    let deploy = e.tx("deploy");
    let txid = bnt_step::tx::txid(&e.raw("deploy"));
    assert_eq!(asset_id(&txid, 0), Some(e.asset), "the deploy outpoint hashes to the asset id");
    let Some(Output::Deploy { supply, payload, clause }) = script::read(&deploy.outputs[0].script) else { panic!("output 0 is a deploy") };
    let fields = payload::decode(&payload).expect("the payload is valid");
    assert!(fields.open && !fields.item && !fields.auth && clause.rules == Rules::Open);
    supply
}

/// The walk: deploy, then each later hop stepped once from its parents' claims.
fn walk(e: &Evidence) -> (Claim, Claim) {
    let split = e.tx("split");
    let split_claim = step(&e.raw("split"), &e.parents(&split), &[]).unwrap();
    let merge = e.tx("merge");
    let merge_claim = step(&e.raw("merge"), &e.parents(&merge), &[split_claim.clone()]).unwrap();
    (split_claim, merge_claim)
}

#[test]
fn the_recipient_walk_credits_the_merge_from_transaction_bodies() {
    let e = evidence();
    assert_eq!(deploy_checks_out(&e), 1000);
    let (split_claim, merge_claim) = walk(&e);
    assert!(split_claim.rules_of(&e.asset).is_some(), "the split carries the asset");
    assert!(merge_claim.rules_of(&e.asset).is_some(), "the merge carries the asset");
    assert_eq!(amounts(&e.tx("split"), &e.asset), vec![250, 750]);
    assert_eq!(amounts(&e.tx("merge"), &e.asset), vec![1000]);
}

#[test]
fn each_output_is_marker_and_asset_then_amount_then_one_key() {
    let e = evidence();
    let mut outputs = 0;
    for role in ["split", "merge"] {
        for out in e.tx(role).outputs.iter().filter(|o| script::names_asset(&o.script, &e.asset)) {
            let s = &out.script;
            assert_eq!(s[0], 23, "one 23-byte push");
            assert_eq!(&s[1..4], b"bnt");
            assert_eq!(s[4..24], e.asset);
            let amount_bytes = s[24] as usize;
            assert_eq!(s[25 + amount_bytes], 0x6d, "OP_2DROP clears marker and amount");
            assert_eq!(&s[s.len() - 36..s.len() - 34], &[0x6d, 33], "then one 33-byte key");
            assert_eq!(s[s.len() - 1], 0xac, "and OP_CHECKSIG");
            assert_eq!(s.len(), 61 + amount_bytes, "the lock is 61 bytes plus the amount");
            assert_eq!(out.satoshis, 1);
            outputs += 1;
        }
    }
    assert_eq!(outputs, 3);
}

#[test]
fn the_split_is_the_452_byte_transfer_less_three_bytes_the_model_rounds_up() {
    let e = evidence();
    let split = e.tx("split");
    let size = |unlocks: &[usize], locks: &[usize]| 10 + unlocks.iter().map(|u| 41 + u).sum::<usize>() + locks.iter().map(|l| 9 + l).sum::<usize>();
    let unlocks: Vec<usize> = split.inputs.iter().map(|i| i.script.len()).collect();
    let locks: Vec<usize> = split.outputs.iter().map(|o| o.script.len()).collect();
    assert_eq!(size(&unlocks, &locks), e.raw("split").len(), "the byte accounting matches the raw transaction");
    assert_eq!(e.raw("split").len(), 449);
    // BRC-255 §12: a 73-byte token unlock, a 107-byte P2PKH funding unlock, two 64-byte token locks, P2PKH change.
    assert_eq!(size(&[73, 107], &[64, 64, 25]), 452);
    // On chain: a 72-byte signature and 2-byte amounts (250, 750) where the model allows 3.
    assert_eq!((unlocks.as_slice(), locks.as_slice()), (&[72, 107][..], &[63, 63, 25][..]));
}

#[test]
fn writing_more_or_fewer_units_than_spent_is_refused() {
    let e = evidence();
    let (split_claim, _) = walk(&e);
    let merge = e.tx("merge");
    for amount in [1001, 999] {
        let mut forged = merge.clone();
        forged.outputs[0].script = held(e.asset, amount, 7);
        let claim = step(&forged.encode(), &e.parents(&merge), &[split_claim.clone()]).unwrap();
        assert!(claim.rules_of(&e.asset).is_none(), "{amount} out of 1000 in");
    }
}

#[test]
fn a_hop_whose_parent_was_not_walked_is_not_credited() {
    let e = evidence();
    let merge = e.tx("merge");
    let claim = step(&e.raw("merge"), &e.parents(&merge), &[]).unwrap();
    assert!(claim.rules_of(&e.asset).is_none());
}

#[test]
fn units_written_from_nothing_are_refused() {
    let e = evidence();
    let coin = e.tx("split");
    let conjured = Tx {
        version: 1,
        inputs: vec![TxIn { prev_txid: bnt_step::tx::txid(&e.raw("split")), prev_vout: 2, script: vec![], sequence: u32::MAX }],
        outputs: vec![TxOut { satoshis: 1, script: held(e.asset, 1000, 9) }],
        locktime: 0,
    };
    let parents = [Parent::parse(&coin.encode()).unwrap()];
    let claim = step(&conjured.encode(), &parents, &[]).unwrap();
    assert!(claim.assets.is_empty(), "spending the split's fee change writes no asset");
}

#[test]
fn a_later_receipt_checks_only_the_new_hop() {
    let e = evidence();
    let (_, merge_claim) = walk(&e);
    let merge_raw = e.raw("merge");
    let next = Tx {
        version: 1,
        inputs: vec![
            TxIn { prev_txid: bnt_step::tx::txid(&merge_raw), prev_vout: 0, script: vec![], sequence: u32::MAX },
            TxIn { prev_txid: bnt_step::tx::txid(&merge_raw), prev_vout: 1, script: vec![], sequence: u32::MAX },
        ],
        outputs: vec![TxOut { satoshis: 1, script: held(e.asset, 400, 5) }, TxOut { satoshis: 1, script: held(e.asset, 600, 6) }],
        locktime: 0,
    };
    // Only the merge and its claim: no deploy, no split.
    let claim = step(&next.encode(), &[Parent::parse(&merge_raw).unwrap()], &[merge_claim]).unwrap();
    assert!(claim.rules_of(&e.asset).is_some());
}
