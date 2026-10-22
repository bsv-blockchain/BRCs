//! A batch proves the same claims as one step after another, and commits only
//! the claims a later transaction can still need.

use bnt_step::script::{encode, Clause, Output, Rules};
use bnt_step::tx::{asset_id, txid, AssetId, Tx, TxIn, TxOut, Txid};
use bnt_step::{batch, step, Claim, Parent, StepError};

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

fn input(prev: Txid, vout: u32) -> TxIn {
    TxIn { prev_txid: prev, prev_vout: vout, script: vec![0x51], sequence: u32::MAX }
}

fn coin(n: u32) -> Vec<u8> {
    let mut script = vec![0x76, 0xa9, 0x14];
    script.extend(&key(n)[..20]);
    script.extend([0x88, 0xac]);
    Tx { version: 1, inputs: vec![input([n as u8; 32], 0)], outputs: vec![TxOut { satoshis: 1000, script }], locktime: 0 }.encode()
}

struct Token {
    deploy: Vec<u8>,
    asset: AssetId,
    coins: Vec<Vec<u8>>,
}

impl Token {
    fn new() -> Token {
        let funding = coin(0);
        let deploy = Tx {
            version: 1,
            inputs: vec![input(txid(&funding), 0)],
            outputs: vec![TxOut {
                satoshis: 1,
                script: encode(&Output::Deploy { supply: 1000, payload: payload(), clause: clause(1) }).unwrap(),
            }],
            locktime: 0,
        }
        .encode();
        let asset = asset_id(&txid(&deploy), 0).unwrap();
        Token { deploy, asset, coins: vec![funding] }
    }

    /// Spends `from` with a fresh fee coin and writes `amounts`, one output each.
    fn spend(&mut self, from: &[(&Vec<u8>, u32)], amounts: &[u64]) -> Vec<u8> {
        let fee = coin(self.coins.len() as u32 + 1);
        let mut inputs: Vec<TxIn> = from.iter().map(|(raw, vout)| input(txid(raw), *vout)).collect();
        inputs.push(input(txid(&fee), 0));
        let outputs = amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| TxOut {
                satoshis: 1,
                script: encode(&Output::Held { asset: self.asset, amount, clause: clause(10 + i as u32) }).unwrap(),
            })
            .collect();
        self.coins.push(fee);
        Tx { version: 1, inputs, outputs, locktime: 0 }.encode()
    }

    /// Every raw transaction that is not a member of `members`.
    fn others(&self, members: &[Vec<u8>], all: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut out = vec![self.deploy.clone()];
        out.extend(self.coins.iter().cloned());
        out.extend(all.iter().filter(|raw| !members.contains(raw)).cloned());
        out
    }
}

/// The claims of `txs` proved one step at a time.
fn one_by_one(token: &Token, txs: &[Vec<u8>]) -> Vec<Claim> {
    let mut pool: Vec<Vec<u8>> = token.others(&[], &[]);
    let mut claims: Vec<Claim> = Vec::new();
    for raw in txs {
        let parents: Vec<Parent> = pool.iter().map(|r| Parent::parse(r).unwrap()).collect();
        let tx = bnt_step::tx::parse_tx(raw).unwrap();
        let mine: Vec<Claim> =
            claims.iter().filter(|c| tx.inputs.iter().any(|i| i.prev_txid == c.txid)).cloned().collect();
        claims.push(step(raw, &parents, &mine).unwrap());
        pool.push(raw.clone());
    }
    claims
}

fn chain(token: &mut Token, length: usize) -> Vec<Vec<u8>> {
    let mut txs: Vec<Vec<u8>> = Vec::new();
    let mut prev = token.deploy.clone();
    for _ in 0..length {
        let next = token.spend(&[(&prev, 0)], &[1000]);
        txs.push(next.clone());
        prev = next;
    }
    txs
}

#[test]
fn a_chain_commits_only_its_last_claim() {
    let mut token = Token::new();
    let txs = chain(&mut token, 20);
    let expected = one_by_one(&token, &txs);
    let committed = batch(&txs, &token.others(&txs, &txs), &[]).unwrap();
    assert_eq!(committed, vec![expected.last().unwrap().clone()]);
    assert_eq!(committed[0].rules_of(&token.asset).map(|r| r.auth), Some(false));
}

#[test]
fn a_batch_of_one_is_a_step() {
    let mut token = Token::new();
    let txs = chain(&mut token, 1);
    assert_eq!(batch(&txs, &token.others(&txs, &txs), &[]).unwrap(), one_by_one(&token, &txs));
}

#[test]
fn a_batch_continues_from_an_earlier_batch() {
    let mut token = Token::new();
    let txs = chain(&mut token, 12);
    let (first, second) = txs.split_at(5);
    let earlier = batch(first, &token.others(first, &txs), &[]).unwrap();
    let later = batch(second, &token.others(second, &txs), &earlier).unwrap();
    assert_eq!(later, batch(&txs, &token.others(&txs, &txs), &[]).unwrap());
}

#[test]
fn unspent_branches_keep_their_claims() {
    let mut token = Token::new();
    let deploy = token.deploy.clone();
    let split = token.spend(&[(&deploy, 0)], &[600, 300, 100]);
    let onward = token.spend(&[(&split, 1)], &[300]);
    let txs = vec![split.clone(), onward.clone()];
    let committed = batch(&txs, &token.others(&txs, &txs), &[]).unwrap();
    assert_eq!(committed, one_by_one(&token, &txs));

    let merge = token.spend(&[(&split, 0), (&split, 2), (&onward, 0)], &[1000]);
    let txs = vec![split, onward, merge];
    let committed = batch(&txs, &token.others(&txs, &txs), &[]).unwrap();
    assert_eq!(committed, vec![one_by_one(&token, &txs)[2].clone()]);
}

#[test]
fn conjured_units_end_the_claim_for_the_rest_of_the_batch() {
    let mut token = Token::new();
    let deploy = token.deploy.clone();
    let good = token.spend(&[(&deploy, 0)], &[1000]);
    let conjured = token.spend(&[(&good, 0)], &[1001]);
    let after = token.spend(&[(&conjured, 0)], &[1001]);
    let txs = vec![good, conjured, after];
    assert_eq!(batch(&txs, &token.others(&txs, &txs), &[]).unwrap(), vec![]);
}

#[test]
fn a_transaction_named_twice_is_refused() {
    let mut token = Token::new();
    let mut txs = chain(&mut token, 2);
    txs.push(txs[0].clone());
    assert_eq!(batch(&txs, &token.others(&txs, &txs), &[]), Err(StepError::Duplicate));
    let one = &txs[..1];
    let mut others = token.others(one, &txs);
    others.push(txs[0].clone());
    assert_eq!(batch(one, &others, &[]), Err(StepError::Duplicate));
}
