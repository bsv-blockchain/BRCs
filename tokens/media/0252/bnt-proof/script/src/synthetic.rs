//! Synthetic BNT transactions for measuring batches: a deploy, then transfers
//! that each pay their fee from a fresh coin and keep change, the shape of the
//! E2E token's split. They are the same every run, so a proof of them can be
//! checked by building them again.

use bnt_step::script::{encode, Clause, Output, Rules};
use bnt_step::tx::{asset_id, txid, AssetId, Tx, TxIn, TxOut, Txid};

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

fn coin(n: u32) -> Vec<u8> {
    Tx {
        version: 1,
        inputs: vec![input([n as u8; 32], n)],
        outputs: vec![TxOut { satoshis: 1000, script: p2pkh(n) }],
        locktime: 0,
    }
    .encode()
}

pub struct Token {
    pub deploy: Vec<u8>,
    pub asset: AssetId,
    /// Every parent that is not a token transaction: the deploy and the fee coins.
    pub others: Vec<Vec<u8>>,
}

impl Token {
    pub fn new(supply: u64) -> Token {
        let funding = coin(0);
        let deploy = Tx {
            version: 1,
            inputs: vec![input(txid(&funding), 0)],
            outputs: vec![TxOut {
                satoshis: 1,
                script: encode(&Output::Deploy { supply, payload: payload(), clause: clause(1) }).unwrap(),
            }],
            locktime: 0,
        }
        .encode();
        let asset = asset_id(&txid(&deploy), 0).unwrap();
        Token { others: vec![funding, deploy.clone()], deploy, asset }
    }

    /// Spends `from` and a fresh fee coin, writing one output per amount and change.
    pub fn spend(&mut self, from: &[(&Vec<u8>, u32)], amounts: &[u64]) -> Vec<u8> {
        let n = self.others.len() as u32;
        let fee = coin(n);
        let mut inputs: Vec<TxIn> = from.iter().map(|(raw, vout)| input(txid(raw), *vout)).collect();
        inputs.push(input(txid(&fee), 0));
        let mut outputs: Vec<TxOut> = amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| TxOut {
                satoshis: 1,
                script: encode(&Output::Held { asset: self.asset, amount, clause: clause(n * 32 + i as u32) }).unwrap(),
            })
            .collect();
        outputs.push(TxOut { satoshis: 900, script: p2pkh(n) });
        self.others.push(fee);
        Tx { version: 1, inputs, outputs, locktime: 0 }.encode()
    }

    /// `length` transfers of the whole supply, the first spending `from`'s output 0.
    pub fn chain(&mut self, from: &Vec<u8>, amount: u64, length: usize) -> Vec<Vec<u8>> {
        let mut txs: Vec<Vec<u8>> = Vec::with_capacity(length);
        let mut prev = from.clone();
        for _ in 0..length {
            prev = self.spend(&[(&prev, 0)], &[amount]);
            txs.push(prev.clone());
        }
        txs
    }
}
