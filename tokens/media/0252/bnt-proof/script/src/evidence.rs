//! The E2E token's pinned mainnet transactions (`experiment/mainnet.json`),
//! shared by the `prove` and `verify` binaries.

use std::path::{Path, PathBuf};

use bnt_step::tx::{parse_tx, Txid};
use bnt_step::{step, Claim, Parent};
use serde_json::Value;

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub struct Evidence(pub Value);

impl Evidence {
    pub fn load() -> Self {
        let text = std::fs::read_to_string(root().join("experiment/mainnet.json")).expect("run node experiment/fetch.mjs");
        Evidence(serde_json::from_str(&text).unwrap())
    }

    pub fn raw(&self, role: &str) -> Vec<u8> {
        hex::decode(self.0["txs"][role]["hex"].as_str().unwrap()).unwrap()
    }

    /// Every distinct parent of the transaction, raw, in input order.
    pub fn parents(&self, role: &str) -> Vec<Vec<u8>> {
        let tx = parse_tx(&self.raw(role)).unwrap();
        let mut seen: Vec<Txid> = Vec::new();
        let mut out = Vec::new();
        for input in &tx.inputs {
            if seen.contains(&input.prev_txid) {
                continue;
            }
            seen.push(input.prev_txid);
            let mut id = input.prev_txid;
            id.reverse();
            let hex = self.0["parents"][hex::encode(id)].as_str().expect("parent pinned");
            out.push(hex::decode(hex).unwrap());
        }
        out
    }

    pub fn claim(&self, role: &str, parent_claims: &[Claim]) -> Claim {
        let parents: Vec<Parent> = self.parents(role).iter().map(|r| Parent::parse(r).unwrap()).collect();
        step(&self.raw(role), &parents, parent_claims).unwrap()
    }
}
