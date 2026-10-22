//! Replays vectors the HandCash Desktop wallet generated and judged with its own
//! BRC-255 rules (`src/wallet/bnt/proofVectors.test.ts`). Each step proves one
//! transaction from its parents' claims; a recipient credits an asset when the
//! claim names it and the deploy checks out, which must match the full walk.

use bnt_step::script::{self, Output, Rules};
use bnt_step::{payload, step, Claim, Parent};
use serde_json::{json, Value};
use std::collections::HashMap;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/desktop.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vectors/desktop.json")).unwrap()
}

fn display(txid: &[u8; 32]) -> String {
    let mut id = *txid;
    id.reverse();
    hex::encode(id)
}

fn mode(rules: &Rules) -> &'static str {
    match rules {
        Rules::Open => "open",
        Rules::Countersign { .. } => "countersign",
    }
}

fn script_summary(hex_script: &str) -> Value {
    match script::read(&hex::decode(hex_script).unwrap()) {
        None => Value::Null,
        Some(Output::Deploy { supply, payload, clause }) => {
            json!({ "form": "deploy", "mode": mode(&clause.rules), "supply": supply.to_string(), "payload": hex::encode(payload) })
        }
        Some(Output::Held { asset, amount, clause }) => {
            json!({ "form": "held", "mode": mode(&clause.rules), "asset": hex::encode(asset), "amount": amount.to_string() })
        }
        Some(Output::Authority { asset, clause, issued }) => json!({
            "form": "authority",
            "mode": mode(&clause.rules),
            "asset": hex::encode(asset),
            "units": issued.map(|i| i.units.to_string()),
            "members": issued.map(|i| i.members.to_string()),
        }),
    }
}

fn payload_summary(hex_payload: &str) -> Value {
    match payload::decode(&hex::decode(hex_payload).unwrap()) {
        None => Value::Null,
        Some(f) => json!({
            "open": f.open,
            "item": f.item,
            "auth": f.auth,
            "max": f.max.map(|n| n.to_string()),
            "size": f.size.map(|n| n.to_string()),
            "col": f.col.map(hex::encode),
            "backed": f.backed,
        }),
    }
}

#[test]
fn reads_scripts_as_the_wallet_does() {
    let v = vectors();
    let scripts = v["scripts"].as_array().unwrap();
    let mut read = 0;
    for s in scripts {
        let hex_script = s["hex"].as_str().unwrap();
        assert_eq!(script_summary(hex_script), s["read"], "script {hex_script}");
        read += !s["read"].is_null() as usize;
    }
    println!("{} scripts, {read} read as outputs", scripts.len());
}

#[test]
fn reads_payloads_as_the_wallet_does() {
    let v = vectors();
    let payloads = v["payloads"].as_array().unwrap();
    let mut read = 0;
    for p in payloads {
        let hex_payload = p["hex"].as_str().unwrap();
        assert_eq!(payload_summary(hex_payload), p["fields"], "payload {hex_payload}");
        read += !p["fields"].is_null() as usize;
    }
    println!("{} payloads, {read} valid", payloads.len());
}

#[test]
fn proves_what_the_walk_validates() {
    let v = vectors();
    let (mut credited, mut refused) = (0, 0);
    for scenario in v["scenarios"].as_array().unwrap() {
        let name = scenario["name"].as_str().unwrap();
        let raw: HashMap<&str, Vec<u8>> =
            scenario["txs"].as_object().unwrap().iter().map(|(id, hex)| (id.as_str(), hex::decode(hex.as_str().unwrap()).unwrap())).collect();
        let mut claims: HashMap<String, Claim> = HashMap::new();
        for id in scenario["order"].as_array().unwrap() {
            let id = id.as_str().unwrap();
            let tx = bnt_step::tx::parse_tx(&raw[id]).unwrap();
            let mut parents: Vec<Parent> = Vec::new();
            let mut parent_claims: Vec<Claim> = Vec::new();
            for input in &tx.inputs {
                let pid = display(&input.prev_txid);
                if parents.iter().any(|p| p.txid == input.prev_txid) {
                    continue;
                }
                parents.push(Parent::parse(&raw[pid.as_str()]).unwrap());
                parent_claims.push(claims[&pid].clone());
            }
            let claim = step(&raw[id], &parents, &parent_claims).unwrap_or_else(|e| panic!("{name}: {id}: {e:?}"));
            assert_eq!(display(&claim.txid), id);
            assert_eq!(Claim::decode(&claim.encode()).as_ref(), Some(&claim));
            claims.insert(id.to_string(), claim);
        }
        for e in scenario["expect"].as_array().unwrap() {
            let (id, asset) = (e["txid"].as_str().unwrap(), e["asset"].as_str().unwrap());
            let asset: [u8; 20] = hex::decode(asset).unwrap().try_into().unwrap();
            let proven = claims[id].rules_of(&asset).is_some() && e["deployOk"].as_bool().unwrap();
            assert_eq!(proven, e["valid"].as_bool().unwrap(), "{name}: {id} for asset {}", hex::encode(asset));
            if proven {
                credited += 1;
            } else {
                refused += 1;
            }
        }
    }
    println!("{credited} credited and {refused} refused, as the walk decides");
}
