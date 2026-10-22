//! Many steps in one proof. The batch proves its transactions in order, each
//! from the claims of earlier batch members and of the proofs it was given, and
//! returns the claims a later transaction can still need: those of members
//! with an asset output that no later member spends. A chain of transfers
//! therefore commits one claim however long it is, and a batch of one commits
//! exactly what a single step does.

use std::collections::{BTreeMap, BTreeSet};

use crate::journal::Claim;
use crate::script;
use crate::step::{step_parsed, StepError};
use crate::tx::{parse_tx, txid, Tx, Txid};

/// Prove `txs` in order. `others` holds every parent that is not a member, raw,
/// and `proven` the claims of the proofs the batch verified.
pub fn batch(txs: &[Vec<u8>], others: &[Vec<u8>], proven: &[Claim]) -> Result<Vec<Claim>, StepError> {
    let mut pool: BTreeMap<Txid, Tx> = BTreeMap::new();
    for raw in others {
        pool.insert(txid(raw), parse_tx(raw).ok_or(StepError::Malformed)?);
    }
    let mut known: BTreeMap<Txid, Claim> = proven.iter().map(|c| (c.txid, c.clone())).collect();
    let mut spent: BTreeSet<(Txid, u32)> = BTreeSet::new();
    let mut order: Vec<Txid> = Vec::with_capacity(txs.len());

    for raw in txs {
        let tx = parse_tx(raw).ok_or(StepError::Malformed)?;
        let id = txid(raw);
        if pool.contains_key(&id) {
            return Err(StepError::Duplicate);
        }
        let mut claims: Vec<Claim> = Vec::new();
        for input in &tx.inputs {
            spent.insert((input.prev_txid, input.prev_vout));
            if let Some(claim) = known.get(&input.prev_txid) {
                if !claims.iter().any(|c| c.txid == claim.txid) {
                    claims.push(claim.clone());
                }
            }
        }
        let claim = step_parsed(&tx, id, |parent| pool.get(parent), &claims)?;
        known.insert(id, claim);
        pool.insert(id, tx);
        order.push(id);
    }

    Ok(order
        .iter()
        .filter_map(|id| {
            let claim = &known[id];
            let tx = &pool[id];
            let open = tx.outputs.iter().enumerate().any(|(vout, out)| {
                script::named_asset(&out.script).is_some_and(|asset| claim.rules_of(&asset).is_some())
                    && !spent.contains(&(*id, vout as u32))
            });
            open.then(|| claim.clone())
        })
        .collect())
}
