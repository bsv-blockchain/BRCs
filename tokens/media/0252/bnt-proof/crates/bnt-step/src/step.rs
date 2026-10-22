//! One proof step: the assets a transaction carries validly, given every parent
//! transaction and the proven claims of the parents that carry assets.
//!
//! This is BRC-255 §4 for each asset, with each parent's claim standing in for
//! the rest of the §7 walk. Script validation is left to Bitcoin: a claim is
//! used only for a transaction that is mined or accepted by miners, and then
//! every ancestor passed script validation too. Deploys are checked by the
//! recipient, who holds each one (§2, §3).

use crate::journal::{AssetRules, Claim, ProvenAsset};
use crate::payload;
use crate::script::{self, Issued, Output, Rules};
use crate::tx::{asset_id, parse_tx, txid, AssetId, Tx, Txid};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepError {
    /// The transaction does not parse.
    Malformed,
    /// A parent does not parse, or an input points past its parent's outputs.
    BadParent { vin: usize },
    /// No parent was supplied for this input.
    MissingParent { vin: usize },
    /// A claim was supplied for a transaction that is not a parent.
    StrayClaim,
    /// A batch names a transaction twice, or as both a member and a parent.
    Duplicate,
}

/// A parent as the prover supplies it: raw bytes, read once.
pub struct Parent {
    pub txid: Txid,
    pub tx: Tx,
}

impl Parent {
    pub fn parse(raw: &[u8]) -> Option<Parent> {
        Some(Parent { txid: txid(raw), tx: parse_tx(raw)? })
    }
}

struct Source<'a> {
    read: Option<Output>,
    /// The asset a deploy output starts, when the input spends one.
    deploy_of: Option<AssetId>,
    claim: Option<&'a Claim>,
}

struct AssetInput {
    amount: u64,
    authority: bool,
    issued: Option<Issued>,
}

struct AssetOutput {
    amount: u64,
    authority: bool,
    issued: Option<Issued>,
}

fn rules_from_deploy(read: &Output) -> Option<AssetRules> {
    let Output::Deploy { payload, clause, .. } = read else { return None };
    let fields = payload::decode(payload)?;
    // Countersigned assets are BRC-253 and backed ones need burial proofs: neither is proven here.
    if !fields.open || fields.backed || clause.rules != Rules::Open {
        return None;
    }
    Some(AssetRules { item: fields.item, auth: fields.auth, max: fields.max, size: fields.size })
}

/// Deploy outputs of `tx` whose payload names `collection` in `col`.
fn members_written(tx: &Tx, collection: &AssetId) -> u128 {
    tx.outputs
        .iter()
        .filter(|o| match script::read(&o.script) {
            Some(Output::Deploy { payload, .. }) => payload::decode(&payload).is_some_and(|f| f.col.as_ref() == Some(collection)),
            _ => false,
        })
        .count() as u128
}

/// §4 for one asset. `None` when the transaction does not carry it validly.
fn check_asset(tx: &Tx, sources: &[Source<'_>], asset: &AssetId) -> Option<AssetRules> {
    let mut rules: Option<AssetRules> = None;
    let mut inputs: Vec<AssetInput> = Vec::new();
    for source in sources {
        let Some(read) = &source.read else { continue };
        let (input, from) = match read {
            Output::Deploy { supply, .. } if source.deploy_of.as_ref() == Some(asset) => {
                // A deploy of another class still spends this asset, and fails closure below.
                let from = rules_from_deploy(read);
                let capped = from.as_ref().is_some_and(AssetRules::capped);
                let auth = from.as_ref().is_some_and(|r| r.auth);
                let issued = capped.then_some(Issued { units: *supply, members: 0 });
                (AssetInput { amount: *supply, authority: auth, issued }, from)
            }
            Output::Held { asset: a, amount, .. } if a == asset => {
                (AssetInput { amount: *amount, authority: false, issued: None }, source.claim.and_then(|c| c.rules_of(asset)))
            }
            Output::Authority { asset: a, issued, .. } if a == asset => {
                (AssetInput { amount: 0, authority: true, issued: *issued }, source.claim.and_then(|c| c.rules_of(asset)))
            }
            _ => continue,
        };
        // Closure: every input of the asset is under the open clause.
        if read.clause().rules != Rules::Open {
            return None;
        }
        // The parent must carry the asset validly; for the deploy, the recipient checks the deploy itself.
        let from = from?;
        if rules.as_ref().is_some_and(|r| *r != from) {
            return None;
        }
        rules = Some(from);
        inputs.push(input);
    }
    // No conjuring: nothing is written that was not spent.
    let rules = rules?;
    let capped = rules.capped();

    let mut outputs: Vec<AssetOutput> = Vec::new();
    for out in &tx.outputs {
        if !script::names_asset(&out.script, asset) {
            continue;
        }
        let read = script::read(&out.script)?;
        if read.clause().rules != Rules::Open || out.satoshis < 1 {
            return None;
        }
        outputs.push(match read {
            Output::Held { amount, .. } => AssetOutput { amount, authority: false, issued: None },
            Output::Authority { issued, .. } => {
                if capped != issued.is_some() {
                    return None;
                }
                AssetOutput { amount: 0, authority: true, issued }
            }
            Output::Deploy { .. } => continue,
        });
    }

    let ins: u128 = inputs.iter().map(|i| i.amount as u128).sum();
    let outs: u128 = outputs.iter().map(|o| o.amount as u128).sum();
    let spent_authorities = inputs.iter().filter(|i| i.authority).count();
    let written_authorities = outputs.iter().filter(|o| o.authority).count();
    let mints = spent_authorities > 0;
    if (written_authorities > 0 && !mints) || written_authorities > 1 || spent_authorities > 1 {
        return None;
    }
    if if mints { outs < ins } else { outs != ins } {
        return None;
    }
    if capped && mints {
        let before = inputs.iter().find(|i| i.authority)?.issued?;
        let units = before.units as u128 + (outs - ins);
        let members = before.members as u128 + members_written(tx, asset);
        if rules.max.is_some_and(|max| units > max as u128) || rules.size.is_some_and(|size| members > size as u128) {
            return None;
        }
        if let Some(written) = outputs.iter().find_map(|o| o.issued) {
            if written.units as u128 != units || written.members as u128 != members {
                return None;
            }
        }
    }
    if rules.item && outs != 1 {
        return None;
    }
    Some(rules)
}

/// Prove one transaction from its parents (every one, raw) and the claims of
/// those parents that carry assets. A missing claim only leaves an asset out.
pub fn step(raw: &[u8], parents: &[Parent], claims: &[Claim]) -> Result<Claim, StepError> {
    let tx = parse_tx(raw).ok_or(StepError::Malformed)?;
    step_parsed(&tx, txid(raw), |id| parents.iter().find(|p| p.txid == *id).map(|p| &p.tx), claims)
}

pub(crate) fn step_parsed<'a>(
    tx: &Tx,
    id: Txid,
    parent_of: impl Fn(&Txid) -> Option<&'a Tx>,
    claims: &[Claim],
) -> Result<Claim, StepError> {
    if claims.iter().any(|c| !tx.inputs.iter().any(|i| i.prev_txid == c.txid)) {
        return Err(StepError::StrayClaim);
    }
    let mut sources = Vec::with_capacity(tx.inputs.len());
    for (vin, input) in tx.inputs.iter().enumerate() {
        let parent = parent_of(&input.prev_txid).ok_or(StepError::MissingParent { vin })?;
        let out = parent.outputs.get(input.prev_vout as usize).ok_or(StepError::BadParent { vin })?;
        let read = script::read(&out.script);
        let deploy_of = match read {
            Some(Output::Deploy { .. }) => asset_id(&input.prev_txid, input.prev_vout),
            _ => None,
        };
        let claim = claims.iter().find(|c| c.txid == input.prev_txid);
        sources.push(Source { read, deploy_of, claim });
    }

    let mut candidates: Vec<AssetId> = Vec::new();
    for source in &sources {
        let id = match &source.read {
            Some(Output::Held { asset, .. }) | Some(Output::Authority { asset, .. }) => Some(*asset),
            Some(Output::Deploy { .. }) => source.deploy_of,
            None => None,
        };
        candidates.extend(id);
    }
    candidates.extend(tx.outputs.iter().filter_map(|o| script::named_asset(&o.script)));
    candidates.sort_unstable();
    candidates.dedup();

    let assets = candidates
        .into_iter()
        .filter_map(|asset| check_asset(tx, &sources, &asset).map(|rules| ProvenAsset { id: asset, rules }))
        .collect();
    Ok(Claim { txid: id, assets })
}
