//! The claim a proof commits to: a txid and the assets its outputs carry
//! validly, each with the deploy rules its children need.
//!
//! ```text
//! claim:  txid (32, internal order) ‖ count (u16 LE) ‖ asset*
//! asset:  id (20) ‖ flags (u8) ‖ [max (u64 LE)] ‖ [size (u64 LE)]
//! flags:  1 item, 2 auth, 4 max follows, 8 size follows
//! ```
//!
//! Assets are in ascending id order. Decoding refuses anything else, so one
//! claim has exactly one encoding.

use crate::tx::{AssetId, Txid};

const ITEM: u8 = 1;
const AUTH: u8 = 2;
const MAX: u8 = 4;
const SIZE: u8 = 8;

/// What a child needs from the deploy of an asset it spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetRules {
    pub item: bool,
    pub auth: bool,
    pub max: Option<u64>,
    pub size: Option<u64>,
}

impl AssetRules {
    pub fn capped(&self) -> bool {
        self.auth && (self.max.is_some() || self.size.is_some())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenAsset {
    pub id: AssetId,
    pub rules: AssetRules,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub txid: Txid,
    pub assets: Vec<ProvenAsset>,
}

impl Claim {
    pub fn rules_of(&self, asset: &AssetId) -> Option<AssetRules> {
        self.assets.iter().find(|a| a.id == *asset).map(|a| a.rules)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34 + self.assets.len() * 37);
        out.extend_from_slice(&self.txid);
        out.extend((self.assets.len() as u16).to_le_bytes());
        for asset in &self.assets {
            let r = asset.rules;
            let flag = |set: bool, bit: u8| if set { bit } else { 0 };
            let flags = flag(r.item, ITEM) | flag(r.auth, AUTH) | flag(r.max.is_some(), MAX) | flag(r.size.is_some(), SIZE);
            out.extend_from_slice(&asset.id);
            out.push(flags);
            for cap in [r.max, r.size].into_iter().flatten() {
                out.extend(cap.to_le_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Claim> {
        Claim::read(bytes).and_then(|(claim, used)| (used == bytes.len()).then_some(claim))
    }

    /// Decode the claim at the start of `bytes`, with the number of bytes it took.
    pub fn read(bytes: &[u8]) -> Option<(Claim, usize)> {
        let txid: Txid = bytes.get(..32)?.try_into().ok()?;
        let count = u16::from_le_bytes(bytes.get(32..34)?.try_into().ok()?) as usize;
        let mut at = 34;
        let mut assets: Vec<ProvenAsset> = Vec::with_capacity(count.min(bytes.len() / 21));
        for _ in 0..count {
            let id: AssetId = bytes.get(at..at + 20)?.try_into().ok()?;
            let flags = *bytes.get(at + 20)?;
            at += 21;
            if flags & !(ITEM | AUTH | MAX | SIZE) != 0 || assets.last().is_some_and(|a| a.id >= id) {
                return None;
            }
            let mut cap = |present: bool| -> Option<Option<u64>> {
                if !present {
                    return Some(None);
                }
                let v = u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?);
                at += 8;
                Some(Some(v))
            };
            let max = cap(flags & MAX != 0)?;
            let size = cap(flags & SIZE != 0)?;
            assets.push(ProvenAsset { id, rules: AssetRules { item: flags & ITEM != 0, auth: flags & AUTH != 0, max, size } });
        }
        Some((Claim { txid, assets }, at))
    }
}

/// What a step proof commits to: the program's own verifying key digest, then
/// the claims, in the order the batch proved them. A step verifies each
/// parent's proof under the key it was given and requires the parent to have
/// committed that same key, so one pinned key covers every proof in the chain.
pub fn public_values(vkey: &[u32; 8], claims: &[Claim]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + claims.len() * 55);
    for word in vkey {
        out.extend(word.to_le_bytes());
    }
    for claim in claims {
        out.extend(claim.encode());
    }
    out
}

/// Split public values into the key they were made under and the claims.
pub fn read_public_values(bytes: &[u8]) -> Option<([u32; 8], Vec<Claim>)> {
    let mut vkey = [0u32; 8];
    for (i, word) in vkey.iter_mut().enumerate() {
        *word = u32::from_le_bytes(bytes.get(4 * i..4 * i + 4)?.try_into().ok()?);
    }
    let mut at = 32;
    let mut claims = Vec::new();
    while at < bytes.len() {
        let (claim, used) = Claim::read(&bytes[at..])?;
        claims.push(claim);
        at += used;
    }
    Some((vkey, claims))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_values_carry_the_key_and_the_claims() {
        let vkey = [1, 2, 3, 4, 5, 6, 7, u32::MAX];
        let one = Claim { txid: [3; 32], assets: vec![] };
        let two = Claim {
            txid: [4; 32],
            assets: vec![ProvenAsset { id: [1; 20], rules: AssetRules { item: false, auth: true, max: Some(9), size: Some(2) } }],
        };
        assert_eq!(public_values(&vkey, &[one.clone()])[32..], one.encode()[..]);
        let both = vec![one, two];
        assert_eq!(read_public_values(&public_values(&vkey, &both)), Some((vkey, both.clone())));
        assert_eq!(read_public_values(&public_values(&vkey, &[])), Some((vkey, vec![])));
        let mut cut = public_values(&vkey, &both);
        cut.pop();
        assert_eq!(read_public_values(&cut), None);
    }

    #[test]
    fn round_trips_and_has_one_encoding() {
        let claim = Claim {
            txid: [7; 32],
            assets: vec![
                ProvenAsset { id: [1; 20], rules: AssetRules { item: false, auth: true, max: Some(1000), size: None } },
                ProvenAsset { id: [2; 20], rules: AssetRules { item: true, auth: false, max: None, size: None } },
            ],
        };
        let bytes = claim.encode();
        assert_eq!(Claim::decode(&bytes), Some(claim.clone()));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Claim::decode(&extra), None);
        let mut swapped = claim;
        swapped.assets.reverse();
        assert_eq!(Claim::decode(&swapped.encode()), None);
    }
}
