//! BRC-255 §1 locking scripts. Every form is parsed, re-encoded and compared, so
//! only the canonical encoding is an output of an asset.

use crate::tx::AssetId;

pub const BNT_MARKER: [u8; 3] = *b"bnt";
pub const IPT_MARKER: [u8; 3] = *b"ipt";
const MAX_SET: usize = 5;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_2DROP: u8 = 0x6d;
const OP_DROP: u8 = 0x75;
const OP_EQUAL: u8 = 0x87;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;

pub type Key = [u8; 33];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Release {
    Hash([u8; 20]),
    Keys { k: usize, keys: Vec<Key> },
}

/// Everything a clause fixes except the holder; closure compares these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rules {
    Open,
    Countersign { m: usize, keys: Vec<Key>, release: Release },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clause {
    pub holder: Key,
    pub rules: Rules,
}

/// What a capped asset's authority has issued so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    pub units: u64,
    pub members: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    Deploy { supply: u64, payload: Vec<u8>, clause: Clause },
    Held { asset: AssetId, amount: u64, clause: Clause },
    Authority { asset: AssetId, clause: Clause, issued: Option<Issued> },
}

impl Output {
    pub fn clause(&self) -> &Clause {
        match self {
            Output::Deploy { clause, .. } | Output::Held { clause, .. } | Output::Authority { clause, .. } => clause,
        }
    }
}

struct Chunk<'a> {
    op: u8,
    data: Option<&'a [u8]>,
}

fn chunks(script: &[u8]) -> Option<Vec<Chunk<'_>>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < script.len() {
        let op = script[at];
        at += 1;
        let len = match op {
            0x01..=0x4b => op as usize,
            OP_PUSHDATA1 => {
                let n = *script.get(at)? as usize;
                at += 1;
                n
            }
            OP_PUSHDATA2 => {
                let n = u16::from_le_bytes(script.get(at..at + 2)?.try_into().ok()?) as usize;
                at += 2;
                n
            }
            OP_PUSHDATA4 => {
                let n = u32::from_le_bytes(script.get(at..at + 4)?.try_into().ok()?) as usize;
                at += 4;
                n
            }
            _ => {
                out.push(Chunk { op, data: None });
                continue;
            }
        };
        let data = script.get(at..at.checked_add(len)?)?;
        at += len;
        out.push(Chunk { op, data: Some(data) });
    }
    Some(out)
}

fn data_of<'a>(chunks: &[Chunk<'a>], at: usize, len: usize) -> Option<&'a [u8]> {
    chunks.get(at)?.data.filter(|d| d.len() == len)
}

fn op_at(chunks: &[Chunk<'_>], at: usize) -> Option<u8> {
    chunks.get(at).filter(|c| c.data.is_none()).map(|c| c.op)
}

/// A minimally encoded script number from 0 to 2^64−1, or None.
fn number(chunk: Option<&Chunk<'_>>) -> Option<u64> {
    let chunk = chunk?;
    let Some(data) = chunk.data else {
        return match chunk.op {
            OP_0 => Some(0),
            OP_1..=OP_16 => Some((chunk.op - OP_1 + 1) as u64),
            _ => None,
        };
    };
    if data.is_empty() || data.len() > 9 || data[data.len() - 1] & 0x80 != 0 {
        return None;
    }
    if data.len() > 1 && data[data.len() - 1] == 0 && data[data.len() - 2] & 0x80 == 0 {
        return None;
    }
    let mut n: u128 = 0;
    for (i, b) in data.iter().enumerate() {
        n |= (*b as u128) << (8 * i);
    }
    let n = u64::try_from(n).ok()?;
    (n > 16).then_some(n)
}

fn valid_key(key: &[u8]) -> bool {
    key.len() == 33 && (key[0] == 0x02 || key[0] == 0x03)
}

fn key_of(data: &[u8]) -> Option<Key> {
    valid_key(data).then(|| data.try_into().ok()).flatten()
}

fn small_int(chunks: &[Chunk<'_>], at: usize) -> Option<usize> {
    match op_at(chunks, at)? {
        op @ OP_1..=OP_16 => Some((op - OP_1 + 1) as usize),
        _ => None,
    }
}

/// Consecutive 33-byte pushes from `at`, as raw bytes; validity is checked with the set.
fn read_keys(chunks: &[Chunk<'_>], at: usize) -> (Vec<[u8; 33]>, usize) {
    let mut keys = Vec::new();
    let mut i = at;
    while let Some(d) = data_of(chunks, i, 33) {
        keys.push(d.try_into().unwrap());
        i += 1;
    }
    (keys, i)
}

fn read_sig_part(chunks: &[Chunk<'_>], at: usize) -> Option<(usize, Vec<[u8; 33]>, usize)> {
    if let Some(key) = data_of(chunks, at, 33) {
        if op_at(chunks, at + 1) == Some(OP_CHECKSIG) {
            return Some((1, vec![key.try_into().unwrap()], at + 2));
        }
    }
    let m = small_int(chunks, at)?;
    let (keys, next) = read_keys(chunks, at + 1);
    if small_int(chunks, next) != Some(keys.len()) || op_at(chunks, next + 1) != Some(OP_CHECKMULTISIG) {
        return None;
    }
    Some((m, keys, next + 2))
}

fn read_release(chunks: &[Chunk<'_>], at: usize) -> Option<(Release, usize)> {
    if op_at(chunks, at) == Some(OP_HASH160) && op_at(chunks, at + 2) == Some(OP_EQUAL) {
        if let Some(h) = data_of(chunks, at + 1, 20) {
            return Some((Release::Hash(h.try_into().unwrap()), at + 3));
        }
    }
    let k = small_int(chunks, at)?;
    let (keys, next) = read_keys(chunks, at + 1);
    if small_int(chunks, next) != Some(keys.len()) || op_at(chunks, next + 1) != Some(OP_CHECKMULTISIG) {
        return None;
    }
    Some((Release::Keys { k, keys }, next + 2))
}

fn set_ok(m: usize, keys: &[[u8; 33]], odd_majority: bool) -> bool {
    let n = keys.len();
    if m < 1 || m > n || n > MAX_SET {
        return false;
    }
    if odd_majority && n > 1 && 2 * m <= n {
        return false;
    }
    if !keys.iter().all(|k| valid_key(k)) {
        return false;
    }
    (0..n).all(|i| (i + 1..n).all(|j| keys[i] != keys[j]))
}

fn rules_ok(rules: &Rules) -> bool {
    match rules {
        Rules::Open => true,
        Rules::Countersign { m, keys, release } => {
            if !set_ok(*m, keys, true) {
                return false;
            }
            match release {
                Release::Hash(_) => true,
                Release::Keys { k, keys: rel } => set_ok(*k, rel, false) && !rel.iter().any(|r| keys.contains(r)),
            }
        }
    }
}

fn read_clause(chunks: &[Chunk<'_>], at: usize) -> Option<Clause> {
    let holder = key_of(data_of(chunks, at, 33)?)?;
    let rules = if op_at(chunks, at + 1) == Some(OP_CHECKSIG) && chunks.len() == at + 2 {
        Rules::Open
    } else {
        if op_at(chunks, at + 1) != Some(OP_CHECKSIGVERIFY) || op_at(chunks, at + 2) != Some(OP_IF) {
            return None;
        }
        let (m, keys, next) = read_sig_part(chunks, at + 3)?;
        if op_at(chunks, next) != Some(OP_ELSE) {
            return None;
        }
        let (release, next) = read_release(chunks, next + 1)?;
        if op_at(chunks, next) != Some(OP_ENDIF) || chunks.len() != next + 1 {
            return None;
        }
        Rules::Countersign { m, keys, release }
    };
    rules_ok(&rules).then_some(Clause { holder, rules })
}

fn push(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n == 0 {
        out.push(OP_0);
        return;
    } else if n < OP_PUSHDATA1 as usize {
        out.push(n as u8);
    } else if n < 1 << 8 {
        out.extend([OP_PUSHDATA1, n as u8]);
    } else if n < 1 << 16 {
        out.push(OP_PUSHDATA2);
        out.extend((n as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend((n as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

fn write_number(out: &mut Vec<u8>, n: u64) {
    if n == 0 {
        out.push(OP_0);
        return;
    }
    if n <= 16 {
        out.push(OP_1 - 1 + n as u8);
        return;
    }
    let mut bytes = Vec::with_capacity(9);
    let mut v = n;
    while v > 0 {
        bytes.push(v as u8);
        v >>= 8;
    }
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        bytes.push(0);
    }
    push(out, &bytes);
}

fn write_set(out: &mut Vec<u8>, m: usize, keys: &[Key]) {
    out.push(OP_1 - 1 + m as u8);
    for key in keys {
        push(out, key);
    }
    out.push(OP_1 - 1 + keys.len() as u8);
    out.push(OP_CHECKMULTISIG);
}

fn write_clause(out: &mut Vec<u8>, clause: &Clause) {
    push(out, &clause.holder);
    match &clause.rules {
        Rules::Open => out.push(OP_CHECKSIG),
        Rules::Countersign { m, keys, release } => {
            out.extend([OP_CHECKSIGVERIFY, OP_IF]);
            if keys.len() == 1 && *m == 1 {
                push(out, &keys[0]);
                out.push(OP_CHECKSIG);
            } else {
                write_set(out, *m, keys);
            }
            out.push(OP_ELSE);
            match release {
                Release::Hash(h) => {
                    out.push(OP_HASH160);
                    push(out, h);
                    out.push(OP_EQUAL);
                }
                Release::Keys { k, keys } => write_set(out, *k, keys),
            }
            out.push(OP_ENDIF);
        }
    }
}

fn marker(rules: &Rules) -> [u8; 3] {
    match rules {
        Rules::Open => BNT_MARKER,
        Rules::Countersign { .. } => IPT_MARKER,
    }
}

/// The canonical script of an output; None where the writer would refuse it.
pub fn encode(output: &Output) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match output {
        Output::Deploy { supply, payload, clause } => {
            if *supply == 0 || payload.is_empty() {
                return None;
            }
            push(&mut out, &marker(&clause.rules));
            write_number(&mut out, *supply);
            push(&mut out, payload);
            out.extend([OP_2DROP, OP_DROP]);
            write_clause(&mut out, clause);
        }
        Output::Held { asset, amount, clause } => {
            if *amount == 0 {
                return None;
            }
            push(&mut out, &[&marker(&clause.rules)[..], asset].concat());
            write_number(&mut out, *amount);
            out.push(OP_2DROP);
            write_clause(&mut out, clause);
        }
        Output::Authority { asset, clause, issued } => {
            push(&mut out, &[&marker(&clause.rules)[..], asset].concat());
            out.push(OP_0);
            if let Some(Issued { units, members }) = issued {
                if *units == 0 {
                    return None;
                }
                write_number(&mut out, *units);
                write_number(&mut out, *members);
                out.push(OP_2DROP);
            }
            out.push(OP_2DROP);
            write_clause(&mut out, clause);
        }
    }
    Some(out)
}

/// The first push names a marker, alone or with an asset id: the only scripts read further.
fn looks_like_bnt(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x03) | Some(0x17))
        && script.get(1..4).is_some_and(|m| m == BNT_MARKER || m == IPT_MARKER)
}

/// Read any BRC-255 output form, either marker; None for anything not canonical.
pub fn read(script: &[u8]) -> Option<Output> {
    if !looks_like_bnt(script) {
        return None;
    }
    let chunks = chunks(script)?;
    let head = chunks.first()?.data?;
    if head.len() != 3 && head.len() != 23 {
        return None;
    }
    let out = if head.len() == 3 {
        let supply = number(chunks.get(1))?;
        let payload = chunks.get(2)?.data?;
        if supply == 0 || payload.is_empty() || op_at(&chunks, 3) != Some(OP_2DROP) || op_at(&chunks, 4) != Some(OP_DROP) {
            return None;
        }
        Output::Deploy { supply, payload: payload.to_vec(), clause: read_clause(&chunks, 5)? }
    } else {
        let asset: AssetId = head[3..].try_into().unwrap();
        let amount = number(chunks.get(1))?;
        if amount == 0 && op_at(&chunks, 2) != Some(OP_2DROP) {
            let units = number(chunks.get(2))?;
            let members = number(chunks.get(3))?;
            if op_at(&chunks, 4) != Some(OP_2DROP) || op_at(&chunks, 5) != Some(OP_2DROP) {
                return None;
            }
            Output::Authority { asset, clause: read_clause(&chunks, 6)?, issued: Some(Issued { units, members }) }
        } else {
            if op_at(&chunks, 2) != Some(OP_2DROP) {
                return None;
            }
            let clause = read_clause(&chunks, 3)?;
            if amount == 0 {
                Output::Authority { asset, clause, issued: None }
            } else {
                Output::Held { asset, amount, clause }
            }
        }
    };
    (encode(&out)? == script).then_some(out)
}

/// Does this output name `asset` in its first push, under either marker?
pub fn names_asset(script: &[u8], asset: &AssetId) -> bool {
    script.first() == Some(&0x17)
        && script.get(1..4).is_some_and(|m| m == BNT_MARKER || m == IPT_MARKER)
        && script.get(4..24) == Some(&asset[..])
}

/// The asset id an output names in its first push, if it looks like an output of an asset.
pub fn named_asset(script: &[u8]) -> Option<AssetId> {
    (script.first() == Some(&0x17) && script.get(1..4).is_some_and(|m| m == BNT_MARKER || m == IPT_MARKER))
        .then(|| script.get(4..24)?.try_into().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(holder: u8) -> Clause {
        let mut key = [holder; 33];
        key[0] = 0x02;
        Clause { holder: key, rules: Rules::Open }
    }

    #[test]
    fn round_trips_every_form() {
        let asset = [0xab; 20];
        for out in [
            Output::Deploy { supply: 21_000_000, payload: vec![0xa0; 300], clause: open(1) },
            Output::Held { asset, amount: 7, clause: open(2) },
            Output::Held { asset, amount: u64::MAX, clause: open(2) },
            Output::Authority { asset, clause: open(3), issued: None },
            Output::Authority { asset, clause: open(3), issued: Some(Issued { units: 128, members: 0 }) },
        ] {
            assert_eq!(read(&encode(&out).unwrap()), Some(out));
        }
    }

    #[test]
    fn refuses_a_number_pushed_as_data() {
        let mut script = encode(&Output::Held { asset: [1; 20], amount: 7, clause: open(2) }).unwrap();
        script.splice(24..25, [0x01, 0x07]);
        assert_eq!(read(&script), None);
    }
}
