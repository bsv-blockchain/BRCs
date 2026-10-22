//! BRC-255 §2 deploy payloads: strict DAG-CBOR and the fields a deploy may
//! carry together. A payload that fails any check names no asset.

use crate::tx::AssetId;

const MAX_SAFE: u64 = (1 << 53) - 1;
const MAX_DEPTH: usize = 32;
const MAX_TEXT: usize = 256;
const MAX_ICON: usize = 96 * 1024;
const MAX_CONTENT: usize = 1024 * 1024;
const MIN_SILENCE: u64 = 604_800;
const MAX_RESERVE: usize = 64;
const BACKING_CHAINS: [&str; 1] = ["ltc"];
const KNOWN: [&str; 23] = [
    "v", "mode", "kind", "iss", "m", "bcn", "rel", "relk", "k", "sil", "auth", "max", "size", "sym", "name", "dec", "icon",
    "ctype", "c", "col", "hdl", "bk", "crit",
];

#[derive(Clone, Debug, PartialEq)]
enum Value {
    /// An unsigned integer up to 2^53−1; larger ones and negatives are `Big`.
    Int(u64),
    Big(i128),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(String, Value)>),
    Bool(bool),
    Null,
    Link,
}

fn read_value(bytes: &[u8], at: usize, depth: usize) -> Option<(Value, usize)> {
    if at >= bytes.len() || depth > MAX_DEPTH {
        return None;
    }
    let ib = bytes[at];
    let (major, addl) = (ib >> 5, ib & 0x1f);
    let mut pos = at + 1;
    if major == 7 {
        return match addl {
            20 => Some((Value::Bool(false), pos)),
            21 => Some((Value::Bool(true), pos)),
            22 => Some((Value::Null, pos)),
            27 => {
                let f = f64::from_be_bytes(bytes.get(pos..pos + 8)?.try_into().ok()?);
                f.is_finite().then_some((Value::Float(f), pos + 8))
            }
            _ => None,
        };
    }
    let arg: u64 = match addl {
        0..=23 => addl as u64,
        24..=27 => {
            let width = 1usize << (addl - 24);
            let mut arg = 0u64;
            for b in bytes.get(pos..pos + width)? {
                arg = (arg << 8) | *b as u64;
            }
            pos += width;
            let floor = [24u64, 1 << 8, 1 << 16, 1 << 32][(addl - 24) as usize];
            if arg < floor {
                return None;
            }
            arg
        }
        _ => return None,
    };
    let remaining = (bytes.len() - pos) as u64;
    match major {
        0 => Some((if arg <= MAX_SAFE { Value::Int(arg) } else { Value::Big(arg as i128) }, pos)),
        1 => Some((Value::Big(-1 - arg as i128), pos)),
        6 => {
            if arg != 42 {
                return None;
            }
            let (link, next) = read_value(bytes, pos, depth + 1)?;
            match link {
                Value::Bytes(b) if b.first() == Some(&0) => Some((Value::Link, next)),
                _ => None,
            }
        }
        2 | 3 => {
            if arg > remaining {
                return None;
            }
            let end = pos + arg as usize;
            let slice = &bytes[pos..end];
            if major == 2 {
                return Some((Value::Bytes(slice.to_vec()), end));
            }
            Some((Value::Text(text_of(slice)?), end))
        }
        4 => {
            if arg > remaining {
                return None;
            }
            let mut items = Vec::new();
            for _ in 0..arg {
                let (item, next) = read_value(bytes, pos, depth + 1)?;
                items.push(item);
                pos = next;
            }
            Some((Value::Array(items), pos))
        }
        5 => {
            if arg.checked_mul(2)? > remaining {
                return None;
            }
            let mut entries: Vec<(String, Value)> = Vec::new();
            for _ in 0..arg {
                if bytes.get(pos).map_or(0, |b| b >> 5) != 3 {
                    return None;
                }
                let (key, next) = read_value(bytes, pos, depth + 1)?;
                let Value::Text(key) = key else { return None };
                if let Some((last, _)) = entries.last() {
                    let (a, b) = (key.as_bytes(), last.as_bytes());
                    if a.len() < b.len() || (a.len() == b.len() && a <= b) {
                        return None;
                    }
                }
                let (value, next) = read_value(bytes, next, depth + 1)?;
                entries.push((key, value));
                pos = next;
            }
            Some((Value::Map(entries), pos))
        }
        _ => None,
    }
}

/// Strict UTF-8 with one leading byte-order mark dropped, as a WHATWG decoder reads text.
fn text_of(bytes: &[u8]) -> Option<String> {
    let text = core::str::from_utf8(bytes).ok()?;
    Some(text.strip_prefix('\u{feff}').unwrap_or(text).to_string())
}

fn decode_map(bytes: &[u8]) -> Option<Vec<(String, Value)>> {
    let (value, next) = read_value(bytes, 0, 0)?;
    match value {
        Value::Map(entries) if next == bytes.len() => Some(entries),
        _ => None,
    }
}

/// A non-negative safe integer, as a JavaScript number reads one (an integral float counts).
fn uint(value: &Value) -> Option<u64> {
    match value {
        Value::Int(n) => Some(*n),
        Value::Float(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE as f64 && *f >= 0.0 => Some(*f as u64),
        _ => None,
    }
}

/// A non-negative count up to 2^64−1.
fn count(value: &Value) -> Option<u64> {
    match value {
        Value::Big(n) => u64::try_from(*n).ok(),
        other => uint(other),
    }
}

fn key33(value: &Value) -> Option<[u8; 33]> {
    match value {
        Value::Bytes(b) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

fn bytes_of(value: &Value, len: usize) -> Option<Vec<u8>> {
    match value {
        Value::Bytes(b) if b.len() == len => Some(b.clone()),
        _ => None,
    }
}

fn js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}'
            | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `[a-z][a-z0-9+.-]*://`, case-insensitive, anywhere in the text.
fn has_url(text: &str) -> bool {
    let b = text.as_bytes();
    let in_class = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'.' || c == b'-';
    (0..b.len()).any(|p| {
        if !b[p..].starts_with(b"://") {
            return false;
        }
        let mut i = p;
        while i > 0 && in_class(b[i - 1]) {
            i -= 1;
            if b[i].is_ascii_alphabetic() {
                return true;
            }
        }
        false
    })
}

fn text_ok(text: &str) -> bool {
    !text.chars().all(js_space) && text.encode_utf16().count() <= MAX_TEXT && !has_url(text)
}

fn valid_key(key: &[u8; 33]) -> bool {
    key[0] == 0x02 || key[0] == 0x03
}

fn distinct<T: PartialEq>(items: &[T]) -> bool {
    (0..items.len()).all(|i| (i + 1..items.len()).all(|j| items[i] != items[j]))
}

/// The deploy fields a proof step reads; the rest only has to be well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fields {
    pub open: bool,
    pub item: bool,
    pub auth: bool,
    pub max: Option<u64>,
    pub size: Option<u64>,
    pub col: Option<AssetId>,
    pub backed: bool,
}

/// A BRC-255 payload, or None: wrong shape, an unknown critical key, a URL, or fields that cannot go together.
pub fn decode(bytes: &[u8]) -> Option<Fields> {
    if bytes.is_empty() {
        return None;
    }
    let map = decode_map(bytes)?;
    let get = |key: &str| map.iter().find(|(k, _)| k == key).map(|(_, v)| v);
    // JavaScript `!= null`: absent or null both count as absent.
    let present = |key: &str| get(key).filter(|v| **v != Value::Null);

    if !matches!(get("v"), Some(v) if uint(v) == Some(1)) {
        return None;
    }
    let crit = present("crit");
    if let Some(crit) = crit {
        let Value::Array(items) = crit else { return None };
        if !items.iter().all(|c| matches!(c, Value::Text(t) if KNOWN.contains(&t.as_str()))) {
            return None;
        }
    }
    let open = match get("mode") {
        Some(Value::Text(t)) if t == "open" => true,
        Some(Value::Text(t)) if t == "countersign" => false,
        _ => return None,
    };
    let item = match present("kind") {
        None => false,
        Some(Value::Text(t)) if t == "token" => false,
        Some(Value::Text(t)) if t == "item" => true,
        _ => return None,
    };
    let iss: Vec<[u8; 33]> = match get("iss") {
        Some(Value::Array(items)) if items.len() >= 2 => items.iter().map(key33).collect::<Option<_>>()?,
        Some(Value::Array(_)) => return None,
        Some(single) => vec![key33(single)?],
        None => return None,
    };
    for key in ["m", "k", "sil", "dec"] {
        if get(key).is_some_and(|v| uint(v).is_none()) {
            return None;
        }
    }
    for key in ["max", "size"] {
        if get(key).is_some_and(|v| count(v).is_none()) {
            return None;
        }
    }
    let text = |key: &str| match get(key) {
        Some(Value::Text(t)) => Some(t.as_str()),
        _ => None,
    };
    for key in ["sym", "name", "ctype", "hdl"] {
        if get(key).is_some() && text(key).is_none() {
            return None;
        }
    }
    let bcn = match present("bcn") {
        None => false,
        Some(v) => {
            bytes_of(v, 36)?;
            true
        }
    };
    let rel = match present("rel") {
        None => false,
        Some(v) => {
            bytes_of(v, 20)?;
            true
        }
    };
    let relk: Option<Vec<[u8; 33]>> = match present("relk") {
        None => None,
        Some(Value::Array(items)) => Some(items.iter().map(key33).collect::<Option<_>>()?),
        Some(_) => return None,
    };
    let auth = match present("auth") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    let icon = match present("icon") {
        None => None,
        Some(Value::Array(items)) => match items.as_slice() {
            [Value::Text(media), Value::Bytes(b)] => Some((media.as_str(), b.len())),
            _ => return None,
        },
        Some(_) => return None,
    };
    let content = match present("c") {
        None => None,
        Some(Value::Bytes(b)) => Some(b.len()),
        Some(_) => return None,
    };
    let col: Option<AssetId> = match present("col") {
        None => None,
        Some(v) => Some(bytes_of(v, 20)?.try_into().ok()?),
    };
    let backing = match present("bk") {
        None => None,
        Some(Value::Array(items)) => match items.as_slice() {
            [Value::Text(chain), Value::Bytes(reserve)] if BACKING_CHAINS.contains(&chain.as_str()) => {
                let critical = matches!(crit, Some(Value::Array(c)) if c.iter().any(|x| *x == Value::Text("bk".into())));
                if !critical {
                    return None;
                }
                Some(reserve.len())
            }
            _ => return None,
        },
        Some(_) => return None,
    };
    let m = get("m").and_then(uint).unwrap_or(1);
    let k = get("k").and_then(uint);
    let sil = get("sil").and_then(uint);
    let dec = get("dec").and_then(uint);
    let max = get("max").and_then(count);
    let size = get("size").and_then(count);

    // The fields a deploy may carry together.
    let n = iss.len();
    if !(1..=5).contains(&n) || !iss.iter().all(valid_key) || !distinct(&iss) {
        return None;
    }
    if m < 1 || m > n as u64 || (n > 1 && 2 * m <= n as u64) {
        return None;
    }
    if open {
        if bcn || rel || relk.is_some() || k.is_some() || sil.is_some() {
            return None;
        }
    } else {
        if !bcn || sil.is_none_or(|s| s < MIN_SILENCE) {
            return None;
        }
        let by_keys = relk.is_some() || k.is_some();
        if rel == by_keys {
            return None;
        }
        if by_keys {
            let relk = relk.as_deref().unwrap_or(&[]);
            let j = relk.len();
            if !(1..=5).contains(&j) || !relk.iter().all(valid_key) || !distinct(relk) {
                return None;
            }
            if !k.is_some_and(|k| k >= 1 && k <= j as u64) {
                return None;
            }
        }
    }
    if item {
        if dec.is_some() || auth {
            return None;
        }
    } else if content.is_some() || get("ctype").is_some() || col.is_some() {
        return None;
    }
    for cap in [max, size].into_iter().flatten() {
        if !auth || cap < 1 {
            return None;
        }
    }
    if dec.is_some_and(|d| d > 18) {
        return None;
    }
    for key in ["sym", "name", "ctype", "hdl"] {
        if text(key).is_some_and(|t| !text_ok(t)) {
            return None;
        }
    }
    if let Some((media, len)) = icon {
        if !text_ok(media) || len == 0 || len > MAX_ICON {
            return None;
        }
    }
    if let Some(len) = content {
        if len == 0 || len > MAX_CONTENT || text("ctype").is_none() {
            return None;
        }
    }
    if let Some(len) = backing {
        if item || !auth || len == 0 || len > MAX_RESERVE {
            return None;
        }
    }
    Some(Fields { open, item, auth, max, size, col, backed: backing.is_some() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_urls_as_the_desktop_pattern_does() {
        assert!(has_url("see https://x"));
        assert!(has_url("a1+.-://"));
        assert!(!has_url("1+.-://"));
        assert!(!has_url("://x"));
        assert!(!has_url("plain name"));
    }

    #[test]
    fn trims_and_counts_like_javascript() {
        assert!(!text_ok("\u{feff}\u{3000} "));
        assert!(text_ok(&"\u{1F600}".repeat(128)));
        assert!(!text_ok(&"\u{1F600}".repeat(129)));
    }

    #[test]
    fn refuses_non_minimal_heads_and_unsorted_keys() {
        // {"v": 1} with the 1 in a one-byte head
        assert_eq!(decode_map(&[0xa1, 0x61, b'v', 0x18, 0x01]), None);
        // {"vv": 1, "v": 1}: longer key first
        assert_eq!(decode_map(&[0xa2, 0x62, b'v', b'v', 0x01, 0x61, b'v', 0x01]), None);
    }
}
