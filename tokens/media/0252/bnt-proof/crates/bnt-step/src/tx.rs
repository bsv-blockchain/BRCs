//! Raw Bitcoin transactions, txids and BRC-255 asset ids.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// A txid in internal byte order, as an input's outpoint carries it.
pub type Txid = [u8; 32];
pub type AssetId = [u8; 20];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    pub prev_txid: Txid,
    pub prev_vout: u32,
    pub script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub satoshis: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub locktime: u32,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn varint(&mut self) -> Option<u64> {
        let first = self.take(1)?[0];
        Some(match first {
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().ok()?) as u64,
            0xfe => self.u32()? as u64,
            0xff => self.u64()?,
            n => n as u64,
        })
    }

    fn var_bytes(&mut self) -> Option<Vec<u8>> {
        let n = usize::try_from(self.varint()?).ok()?;
        Some(self.take(n)?.to_vec())
    }

    /// A count of items each at least `min` bytes long, bounded by what is left.
    fn count(&mut self, min: usize) -> Option<usize> {
        let n = usize::try_from(self.varint()?).ok()?;
        (n.checked_mul(min)? <= self.bytes.len() - self.at).then_some(n)
    }
}

/// Parse a whole raw transaction; trailing bytes are refused.
pub fn parse_tx(raw: &[u8]) -> Option<Tx> {
    let mut r = Reader { bytes: raw, at: 0 };
    let version = r.u32()?;
    let n_in = r.count(41)?;
    let mut inputs = Vec::with_capacity(n_in);
    for _ in 0..n_in {
        let prev_txid: Txid = r.take(32)?.try_into().ok()?;
        let prev_vout = r.u32()?;
        let script = r.var_bytes()?;
        let sequence = r.u32()?;
        inputs.push(TxIn { prev_txid, prev_vout, script, sequence });
    }
    let n_out = r.count(9)?;
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let satoshis = r.u64()?;
        let script = r.var_bytes()?;
        outputs.push(TxOut { satoshis, script });
    }
    let locktime = r.u32()?;
    (r.at == raw.len()).then_some(Tx { version, inputs, outputs, locktime })
}

fn write_varint(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend((n as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend((n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend((n as u64).to_le_bytes());
        }
    }
}

impl Tx {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.version.to_le_bytes());
        write_varint(&mut out, self.inputs.len());
        for input in &self.inputs {
            out.extend_from_slice(&input.prev_txid);
            out.extend(input.prev_vout.to_le_bytes());
            write_varint(&mut out, input.script.len());
            out.extend_from_slice(&input.script);
            out.extend(input.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len());
        for output in &self.outputs {
            out.extend(output.satoshis.to_le_bytes());
            write_varint(&mut out, output.script.len());
            out.extend_from_slice(&output.script);
        }
        out.extend(self.locktime.to_le_bytes());
        out
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn txid(raw: &[u8]) -> Txid {
    sha256(&sha256(raw))
}

pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(bytes)).into()
}

/// `HASH160(txid in internal byte order ‖ index byte)`; deploy outputs past index 255 name no asset.
pub fn asset_id(txid: &Txid, vout: u32) -> Option<AssetId> {
    let index = u8::try_from(vout).ok()?;
    let mut preimage = [0u8; 33];
    preimage[..32].copy_from_slice(txid);
    preimage[32] = index;
    Some(hash160(&preimage))
}
