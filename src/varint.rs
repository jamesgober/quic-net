//! Variable-length integers (RFC 9000 section 16) and the byte cursor every
//! decoder in this crate reads through.

use crate::error::DecodeError;

/// The largest value a variable-length integer holds: 2^62 - 1.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// A variable-length integer: at most 2^62 - 1, written on 1, 2, 4, or 8
/// bytes, the length in the top two bits of the first.
///
/// ```
/// use quic_net::VarInt;
/// let v = VarInt::new(15_293).unwrap();
/// let mut out = Vec::new();
/// v.encode(&mut out);
/// assert_eq!(out, [0x7b, 0xbd]);
/// assert_eq!(VarInt::decode(&out), Ok((v, 2)));
/// assert!(VarInt::new(1 << 62).is_none());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest value.
    pub const MAX: VarInt = VarInt(MAX_VARINT);

    /// `value`, or `None` past 2^62 - 1.
    #[must_use]
    pub const fn new(value: u64) -> Option<VarInt> {
        if value <= MAX_VARINT {
            Some(VarInt(value))
        } else {
            None
        }
    }

    /// A value that always fits.
    #[must_use]
    pub const fn from_u32(value: u32) -> VarInt {
        VarInt(value as u64)
    }

    /// The value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Bytes on the wire at the shortest encoding: 1, 2, 4, or 8.
    #[must_use]
    pub const fn size(self) -> usize {
        size(self.0)
    }

    /// Appends the shortest encoding.
    pub fn encode(self, out: &mut Vec<u8>) {
        put(out, self.0);
    }

    /// Reads one from the front of `bytes`: the value and how many bytes it took.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Short`] when `bytes` ends first.
    pub fn decode(bytes: &[u8]) -> Result<(VarInt, usize), DecodeError> {
        let mut r = Reader::new(bytes);
        let (v, n) = r.varint_len()?;
        Ok((VarInt(v), n))
    }
}

impl From<u32> for VarInt {
    fn from(v: u32) -> VarInt {
        VarInt::from_u32(v)
    }
}

impl std::fmt::Display for VarInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Bytes of the shortest encoding of `v` (which must be at most 2^62 - 1).
pub(crate) const fn size(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Appends the shortest encoding of `v`, which must be at most 2^62 - 1
/// (larger values are clamped: callers check first).
pub(crate) fn put(out: &mut Vec<u8>, v: u64) {
    let v = v.min(MAX_VARINT);
    match size(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// A cursor over input bytes. Every read checks the length first.
#[derive(Clone, Debug)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let r = &self.buf[self.pos..];
        self.pos = self.buf.len();
        r
    }

    pub(crate) fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Short)?;
        let b = self.buf.get(self.pos..end).ok_or(DecodeError::Short)?;
        self.pos = end;
        Ok(b)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.bytes(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let b = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }

    /// A variable-length integer and the bytes it took.
    pub(crate) fn varint_len(&mut self) -> Result<(u64, usize), DecodeError> {
        let first = self.peek_u8().ok_or(DecodeError::Short)?;
        let n = 1usize << (first >> 6);
        let b = self.bytes(n)?;
        let mut v = u64::from(b[0] & 0x3F);
        for &x in &b[1..] {
            v = (v << 8) | u64::from(x);
        }
        Ok((v, n))
    }

    pub(crate) fn varint(&mut self) -> Result<u64, DecodeError> {
        Ok(self.varint_len()?.0)
    }

    /// A varint used as a length or count of bytes that follow: at most what
    /// is left, so it can never ask for more than the input holds.
    pub(crate) fn length(&mut self) -> Result<usize, DecodeError> {
        let v = self.varint()?;
        if v > self.remaining() as u64 {
            return Err(DecodeError::Short);
        }
        Ok(v as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_examples() {
        // RFC 9000 appendix A.1.
        let cases: [(&[u8], u64); 4] = [
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (bytes, value) in cases {
            assert_eq!(VarInt::decode(bytes), Ok((VarInt(value), bytes.len())));
            let mut out = Vec::new();
            VarInt(value).encode(&mut out);
            assert_eq!(out, bytes);
        }
        // 37 on two bytes is allowed for values (not frame types).
        assert_eq!(VarInt::decode(&[0x40, 0x25]), Ok((VarInt(37), 2)));
    }

    #[test]
    fn boundaries() {
        for v in [
            0,
            63,
            64,
            16_383,
            16_384,
            (1 << 30) - 1,
            1 << 30,
            MAX_VARINT,
        ] {
            let mut out = Vec::new();
            put(&mut out, v);
            assert_eq!(out.len(), size(v));
            assert_eq!(VarInt::decode(&out), Ok((VarInt(v), out.len())));
            for cut in 0..out.len() {
                assert_eq!(VarInt::decode(&out[..cut]), Err(DecodeError::Short));
            }
        }
        assert_eq!(VarInt::new(MAX_VARINT + 1), None);
    }

    #[test]
    fn lengths_never_exceed_the_input() {
        let mut r = Reader::new(&[0x05, 1, 2]);
        assert_eq!(r.length(), Err(DecodeError::Short));
        let mut r = Reader::new(&[0x02, 1, 2]);
        assert_eq!(r.length(), Ok(2));
        let mut r = Reader::new(&[]);
        assert_eq!(r.bytes(usize::MAX), Err(DecodeError::Short));
    }
}
