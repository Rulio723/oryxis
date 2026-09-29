//! The sliver of CBOR CTAP2 needs.
//!
//! Hand-rolled rather than a dependency because the surface is tiny: the
//! requests are a handful of maps we build ourselves, and the responses
//! are read into a small [`Value`] tree. What matters is that requests go
//! out in CTAP2 CANONICAL form (CTAP 2.1 section 8), since a strict token
//! refuses anything else with `CBOR_UNEXPECTED_TYPE`: shortest-form
//! integers, definite lengths, and map keys sorted by major type, then by
//! encoded length, then bytewise. Callers write keys in that order; the
//! tests pin it for every map we send.

use crate::Error;

/// A CBOR writer for the canonical subset.
pub(crate) struct Cbor(Vec<u8>);

impl Cbor {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn map(&mut self, entries: usize) -> &mut Self {
        self.head(5, entries as u64)
    }

    pub(crate) fn array(&mut self, items: usize) -> &mut Self {
        self.head(4, items as u64)
    }

    pub(crate) fn uint(&mut self, value: u64) -> &mut Self {
        self.head(0, value)
    }

    /// A signed integer, in whichever major type its sign calls for.
    pub(crate) fn int(&mut self, value: i64) -> &mut Self {
        if value >= 0 {
            self.head(0, value as u64)
        } else {
            self.head(1, (-1 - value) as u64)
        }
    }

    pub(crate) fn text(&mut self, value: &str) -> &mut Self {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
        self
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
        self
    }

    pub(crate) fn bool(&mut self, value: bool) -> &mut Self {
        self.0.push(if value { 0xf5 } else { 0xf4 });
        self
    }

    /// Major type plus argument, in the shortest form CBOR allows.
    fn head(&mut self, major: u8, value: u64) -> &mut Self {
        let tag = major << 5;
        match value {
            0..=23 => self.0.push(tag | value as u8),
            24..=0xff => {
                self.0.push(tag | 24);
                self.0.push(value as u8);
            }
            0x100..=0xffff => {
                self.0.push(tag | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(tag | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(tag | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
        self
    }
}

/// The slice of CBOR a CTAP2 response can contain.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Uint(u64),
    Neg(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub(crate) fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Uint(value) => i64::try_from(*value).ok(),
            Self::Neg(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Uint(_) => "an unsigned integer",
            Self::Neg(_) => "a negative integer",
            Self::Bytes(_) => "a byte string",
            Self::Text(_) => "a text string",
            Self::Array(_) => "an array",
            Self::Map(_) => "a map",
            Self::Bool(_) => "a boolean",
            Self::Null => "null",
        }
    }

    /// The entries of a map, or a named error.
    pub(crate) fn into_map(self) -> Result<Vec<(Value, Value)>, Error> {
        match self {
            Self::Map(entries) => Ok(entries),
            other => Err(Error::Malformed(format!(
                "expected a CBOR map, got {}",
                other.kind()
            ))),
        }
    }
}

/// Decode one value from the front of `bytes`, returning it and how many
/// bytes it used.
pub(crate) fn decode(bytes: &[u8]) -> Result<(Value, usize), Error> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.value(0)?;
    Ok((value, reader.pos))
}

/// Nesting deeper than any CTAP2 response goes. The response comes from a
/// USB device, and an unbounded recursion on its say-so is a stack
/// overflow waiting for a hostile gadget.
const MAX_DEPTH: usize = 16;

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| Error::Malformed("truncated CBOR".into()))?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| Error::Malformed("truncated CBOR".into()))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn argument(&mut self, info: u8) -> Result<u64, Error> {
        Ok(match info {
            0..=23 => info as u64,
            24 => self.byte()? as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(Error::Malformed("indefinite-length CBOR".into())),
        })
    }

    /// A length that must fit in what is left of the input: a declared
    /// count can never be trusted to size an allocation.
    fn length(&mut self, info: u8) -> Result<usize, Error> {
        let len = self.argument(info)?;
        usize::try_from(len)
            .ok()
            .filter(|len| *len <= self.bytes.len() - self.pos)
            .ok_or_else(|| Error::Malformed("CBOR length runs past the message".into()))
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Malformed("CBOR nested too deeply".into()));
        }
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        Ok(match major {
            0 => Value::Uint(self.argument(info)?),
            1 => {
                let magnitude = self.argument(info)?;
                let magnitude = i64::try_from(magnitude)
                    .map_err(|_| Error::Malformed("CBOR negative integer out of range".into()))?;
                Value::Neg(-1 - magnitude)
            }
            2 => {
                let len = self.length(info)?;
                Value::Bytes(self.take(len)?.to_vec())
            }
            3 => {
                let len = self.length(info)?;
                let raw = self.take(len)?;
                Value::Text(
                    std::str::from_utf8(raw)
                        .map_err(|_| Error::Malformed("invalid UTF-8 in CBOR".into()))?
                        .to_string(),
                )
            }
            4 => {
                let len = self.length(info)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let len = self.length(info)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.value(depth + 1)?;
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(Error::Malformed("unsupported CBOR simple value".into())),
            },
            other => {
                return Err(Error::Malformed(format!(
                    "unsupported CBOR major type {other}"
                )));
            }
        })
    }
}

/// Whether `keys` (already encoded) are in CTAP2 canonical order.
#[cfg(test)]
pub(crate) fn is_canonical_order(keys: &[Vec<u8>]) -> bool {
    keys.windows(2).all(|pair| {
        let (a, b) = (&pair[0], &pair[1]);
        (a[0] >> 5, a.len(), a.as_slice()) < (b[0] >> 5, b.len(), b.as_slice())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_take_the_shortest_form_both_signs() {
        let mut cbor = Cbor::new();
        cbor.uint(23).uint(24).int(-1).int(-25).int(-256).int(-257);
        assert_eq!(
            cbor.finish(),
            vec![0x17, 0x18, 0x18, 0x20, 0x38, 0x18, 0x38, 0xff, 0x39, 0x01, 0x00]
        );
    }

    #[test]
    fn negative_integers_round_trip() {
        let mut cbor = Cbor::new();
        cbor.array(3).int(-1).int(-25).int(-3);
        let (value, _) = decode(&cbor.finish()).unwrap();
        assert_eq!(
            value,
            Value::Array(vec![Value::Neg(-1), Value::Neg(-25), Value::Neg(-3)])
        );
    }

    #[test]
    fn a_hostile_length_is_refused_before_it_allocates() {
        // A byte string claiming 2^32 bytes, then nothing.
        assert!(decode(&[0x5a, 0xff, 0xff, 0xff, 0xff]).is_err());
        // An array claiming 2^32 items.
        assert!(decode(&[0x9a, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn deep_nesting_is_refused_rather_than_recursed() {
        let bytes = vec![0x81; 64];
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn canonical_order_is_major_type_then_length_then_bytes() {
        let key = |f: &dyn Fn(&mut Cbor)| {
            let mut cbor = Cbor::new();
            f(&mut cbor);
            cbor.finish()
        };
        // 1, 3, -1, -2, -3: the COSE key order.
        let cose: Vec<Vec<u8>> = vec![
            key(&|c| {
                c.uint(1);
            }),
            key(&|c| {
                c.uint(3);
            }),
            key(&|c| {
                c.int(-1);
            }),
            key(&|c| {
                c.int(-2);
            }),
            key(&|c| {
                c.int(-3);
            }),
        ];
        assert!(is_canonical_order(&cose));
        // "id" before "type": shorter first, whatever the letters say.
        let descriptor = vec![
            key(&|c| {
                c.text("id");
            }),
            key(&|c| {
                c.text("type");
            }),
        ];
        assert!(is_canonical_order(&descriptor));
        assert!(!is_canonical_order(&[descriptor[1].clone(), descriptor[0].clone()]));
    }
}
