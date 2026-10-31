//! Length-bounded reads and preferred-length writes for a few CBOR shapes.
//!
//! This is not a CBOR decoder. Indefinite lengths, tags, floats, and negative
//! integers are rejected. Callers cap array and byte lengths before copying.

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NarrowError;

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, index: 0 }
    }

    pub(crate) fn is_exhausted(&self) -> bool {
        self.index == self.data.len()
    }

    pub(crate) fn header(&mut self) -> Result<(u8, u8), NarrowError> {
        let byte = *self.data.get(self.index).ok_or(NarrowError)?;
        self.index += 1;
        Ok((byte >> 5, byte & 0x1f))
    }

    pub(crate) fn argument(&mut self, additional: u8) -> Result<u64, NarrowError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(*self.data.get(self.index).ok_or(NarrowError)?);
                self.index += 1;
                if value < 24 {
                    return Err(NarrowError);
                }
                Ok(value)
            }
            25 => self.wide(2, 256),
            26 => self.wide(4, 1 << 16),
            27 => self.wide(8, 1 << 32),
            _ => Err(NarrowError),
        }
    }

    pub(crate) fn uint(&mut self) -> Result<u64, NarrowError> {
        let (major, argument) = self.header()?;
        if major != 0 {
            return Err(NarrowError);
        }
        self.argument(argument)
    }

    pub(crate) fn bytes_exact(&mut self, len: usize) -> Result<Vec<u8>, NarrowError> {
        let (major, argument) = self.header()?;
        if major != 2 {
            return Err(NarrowError);
        }
        let decoded = self.argument(argument)?;
        if decoded != u64::try_from(len).map_err(|_| NarrowError)? {
            return Err(NarrowError);
        }
        self.take(len)
    }

    pub(crate) fn text(&mut self, max_bytes: usize) -> Result<String, NarrowError> {
        let (major, argument) = self.header()?;
        if major != 3 {
            return Err(NarrowError);
        }
        let len = usize::try_from(self.argument(argument)?).map_err(|_| NarrowError)?;
        if len > max_bytes {
            return Err(NarrowError);
        }
        let bytes = self.take(len)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| NarrowError)?;
        Ok(text.to_string())
    }

    pub(crate) fn array_len(&mut self, max: usize) -> Result<usize, NarrowError> {
        self.container_len(4, max)
    }

    pub(crate) fn map_len(&mut self, exact: usize) -> Result<(), NarrowError> {
        let count = self.container_len(5, exact)?;
        if count == exact {
            Ok(())
        } else {
            Err(NarrowError)
        }
    }

    /// A CBOR null, or a byte string of exactly `len` bytes.
    pub(crate) fn null_or_bytes(&mut self, len: usize) -> Result<Option<Vec<u8>>, NarrowError> {
        let (major, argument) = self.header()?;
        if major == 7 && argument == 22 {
            return Ok(None);
        }
        if major != 2 {
            return Err(NarrowError);
        }
        let decoded = self.argument(argument)?;
        if decoded != u64::try_from(len).map_err(|_| NarrowError)? {
            return Err(NarrowError);
        }
        self.take(len).map(Some)
    }

    fn container_len(&mut self, major_expected: u8, max: usize) -> Result<usize, NarrowError> {
        let (major, argument) = self.header()?;
        if major != major_expected {
            return Err(NarrowError);
        }
        let count = usize::try_from(self.argument(argument)?).map_err(|_| NarrowError)?;
        if count > max {
            return Err(NarrowError);
        }
        Ok(count)
    }

    fn take(&mut self, len: usize) -> Result<Vec<u8>, NarrowError> {
        let end = self.index.checked_add(len).ok_or(NarrowError)?;
        let bytes = self.data.get(self.index..end).ok_or(NarrowError)?;
        self.index = end;
        Ok(bytes.to_vec())
    }

    fn wide(&mut self, width: usize, minimum: u64) -> Result<u64, NarrowError> {
        let end = self.index.checked_add(width).ok_or(NarrowError)?;
        let bytes = self.data.get(self.index..end).ok_or(NarrowError)?;
        let mut be = [0u8; 8];
        be[8 - width..].copy_from_slice(bytes);
        self.index = end;
        let value = u64::from_be_bytes(be);
        if value < minimum {
            return Err(NarrowError);
        }
        Ok(value)
    }
}

pub(crate) fn encode_uint(out: &mut Vec<u8>, value: u64) {
    if value < 24 {
        out.push(value as u8);
    } else if value < 256 {
        out.push(0x18);
        out.push(value as u8);
    } else if value < 65536 {
        out.push(0x19);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 1 << 32 {
        out.push(0x1a);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn encode_len(out: &mut Vec<u8>, major: u8, len: usize) {
    let head = major << 5;
    if len < 24 {
        out.push(head | u8::try_from(len).expect("len fits one byte"));
    } else if len < 256 {
        out.push(head | 24);
        out.push(u8::try_from(len).expect("len fits one byte"));
    } else if len < 65536 {
        out.push(head | 25);
        out.extend_from_slice(
            &u16::try_from(len)
                .expect("len fits two bytes")
                .to_be_bytes(),
        );
    } else {
        out.push(head | 26);
        out.extend_from_slice(
            &u32::try_from(len)
                .expect("len fits four bytes")
                .to_be_bytes(),
        );
    }
}

pub(crate) fn encode_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_len(out, 2, bytes.len());
    out.extend_from_slice(bytes);
}

pub(crate) fn encode_text(out: &mut Vec<u8>, text: &str) {
    encode_len(out, 3, text.len());
    out.extend_from_slice(text.as_bytes());
}
