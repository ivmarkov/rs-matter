use crate::error::Error;

use super::{TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType};

pub type BE = Result<u8, Error>;

/// A decorator trait for serializing data as TLV in the form of an
/// `Iterator` of `Result<u8, Error>` bytes.
///
/// The trait provides additional combinators on top of the standard `Iterator`
/// trait combinators (e.g. `map`, `filter`, `flat_map`, etc.) that allow for serializing TLV elements.
///
/// The trait is already implemented for any `Iterator` with `Item = Result<u8, Error>`, so users are
/// not expected to proviude implementations of it.
///
/// Using an Iterator approach to TLV serialization is useful when the data is not serialized to its
/// final location (be it in the storage or in an outgoing network packet) - but rather - is serialized
/// so that it is afterwards consumed as a stream of bytes by another component - say - a hash signature
/// algorithm that operates on the TLV representation of the data.
///
/// This way, the need for an interim buffer for the serialized TLV data might be avoided.
///
/// NOTE:
/// Keep in mind that the resulting iterator might quickly become rather large if the serialized
/// TLV data contains many small TLV elements, as each TLV element is represented as multiple compositions
/// of the Rust `Iterator` combinators (e.g. `chain`, `map`, `flat_map`, etc.).
///
/// Therefore, the iterator TLV serialization is only useful when the serialized TLV data contains few but
/// large non-container TLV elements, like octet strings or utf8 strings (typically, TLV-encoded certificates).
///
/// For other cases, allocating a temporary memory buffer and serializing into it with `TLVWriter` might result
/// in less memory overhead (and better performance when reading the raw serialized TLV data) by the code that
/// opertates on it.
pub trait ToTLVIter: Iterator<Item = BE> + Sized {
    fn option<I>(self, value: Option<I>) -> impl Iterator<Item = BE>
    where
        I: Iterator<Item = BE>,
    {
        self.chain(match value {
            Some(value) => EitherIter::First(value),
            None => EitherIter::Second(core::iter::empty()),
        })
    }

    /// Serialize a TLV element with the given tag and value.
    fn tlv(self, tag: TLVTag, value: TLVValue) -> impl Iterator<Item = BE> {
        let tag = self._tag(tag, value.value_type());

        let size = match value {
            TLVValue::Str8l(a) => {
                Either5Iter::Second(tag._raw_bytes((a.len() as u8).to_le_bytes()))
            }
            TLVValue::Str16l(a) => {
                Either5Iter::Third(tag._raw_bytes((a.len() as u16).to_le_bytes()))
            }
            TLVValue::Str32l(a) => {
                Either5Iter::Fourth(tag._raw_bytes((a.len() as u32).to_le_bytes()))
            }
            TLVValue::Str64l(a) => {
                Either5Iter::Fifth(tag._raw_bytes((a.len() as u64).to_le_bytes()))
            }
            TLVValue::Utf8l(a) => {
                Either5Iter::Second(tag._raw_bytes((a.len() as u8).to_le_bytes()))
            }
            TLVValue::Utf16l(a) => {
                Either5Iter::Third(tag._raw_bytes((a.len() as u16).to_le_bytes()))
            }
            TLVValue::Utf32l(a) => {
                Either5Iter::Fourth(tag._raw_bytes((a.len() as u32).to_le_bytes()))
            }
            TLVValue::Utf64l(a) => {
                Either5Iter::Fifth(tag._raw_bytes((a.len() as u64).to_le_bytes()))
            }
            _ => Either5Iter::First(tag),
        };

        match value {
            TLVValue::S8(a) => Either6Iter::Second(size._raw_bytes(a.to_le_bytes())),
            TLVValue::S16(a) => Either6Iter::Third(size._raw_bytes(a.to_le_bytes())),
            TLVValue::S32(a) => Either6Iter::Fourth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::S64(a) => Either6Iter::Fifth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::U8(a) => Either6Iter::Second(size._raw_bytes(a.to_le_bytes())),
            TLVValue::U16(a) => Either6Iter::Third(size._raw_bytes(a.to_le_bytes())),
            TLVValue::U32(a) => Either6Iter::Fourth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::U64(a) => Either6Iter::Fifth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::Struct(seq) | TLVValue::Array(seq) | TLVValue::List(seq) => {
                Either6Iter::Sixth(size._raw_bytes(seq.0.into_iter().copied()))
            }
            TLVValue::Null | TLVValue::True | TLVValue::False => Either6Iter::First(size),
            TLVValue::F32(a) => Either6Iter::Fourth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::F64(a) => Either6Iter::Fifth(size._raw_bytes(a.to_le_bytes())),
            TLVValue::Str8l(a)
            | TLVValue::Str16l(a)
            | TLVValue::Str32l(a)
            | TLVValue::Str64l(a) => Either6Iter::Sixth(size._raw_bytes((*a).into_iter().copied())),
            TLVValue::Utf8l(a)
            | TLVValue::Utf16l(a)
            | TLVValue::Utf32l(a)
            | TLVValue::Utf64l(a) => {
                Either6Iter::Sixth(size._raw_bytes((*a.as_bytes()).into_iter().copied()))
            }
        }
    }

    /// Serialize the given tag and the provided value as an S8 TLV value.
    fn i8(self, tag: TLVTag, data: i8) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::S8)
            ._raw_bytes(data.to_le_bytes())
    }

    /// Serialize the given tag and the provided value as a U8 TLV value.
    fn u8(self, tag: TLVTag, data: u8) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::U8)._raw_byte(data)
    }

    /// Serialize the given tag and the provided value as an S16 TLV value,
    /// or as an S8 TLV value if the provided data can fit in the S8 domain range.
    fn i16(self, tag: TLVTag, data: i16) -> impl Iterator<Item = BE> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            EitherIter::First(
                self._tag(tag, TLVValueType::S8)
                    ._raw_bytes((data as i8).to_le_bytes()),
            )
        } else {
            EitherIter::Second(
                self._tag(tag, TLVValueType::S16)
                    ._raw_bytes((data as i16).to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as a U16 TLV value,
    /// or as a U8 TLV value if the provided data can fit in the U8 domain range.
    fn u16(self, tag: TLVTag, data: u16) -> impl Iterator<Item = BE> {
        if data <= u8::MAX as _ {
            EitherIter::First(
                self._tag(tag, TLVValueType::U8)
                    ._raw_bytes((data as u8).to_le_bytes()),
            )
        } else {
            EitherIter::Second(
                self._tag(tag, TLVValueType::U16)
                    ._raw_bytes((data as u16).to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as an S32 TLV value,
    /// or as an S16 / S8 TLV value if the provided data can fit in a smaller domain range.
    fn i32(self, tag: TLVTag, data: i32) -> impl Iterator<Item = BE> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            Either3Iter::First(
                self._tag(tag, TLVValueType::S8)
                    ._raw_bytes((data as i8).to_le_bytes()),
            )
        } else if data >= i16::MIN as _ && data <= i16::MAX as _ {
            Either3Iter::Second(
                self._tag(tag, TLVValueType::S16)
                    ._raw_bytes((data as i16).to_le_bytes()),
            )
        } else {
            Either3Iter::Third(
                self._tag(tag, TLVValueType::S32)
                    ._raw_bytes((data as i32).to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as a U32 TLV value,
    /// or as a U16 / U8 TLV value if the provided data can fit in a smaller domain range.
    fn u32(self, tag: TLVTag, data: u32) -> impl Iterator<Item = BE> {
        if data <= u8::MAX as _ {
            Either3Iter::First(
                self._tag(tag, TLVValueType::U8)
                    ._raw_bytes((data as u8).to_le_bytes()),
            )
        } else if data <= u16::MAX as _ {
            Either3Iter::Second(
                self._tag(tag, TLVValueType::U16)
                    ._raw_bytes((data as u16).to_le_bytes()),
            )
        } else {
            Either3Iter::Third(
                self._tag(tag, TLVValueType::U32)
                    ._raw_bytes((data as u32).to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as an S64 TLV value,
    /// or as an S32 / S16 / S8 TLV value if the provided data can fit in a smaller domain range.
    fn i64(self, tag: TLVTag, data: i64) -> impl Iterator<Item = BE> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            Either4Iter::First(
                self._tag(tag, TLVValueType::S8)
                    ._raw_bytes((data as i8).to_le_bytes()),
            )
        } else if data >= i16::MIN as _ && data <= i16::MAX as _ {
            Either4Iter::Second(
                self._tag(tag, TLVValueType::S16)
                    ._raw_bytes((data as i16).to_le_bytes()),
            )
        } else if data >= i32::MIN as _ && data <= i32::MAX as _ {
            Either4Iter::Third(
                self._tag(tag, TLVValueType::S32)
                    ._raw_bytes((data as i32).to_le_bytes()),
            )
        } else {
            Either4Iter::Fourth(
                self._tag(tag, TLVValueType::S64)
                    ._raw_bytes(data.to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as a U64 TLV value,
    /// or as a U32 / U16 / U8 TLV value if the provided data can fit in a smaller domain range.
    fn u64(self, tag: TLVTag, data: u64) -> impl Iterator<Item = BE> {
        if data <= u8::MAX as _ {
            Either4Iter::First(
                self._tag(tag, TLVValueType::U8)
                    ._raw_bytes((data as u8).to_le_bytes()),
            )
        } else if data <= u16::MAX as _ {
            Either4Iter::Second(
                self._tag(tag, TLVValueType::U16)
                    ._raw_bytes((data as u16).to_le_bytes()),
            )
        } else if data <= u32::MAX as _ {
            Either4Iter::Third(
                self._tag(tag, TLVValueType::U32)
                    ._raw_bytes((data as u32).to_le_bytes()),
            )
        } else {
            Either4Iter::Fourth(
                self._tag(tag, TLVValueType::U64)
                    ._raw_bytes(data.to_le_bytes()),
            )
        }
    }

    /// Serialize the given tag and the provided value as a TLV Octet String.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn str(self, tag: TLVTag, data: &[u8]) -> impl Iterator<Item = BE> {
        self.stri(
            tag,
            data.len(),
            core::iter::empty()._raw_bytes(data.into_iter().copied()),
        )
    }

    /// Serialize the given tag and the provided value as a TLV Octet String.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE: The length of the Octet String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    fn stri<I>(self, tag: TLVTag, len: usize, iter: I) -> impl Iterator<Item = BE>
    where
        I: Iterator<Item = BE>,
    {
        if len <= u8::MAX as usize {
            Either4Iter::First(
                self._tag(tag, TLVValueType::Str8l)
                    ._raw_byte(len as u8)
                    .chain(iter),
            )
        } else if len <= u16::MAX as usize {
            Either4Iter::Second(
                self._tag(tag, TLVValueType::Str16l)
                    ._raw_bytes((len as u16).to_le_bytes())
                    .chain(iter),
            )
        } else if len <= u32::MAX as usize {
            Either4Iter::Third(
                self._tag(tag, TLVValueType::Str32l)
                    ._raw_bytes((len as u32).to_le_bytes())
                    .chain(iter),
            )
        } else {
            Either4Iter::Fourth(
                self._tag(tag, TLVValueType::Str64l)
                    ._raw_bytes((len as u64).to_le_bytes())
                    .chain(iter),
            )
        }
    }

    /// Serialize the given tag and the provided value as a TLV UTF-8 String.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn utf8(self, tag: TLVTag, data: &str) -> impl Iterator<Item = BE> {
        self.utf8i(
            tag,
            data.len(),
            core::iter::empty()._raw_bytes(data.as_bytes().into_iter().copied()),
        )
    }

    /// Serialize the given tag and the provided value as a TLV UTF-8 String.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE 1: The length of the UTF-8 String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    ///
    /// NOTE 2: The provided iterator must return valid UTF-8 bytes, or else the generated TLV stream will be invalid.
    fn utf8i<I>(self, tag: TLVTag, len: usize, iter: I) -> impl Iterator<Item = BE>
    where
        I: Iterator<Item = BE>,
    {
        if len <= u8::MAX as usize {
            Either4Iter::First(
                self._tag(tag, TLVValueType::Utf8l)
                    ._raw_byte(len as u8)
                    .chain(iter),
            )
        } else if len <= u16::MAX as usize {
            Either4Iter::Second(
                self._tag(tag, TLVValueType::Utf16l)
                    ._raw_bytes((len as u16).to_le_bytes())
                    .chain(iter),
            )
        } else if len <= u32::MAX as usize {
            Either4Iter::Third(
                self._tag(tag, TLVValueType::Utf32l)
                    ._raw_bytes((len as u32).to_le_bytes())
                    .chain(iter),
            )
        } else {
            Either4Iter::Fourth(
                self._tag(tag, TLVValueType::Utf64l)
                    ._raw_bytes((len as u64).to_le_bytes())
                    .chain(iter),
            )
        }
    }

    /// Serialize the given tag and a value indicating the start of a Struct TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the Struct fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_struct(self, tag: TLVTag) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::Struct)
    }

    /// Serialize the given tag and a value indicating the start of an Array TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the Array elements
    /// to close the Array container or else the generated TLV stream will be invalid.
    fn start_array(self, tag: TLVTag) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::Array)
    }

    /// Serialize the given tag and a value indicating the start of a List TLV container.
    ///
    /// NOTE: The user must call `end_container` after serializing all the List elements
    /// to close the List container or else the generated TLV stream will be invalid.
    fn start_list(self, tag: TLVTag) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::List)
    }

    /// Serialize a value indicating the end of a Struct, Array, or List TLV container.
    ///
    /// NOTE: This method must be called only when the corresponding container has been opened
    /// using `start_struct`, `start_array`, or `start_list`, or else the generated TLV stream will be invalid.
    fn end_container(self) -> impl Iterator<Item = BE> {
        self._raw_byte(TLVControl::new(TLVTagType::Anonymous, TLVValueType::EndCnt).as_raw())
    }

    /// Serialize the given tag and a value indicating a Null TLV value.
    fn null(self, tag: TLVTag) -> impl Iterator<Item = BE> {
        self._tag(tag, TLVValueType::Null)
    }

    /// Serialize the given tag and a value indicating a True or False TLV value.
    fn bool(self, tag: TLVTag, val: bool) -> impl Iterator<Item = BE> {
        self._tag(
            tag,
            if val {
                TLVValueType::True
            } else {
                TLVValueType::False
            },
        )
    }

    fn raw_value<I>(
        self,
        tag: TLVTag,
        value_type: TLVValueType,
        raw_value: I,
    ) -> impl Iterator<Item = BE>
    where
        I: Iterator<Item = BE>,
    {
        self._tag(tag, value_type).chain(raw_value)
    }

    /// Serialize a tag by encoding in the control byte preceding the tag
    /// the supplied TLV value type.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn _tag(self, tag: TLVTag, value_type: TLVValueType) -> impl Iterator<Item = BE> {
        let control = self._raw_byte(TLVControl::new(tag.tag_type(), value_type).as_raw());

        match tag {
            TLVTag::Anonymous => Either6Iter::First(control),
            TLVTag::Context(v) => Either6Iter::Second(control._raw_byte(v)),
            TLVTag::CommonPrf16(v) => Either6Iter::Third(control._raw_bytes(v.to_le_bytes())),
            TLVTag::CommonPrf32(v) => Either6Iter::Fourth(control._raw_bytes(v.to_le_bytes())),
            TLVTag::ImplPrf16(v) => Either6Iter::Third(control._raw_bytes(v.to_le_bytes())),
            TLVTag::ImplPrf32(v) => Either6Iter::Fourth(control._raw_bytes(v.to_le_bytes())),
            TLVTag::FullQual48(v) => {
                Either6Iter::Fifth(control._raw_bytes(v.to_le_bytes().into_iter().take(6)))
            }
            TLVTag::FullQual64(v) => Either6Iter::Sixth(control._raw_bytes(v.to_be_bytes())),
        }
    }

    /// Serialize a raw byte array representing already-encoded TLV bytes.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn _raw_bytes<I>(self, bytes: I) -> impl Iterator<Item = BE>
    where
        I: IntoIterator<Item = u8>,
    {
        self.chain(bytes.into_iter().map(Result::Ok))
    }

    /// Serialize a raw, already encoded TLV byte.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn _raw_byte(self, byte: u8) -> impl Iterator<Item = BE> {
        self.chain(core::iter::once(Ok(byte)))
    }
}

impl<T> ToTLVIter for T where T: Iterator<Item = BE> {}

pub enum Either1Iter<F> {
    First(F),
}

impl<F> Iterator for Either1Iter<F>
where
    F: Iterator,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
        }
    }
}

pub enum EitherIter<F, S> {
    First(F),
    Second(S),
}

impl<F, S> Iterator for EitherIter<F, S>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
        }
    }
}

pub enum Either3Iter<F, S, T> {
    First(F),
    Second(S),
    Third(T),
}

impl<F, S, T> Iterator for Either3Iter<F, S, T>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
        }
    }
}

pub enum Either4Iter<F, S, T, U> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
}

impl<F, S, T, U> Iterator for Either4Iter<F, S, T, U>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
        }
    }
}

pub enum Either5Iter<F, S, T, U, I> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
}

impl<F, S, T, U, I> Iterator for Either5Iter<F, S, T, U, I>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
    I: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
            Self::Fifth(i) => i.next(),
        }
    }
}

pub enum Either6Iter<F, S, T, U, I, X> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
    Sixth(X),
}

impl<F, S, T, U, I, X> Iterator for Either6Iter<F, S, T, U, I, X>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
    I: Iterator<Item = F::Item>,
    X: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::First(i) => i.next(),
            Self::Second(i) => i.next(),
            Self::Third(i) => i.next(),
            Self::Fourth(i) => i.next(),
            Self::Fifth(i) => i.next(),
            Self::Sixth(i) => i.next(),
        }
    }
}

pub fn flatten<I>(value: Result<I, Error>) -> impl Iterator<Item = BE>
where
    I: Iterator<Item = BE>,
{
    match value {
        Ok(value) => EitherIter::First(value),
        Err(err) => EitherIter::Second(core::iter::once(Err(err))),
    }
}
