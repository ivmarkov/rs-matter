use super::{TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType, TLV};

pub trait ToTLVIter: Iterator<Item = u8> + Sized {
    fn option<F, V, I>(self, value: Option<V>, f: F) -> impl Iterator<Item = u8>
    where
        I: Iterator<Item = u8>,
        F: FnOnce(Self, V) -> I,
    {
        if let Some(value) = value {
            Either::First(f(self, value))
        } else {
            Either::Second(self)
        }
    }

    fn byte(self, byte: u8) -> impl Iterator<Item = u8> {
        self.chain(core::iter::once(byte))
    }

    fn bytes<const N: usize>(self, bytes: [u8; N]) -> impl Iterator<Item = u8> {
        self.chain(bytes.into_iter())
    }

    fn slice<'a>(self, slice: &'a [u8]) -> impl Iterator<Item = u8> + 'a
    where
        Self: 'a,
    {
        self.chain(slice.into_iter().copied())
    }

    fn control(self, control: TLVControl) -> impl Iterator<Item = u8> {
        self.byte(control.into_raw())
    }

    fn tag(self, tag: TLVTag, value_type: TLVValueType) -> impl Iterator<Item = u8> {
        let control = self.control(TLVControl::from(tag.tag_type(), value_type));

        match tag {
            TLVTag::Anonymous => Either6::First(control),
            TLVTag::Context(v) => Either6::Second(control.byte(v)),
            TLVTag::CommonPrf16(v) => Either6::Third(control.bytes(v.to_le_bytes())),
            TLVTag::CommonPrf32(v) => Either6::Fourth(control.bytes(v.to_le_bytes())),
            TLVTag::ImplPrf16(v) => Either6::Third(control.bytes(v.to_le_bytes())),
            TLVTag::ImplPrf32(v) => Either6::Fourth(control.bytes(v.to_le_bytes())),
            TLVTag::FullQual48(v) => {
                Either6::Fifth(control.chain(v.to_le_bytes().into_iter().take(6)))
            }
            TLVTag::FullQual64(v) => Either6::Sixth(control.bytes(v.to_be_bytes())),
        }
    }

    fn value(self, value: TLVValue) -> impl Iterator<Item = u8> {
        let size = match value {
            TLVValue::Utf8l(a) | TLVValue::Str8l(a) => {
                Either5::Second(self.bytes((a.len() as u8).to_le_bytes()))
            }
            TLVValue::Utf16l(a) | TLVValue::Str16l(a) => {
                Either5::Third(self.bytes((a.len() as u16).to_le_bytes()))
            }
            TLVValue::Utf32l(a) | TLVValue::Str32l(a) => {
                Either5::Fourth(self.bytes((a.len() as u32).to_le_bytes()))
            }
            TLVValue::Utf64l(a) | TLVValue::Str64l(a) => {
                Either5::Fifth(self.bytes((a.len() as u64).to_le_bytes()))
            }
            _ => Either5::First(self),
        };

        match value {
            TLVValue::S8(a) => Either6::Second(size.bytes(a.to_le_bytes())),
            TLVValue::S16(a) => Either6::Third(size.bytes(a.to_le_bytes())),
            TLVValue::S32(a) => Either6::Fourth(size.bytes(a.to_le_bytes())),
            TLVValue::S64(a) => Either6::Fifth(size.bytes(a.to_le_bytes())),
            TLVValue::U8(a) => Either6::Second(size.bytes(a.to_le_bytes())),
            TLVValue::U16(a) => Either6::Third(size.bytes(a.to_le_bytes())),
            TLVValue::U32(a) => Either6::Fourth(size.bytes(a.to_le_bytes())),
            TLVValue::U64(a) => Either6::Fifth(size.bytes(a.to_le_bytes())),
            TLVValue::Struct
            | TLVValue::Array
            | TLVValue::List
            | TLVValue::EndCnt
            | TLVValue::Null
            | TLVValue::True
            | TLVValue::False => Either6::First(size),
            TLVValue::F32(a) => Either6::Fourth(size.bytes(a.to_le_bytes())),
            TLVValue::F64(a) => Either6::Fifth(size.bytes(a.to_le_bytes())),
            TLVValue::Utf8l(a)
            | TLVValue::Str8l(a)
            | TLVValue::Utf16l(a)
            | TLVValue::Str16l(a)
            | TLVValue::Utf32l(a)
            | TLVValue::Str32l(a)
            | TLVValue::Utf64l(a)
            | TLVValue::Str64l(a) => Either6::Sixth(size.chain((*a).into_iter().copied())),
        }
    }

    fn tlv(self, tlv: TLV) -> impl Iterator<Item = u8> {
        self.tag(tlv.tag, tlv.value.value_type()).value(tlv.value)
    }

    fn i8(self, tag: TLVTag, data: i8) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::S8).bytes(data.to_le_bytes())
    }

    fn u8(self, tag: TLVTag, data: u8) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::U8).byte(data)
    }

    fn i16(self, tag: TLVTag, data: i16) -> impl Iterator<Item = u8> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            Either::First(
                self.tag(tag, TLVValueType::S8)
                    .bytes((data as i8).to_le_bytes()),
            )
        } else {
            Either::Second(
                self.tag(tag, TLVValueType::S16)
                    .bytes((data as i16).to_le_bytes()),
            )
        }
    }

    fn u16(self, tag: TLVTag, data: u16) -> impl Iterator<Item = u8> {
        if data <= u8::MAX as _ {
            Either::First(
                self.tag(tag, TLVValueType::U8)
                    .bytes((data as u8).to_le_bytes()),
            )
        } else {
            Either::Second(
                self.tag(tag, TLVValueType::U16)
                    .bytes((data as u16).to_le_bytes()),
            )
        }
    }

    fn i32(self, tag: TLVTag, data: i32) -> impl Iterator<Item = u8> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            Either3::First(
                self.tag(tag, TLVValueType::S8)
                    .bytes((data as i8).to_le_bytes()),
            )
        } else if data >= i16::MIN as _ && data <= i16::MAX as _ {
            Either3::Second(
                self.tag(tag, TLVValueType::S16)
                    .bytes((data as i16).to_le_bytes()),
            )
        } else {
            Either3::Third(
                self.tag(tag, TLVValueType::S32)
                    .bytes((data as i32).to_le_bytes()),
            )
        }
    }

    fn u32(self, tag: TLVTag, data: u32) -> impl Iterator<Item = u8> {
        if data <= u8::MAX as _ {
            Either3::First(
                self.tag(tag, TLVValueType::U8)
                    .bytes((data as u8).to_le_bytes()),
            )
        } else if data <= u16::MAX as _ {
            Either3::Second(
                self.tag(tag, TLVValueType::U16)
                    .bytes((data as u16).to_le_bytes()),
            )
        } else {
            Either3::Third(
                self.tag(tag, TLVValueType::U32)
                    .bytes((data as u32).to_le_bytes()),
            )
        }
    }

    fn i64(self, tag: TLVTag, data: i64) -> impl Iterator<Item = u8> {
        if data >= i8::MIN as _ && data <= i8::MAX as _ {
            Either4::First(
                self.tag(tag, TLVValueType::S8)
                    .bytes((data as i8).to_le_bytes()),
            )
        } else if data >= i16::MIN as _ && data <= i16::MAX as _ {
            Either4::Second(
                self.tag(tag, TLVValueType::S16)
                    .bytes((data as i16).to_le_bytes()),
            )
        } else if data >= i32::MIN as _ && data <= i32::MAX as _ {
            Either4::Third(
                self.tag(tag, TLVValueType::S32)
                    .bytes((data as i32).to_le_bytes()),
            )
        } else {
            Either4::Fourth(self.tag(tag, TLVValueType::S64).bytes(data.to_le_bytes()))
        }
    }

    fn u64(self, tag: TLVTag, data: u64) -> impl Iterator<Item = u8> {
        if data <= u8::MAX as _ {
            Either4::First(
                self.tag(tag, TLVValueType::U8)
                    .bytes((data as u8).to_le_bytes()),
            )
        } else if data <= u16::MAX as _ {
            Either4::Second(
                self.tag(tag, TLVValueType::U16)
                    .bytes((data as u16).to_le_bytes()),
            )
        } else if data <= u32::MAX as _ {
            Either4::Third(
                self.tag(tag, TLVValueType::U32)
                    .bytes((data as u32).to_le_bytes()),
            )
        } else {
            Either4::Fourth(self.tag(tag, TLVValueType::U64).bytes(data.to_le_bytes()))
        }
    }

    fn str(self, tag: TLVTag, data: &[u8]) -> impl Iterator<Item = u8> {
        self.stri(tag, data.len(), data.into_iter().copied())
    }

    fn stri<I>(self, tag: TLVTag, len: usize, iter: I) -> impl Iterator<Item = u8>
    where
        I: Iterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            Either4::First(
                self.tag(tag, TLVValueType::Str8l)
                    .byte(len as u8)
                    .chain(iter),
            )
        } else if len <= u16::MAX as usize {
            Either4::Second(
                self.tag(tag, TLVValueType::Str16l)
                    .bytes((len as u16).to_le_bytes())
                    .chain(iter),
            )
        } else if len <= u32::MAX as usize {
            Either4::Third(
                self.tag(tag, TLVValueType::Str32l)
                    .bytes((len as u32).to_le_bytes())
                    .chain(iter),
            )
        } else {
            Either4::Fourth(
                self.tag(tag, TLVValueType::Str64l)
                    .bytes((len as u64).to_le_bytes())
                    .chain(iter),
            )
        }
    }

    fn utf8(self, tag: TLVTag, data: &[u8]) -> impl Iterator<Item = u8> {
        self.utf8i(tag, data.len(), data.into_iter().copied())
    }

    fn utf8i<I>(self, tag: TLVTag, len: usize, iter: I) -> impl Iterator<Item = u8>
    where
        I: Iterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            Either4::First(
                self.tag(tag, TLVValueType::Utf8l)
                    .byte(len as u8)
                    .chain(iter),
            )
        } else if len <= u16::MAX as usize {
            Either4::Second(
                self.tag(tag, TLVValueType::Utf16l)
                    .bytes((len as u16).to_le_bytes())
                    .chain(iter),
            )
        } else if len <= u32::MAX as usize {
            Either4::Third(
                self.tag(tag, TLVValueType::Utf32l)
                    .bytes((len as u32).to_le_bytes())
                    .chain(iter),
            )
        } else {
            Either4::Fourth(
                self.tag(tag, TLVValueType::Utf64l)
                    .bytes((len as u64).to_le_bytes())
                    .chain(iter),
            )
        }
    }

    fn start_struct(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::Struct)
    }

    fn start_array(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::Array)
    }

    fn start_list(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::List)
    }

    fn end_container(self) -> impl Iterator<Item = u8> {
        self.control(TLVControl::from(
            TLVTagType::Anonymous,
            TLVValueType::EndCnt,
        ))
    }

    fn null(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.tag(tag, TLVValueType::Null)
    }

    fn bool(self, tag: TLVTag, val: bool) -> impl Iterator<Item = u8> {
        self.tag(
            tag,
            if val {
                TLVValueType::True
            } else {
                TLVValueType::False
            },
        )
    }
}

impl<T> ToTLVIter for T where T: Iterator<Item = u8> {}

pub(crate) enum Either<F, S> {
    First(F),
    Second(S),
}

impl<F, S> Iterator for Either<F, S>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either::First(i) => i.next(),
            Either::Second(i) => i.next(),
        }
    }
}

enum Either3<F, S, T> {
    First(F),
    Second(S),
    Third(T),
}

impl<F, S, T> Iterator for Either3<F, S, T>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either3::First(i) => i.next(),
            Either3::Second(i) => i.next(),
            Either3::Third(i) => i.next(),
        }
    }
}

enum Either4<F, S, T, U> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
}

impl<F, S, T, U> Iterator for Either4<F, S, T, U>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
    T: Iterator<Item = F::Item>,
    U: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Either4::First(i) => i.next(),
            Either4::Second(i) => i.next(),
            Either4::Third(i) => i.next(),
            Either4::Fourth(i) => i.next(),
        }
    }
}

enum Either5<F, S, T, U, I> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
}

impl<F, S, T, U, I> Iterator for Either5<F, S, T, U, I>
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
            Either5::First(i) => i.next(),
            Either5::Second(i) => i.next(),
            Either5::Third(i) => i.next(),
            Either5::Fourth(i) => i.next(),
            Either5::Fifth(i) => i.next(),
        }
    }
}

enum Either6<F, S, T, U, I, X> {
    First(F),
    Second(S),
    Third(T),
    Fourth(U),
    Fifth(I),
    Sixth(X),
}

impl<F, S, T, U, I, X> Iterator for Either6<F, S, T, U, I, X>
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
            Either6::First(i) => i.next(),
            Either6::Second(i) => i.next(),
            Either6::Third(i) => i.next(),
            Either6::Fourth(i) => i.next(),
            Either6::Fifth(i) => i.next(),
            Either6::Sixth(i) => i.next(),
        }
    }
}
