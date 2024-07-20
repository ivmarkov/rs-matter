use super::{TagType, WriteElementType, TAG_SHIFT_BITS, TAG_SIZE_MAP};

pub enum EitherIterator<F, S> {
    First(F),
    Second(S),
}

impl<F, S> Iterator for EitherIterator<F, S>
where
    F: Iterator,
    S: Iterator<Item = F::Item>,
{
    type Item = <F as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            EitherIterator::First(f) => f.next(),
            EitherIterator::Second(s) => s.next(),
        }
    }
}

pub struct TLVIteratorBuilder<T>(T);

impl TLVIteratorBuilder<core::iter::Empty<u8>> {
    pub const fn new() -> Self {
        Self(core::iter::empty())
    }
}

impl<T> TLVIteratorBuilder<T>
where
    T: Iterator<Item = u8>,
{
    fn chain<I>(self, iter: I) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
    {
        TLVIteratorBuilder(self.0.chain(iter))
    }

    fn chain_one(self, byte: u8) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.chain(core::iter::once(byte))
    }

    fn chain_bytes<const N: usize>(
        self,
        bytes: [u8; N],
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.chain(bytes.into_iter())
    }

    // TODO: The current method of using writebuf's put methods force us to do
    // at max 3 checks while writing a single TLV (once for control, once for tag,
    // once for value), so do a single check and write the whole thing.
    #[inline(always)]
    fn put_control_tag(
        self,
        tag_type: TagType,
        val_type: WriteElementType,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        let (tag_id, tag_val) = match tag_type {
            TagType::Anonymous => (0_u8, 0),
            TagType::Context(v) => (1, v as u64),
            TagType::CommonPrf16(v) => (2, v as u64),
            TagType::CommonPrf32(v) => (3, v as u64),
            TagType::ImplPrf16(v) => (4, v as u64),
            TagType::ImplPrf32(v) => (5, v as u64),
            TagType::FullQual48(v) => (6, v),
            TagType::FullQual64(v) => (7, v),
        };

        self.chain(core::iter::once(
            ((tag_id) << TAG_SHIFT_BITS) | (val_type as u8),
        ))
        .chain(
            tag_val
                .to_le_bytes()
                .into_iter()
                .take(TAG_SIZE_MAP[tag_id as usize]),
        )
    }

    fn wrap_first<S>(self) -> TLVIteratorBuilder<EitherIterator<T, S>>
    where
        S: Iterator<Item = u8>,
    {
        TLVIteratorBuilder(EitherIterator::First(self.0))
    }

    fn wrap_second<F>(self) -> TLVIteratorBuilder<EitherIterator<F, T>>
    where
        F: Iterator<Item = u8>,
    {
        TLVIteratorBuilder(EitherIterator::Second(self.0))
    }

    pub fn option<F, V, I>(
        self,
        value: Option<V>,
        f: F,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
        F: FnOnce(Self, V) -> TLVIteratorBuilder<I>,
    {
        if let Some(value) = value {
            f(self, value).wrap_first()
        } else {
            self.wrap_second()
        }
    }

    pub fn i8(self, tag_type: TagType, data: i8) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.put_control_tag(tag_type, WriteElementType::S8)
            .chain_bytes(data.to_le_bytes())
    }

    pub fn u8(self, tag_type: TagType, data: u8) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.put_control_tag(tag_type, WriteElementType::U8)
            .chain_one(data)
    }

    pub fn i16(self, tag_type: TagType, data: i16) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        if data >= i8::MIN as i16 && data <= i8::MAX as i16 {
            self.i8(tag_type, data as i8).wrap_first()
        } else {
            self.put_control_tag(tag_type, WriteElementType::S16)
                .chain_bytes(data.to_le_bytes())
                .wrap_second()
        }
    }

    pub fn u16(self, tag_type: TagType, data: u16) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        if data <= 0xff {
            self.u8(tag_type, data as u8).wrap_first()
        } else {
            self.put_control_tag(tag_type, WriteElementType::U16)
                .chain_bytes(data.to_le_bytes())
                .wrap_second()
        }
    }

    pub fn i32(self, tag_type: TagType, data: i32) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        if data >= i8::MIN as i32 && data <= i8::MAX as i32 {
            self.i8(tag_type, data as i8).wrap_first()
        } else if data >= i16::MIN as i32 && data <= i16::MAX as i32 {
            self.i16(tag_type, data as i16).wrap_first().wrap_second()
        } else {
            self.put_control_tag(tag_type, WriteElementType::S32)
                .chain_bytes(data.to_le_bytes())
                .wrap_second()
                .wrap_second()
        }
    }

    pub fn u32(self, tag_type: TagType, data: u32) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        if data <= 0xff {
            self.u8(tag_type, data as u8).wrap_first()
        } else if data <= 0xffff {
            self.u16(tag_type, data as u16).wrap_first().wrap_second()
        } else {
            self.put_control_tag(tag_type, WriteElementType::U32)
                .chain_bytes(data.to_le_bytes())
                .wrap_second()
                .wrap_second()
        }
    }

    // pub fn i64(&mut self, tag_type: TagType, data: i64) -> Result<(), Error> {
    //     if data >= i8::MIN as i64 && data <= i8::MAX as i64 {
    //         self.i8(tag_type, data as i8)
    //     } else if data >= i16::MIN as i64 && data <= i16::MAX as i64 {
    //         self.i16(tag_type, data as i16)
    //     } else if data >= i32::MIN as i64 && data <= i32::MAX as i64 {
    //         self.i32(tag_type, data as i32)
    //     } else {
    //         self.put_control_tag(tag_type, WriteElementType::S64)?;
    //         self.buf.le_i64(data)
    //     }
    // }

    // pub fn u64(&mut self, tag_type: TagType, data: u64) -> Result<(), Error> {
    //     if data <= 0xff {
    //         self.u8(tag_type, data as u8)
    //     } else if data <= 0xffff {
    //         self.u16(tag_type, data as u16)
    //     } else if data <= 0xffffffff {
    //         self.u32(tag_type, data as u32)
    //     } else {
    //         self.put_control_tag(tag_type, WriteElementType::U64)?;
    //         self.buf.le_u64(data)
    //     }
    // }

    pub fn str8<'a>(
        self,
        tag_type: TagType,
        data: &'a [u8],
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8> + 'a>
    where
        T: 'a,
    {
        if data.len() > 255 {
            panic!("use str16() instead");
        }

        self.str8i(tag_type, data.len(), data.into_iter().copied())
    }

    pub fn str8i<I>(
        self,
        tag_type: TagType,
        len: usize,
        iter: I,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
    {
        self.put_control_tag(tag_type, WriteElementType::Str8l)
            .chain_one(len as u8)
            .chain(iter)
    }

    pub fn str16<'a>(
        self,
        tag_type: TagType,
        data: &'a [u8],
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8> + 'a>
    where
        T: 'a,
    {
        self.str16i(tag_type, data.len(), data.into_iter().copied())
    }

    pub fn str16i<I>(
        self,
        tag_type: TagType,
        len: usize,
        iter: I,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
    {
        if len < 256 {
            self.str8i(tag_type, len, iter).wrap_first()
        } else {
            self.put_control_tag(tag_type, WriteElementType::Str16l)
                .chain_bytes((len as u16).to_le_bytes())
                .chain(iter)
                .wrap_second()
        }
    }

    pub fn utf8<'a>(
        self,
        tag_type: TagType,
        data: &'a [u8],
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8> + 'a>
    where
        T: 'a,
    {
        if data.len() > 255 {
            panic!("use utf16() instead");
        }

        self.utf8i(tag_type, data.len(), data.into_iter().copied())
    }

    pub fn utf8i<I>(
        self,
        tag_type: TagType,
        len: usize,
        iter: I,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
    {
        self.put_control_tag(tag_type, WriteElementType::Utf8l)
            .chain_one(len as u8)
            .chain(iter)
    }

    pub fn utf16<'a>(
        self,
        tag_type: TagType,
        data: &'a [u8],
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8> + 'a>
    where
        T: 'a,
    {
        self.utf16i(tag_type, data.len(), data.into_iter().copied())
    }

    pub fn utf16i<I>(
        self,
        tag_type: TagType,
        len: usize,
        iter: I,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>>
    where
        I: Iterator<Item = u8>,
    {
        if len < 256 {
            self.str8i(tag_type, len, iter).wrap_first()
        } else {
            self.put_control_tag(tag_type, WriteElementType::Utf16l)
                .chain_bytes((len as u16).to_le_bytes())
                .chain(iter)
                .wrap_second()
        }
    }

    fn no_val(
        self,
        tag_type: TagType,
        element: WriteElementType,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.put_control_tag(tag_type, element)
    }

    pub fn start_struct(self, tag_type: TagType) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.no_val(tag_type, WriteElementType::Struct)
    }

    pub fn start_array(self, tag_type: TagType) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.no_val(tag_type, WriteElementType::Array)
    }

    pub fn start_list(self, tag_type: TagType) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.no_val(tag_type, WriteElementType::List)
    }

    pub fn end_container(self) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.no_val(TagType::Anonymous, WriteElementType::EndCnt)
    }

    pub fn null(self, tag_type: TagType) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        self.no_val(tag_type, WriteElementType::Null)
    }

    pub fn bool(
        self,
        tag_type: TagType,
        val: bool,
    ) -> TLVIteratorBuilder<impl Iterator<Item = u8>> {
        if val {
            self.no_val(tag_type, WriteElementType::True)
        } else {
            self.no_val(tag_type, WriteElementType::False)
        }
    }

    pub fn build(self) -> T {
        self.0
    }
}
