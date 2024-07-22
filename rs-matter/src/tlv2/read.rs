use crate::error::{Error, ErrorCode};

use super::{BytesRead, BytesSlice, TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType, TLV};

pub trait TLVRead: BytesRead {
    fn try_control(&mut self) -> Result<Option<TLVControl>, Error> {
        let Some(control) = self.next().transpose()? else {
            return Ok(None);
        };

        Ok(Some(TLVControl::new(control)?))
    }

    // fn try_find_ctx<'a>(&mut self, context: u8, ordered: true) -> Result<Option<TLVValueType>, Error> 
    // where 
    //     Self: BytesSlice<'a> + Clone,
    // {
    //     loop {
    //         let Some(control) = self.try_control()? else {
    //             return Ok(None);
    //         };

    //         if matches!(control.value_type(), TLVValueType::EndCnt) {
    //             return Ok(None);
    //         }

    //         if matches!(control.tag_type(), TLVTagType::Context) {
    //             let r_context = self.read()?;

    //             if r_context == context {
    //                 return Ok(Some(control.value_type()));
    //             } else if ordered
    //         } else {
    //             self.skip_tag(control.tag_type())?;
    //         }
            
    //         self.skip_value(control.value_type())?;
    //     }
    // }

    fn skip_value(&mut self, value_type: TLVValueType) -> Result<(), Error> {
        if value_type.is_slice() {
            let len = self.value_len(value_type)?;

            self.skip(len)
        } else {
            Ok(())
        }
    }

    fn skip_tag(&mut self, tag_type: TLVTagType) -> Result<(), Error> {
        self.skip(tag_type.size())
    }

    fn i8(&mut self, value_type: TLVValueType) -> Result<i8, Error> {
        if matches!(value_type, TLVValueType::S8) {
            Ok(i8::from_le_bytes(self.read_all()?))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn u8(&mut self, value_type: TLVValueType) -> Result<u8, Error> {
        if matches!(value_type, TLVValueType::U8) {
            Ok(u8::from_le_bytes(self.read_all()?))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn i16(&mut self, value_type: TLVValueType) -> Result<i16, Error> {
        if matches!(value_type, TLVValueType::S16) {
            Ok(i16::from_le_bytes(self.read_all()?))
        } else {
            self.i8(value_type).map(|a| a.into())
        }
    }

    fn u16(&mut self, value_type: TLVValueType) -> Result<u16, Error> {
        if matches!(value_type, TLVValueType::U16) {
            Ok(u16::from_le_bytes(self.read_all()?))
        } else {
            self.u8(value_type).map(|a| a.into())
        }
    }

    fn i32(&mut self, value_type: TLVValueType) -> Result<i32, Error> {
        if matches!(value_type, TLVValueType::S32) {
            Ok(i32::from_le_bytes(self.read_all()?))
        } else {
            self.i16(value_type).map(|a| a.into())
        }
    }

    fn u32(&mut self, value_type: TLVValueType) -> Result<u32, Error> {
        if matches!(value_type, TLVValueType::U32) {
            Ok(u32::from_le_bytes(self.read_all()?))
        } else {
            self.u16(value_type).map(|a| a.into())
        }
    }

    fn i64(&mut self, value_type: TLVValueType) -> Result<i64, Error> {
        if matches!(value_type, TLVValueType::S64) {
            Ok(i64::from_le_bytes(self.read_all()?))
        } else {
            self.i32(value_type).map(|a| a.into())
        }
    }

    fn u64(&mut self, value_type: TLVValueType) -> Result<u64, Error> {
        if matches!(value_type, TLVValueType::U64) {
            Ok(u64::from_le_bytes(self.read_all()?))
        } else {
            self.u32(value_type).map(|a| a.into())
        }
    }

    fn str<'a>(&mut self, value_type: TLVValueType) -> Result<&'a [u8], Error>
    where
        Self: BytesSlice<'a>,
    {
        if !value_type.is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.slice(value_type)
    }

    fn utf8<'a>(&mut self, value_type: TLVValueType) -> Result<&'a [u8], Error>
    where
        Self: BytesSlice<'a>,
    {
        if !value_type.is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        self.slice(value_type)
    }

    fn slice<'a>(&mut self, value_type: TLVValueType) -> Result<&'a [u8], Error>
    where
        Self: BytesSlice<'a>,
    {
        if !value_type.is_slice() {
            Err(ErrorCode::Invalid)?;
        }

        let len = self.value_len(value_type)?;

        BytesSlice::read_slice(self, Some(len))
    }

    fn str_len(&mut self, value_type: TLVValueType) -> Result<usize, Error> {
        if !value_type.is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.value_len(value_type)
    }

    fn utf8_len(&mut self, value_type: TLVValueType) -> Result<usize, Error> {
        if !value_type.is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        self.value_len(value_type)
    }

    fn slice_len(&mut self, value_type: TLVValueType) -> Result<usize, Error> {
        if !value_type.is_slice() {
            Err(ErrorCode::Invalid)?;
        }

        self.value_len(value_type)
    }

    fn value_len(&mut self, value_type: TLVValueType) -> Result<usize, Error> {
        if let Some(size) = value_type.fixed_size() {
            return Ok(size);
        }

        let read_len = value_type.variable_size_len();

        let len = match read_len {
            1 => self.read()? as usize,
            2 => u16::from_le_bytes(self.read_all()?) as usize,
            4 => u32::from_le_bytes(self.read_all()?) as usize,
            8 => {
                let len = u64::from_le_bytes(self.read_all()?);

                len.try_into().map_err(|_| ErrorCode::InvalidData)?
            }
            _ => unreachable!(),
        };

        Ok(len)
    }

    fn bool(&self, value_type: TLVValueType) -> Result<bool, Error> {
        match value_type {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    fn null(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(value_type, TLVValueType::Null) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn container(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(
            value_type,
            TLVValueType::Struct | TLVValueType::Array | TLVValueType::List
        ) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn structure(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(value_type, TLVValueType::Struct) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn array(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(value_type, TLVValueType::Array) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn list(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(value_type, TLVValueType::List) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    fn end_container(&self, value_type: TLVValueType) -> Result<(), Error> {
        if matches!(value_type, TLVValueType::EndCnt) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    // pub fn find_tag(&self, tag: u32) -> Result<TLVElement<'a>, Error> {
    //     let match_tag: TagType = TagType::Context(tag as u8);

    //     let iter = self.enter().ok_or(ErrorCode::TLVTypeMismatch)?;
    //     for a in iter {
    //         if match_tag == a.tag_type {
    //             return Ok(a);
    //         }
    //     }
    //     Err(ErrorCode::NoTagFound.into())
    // }

    // pub fn check_ctx_tag(&self, tag: u8) -> Result<bool, Error> {
    //     if let TagType::Context(our_tag) = self.tag()? {
    //         if our_tag == tag {
    //             return Ok(true);
    //         }
    //     }

    //     Ok(false)
    // }

    fn try_tlv<'a>(&mut self) -> Result<Option<TLV<'a>>, Error>
    where
        Self: BytesSlice<'a>,
    {
        let Some(control) = self.try_control()? else {
            return Ok(None);
        };

        let tag = self.tag(control.tag_type())?;
        let value = self.value(control.value_type())?;

        Ok(Some(TLV { tag, value }))
    }

    fn tag(&mut self, tag_type: TLVTagType) -> Result<TLVTag, Error> {
        match tag_type {
            TLVTagType::Anonymous => Ok(TLVTag::Anonymous),
            TLVTagType::Context => Ok(TLVTag::Context(self.read()?)),
            TLVTagType::CommonPrf16 => {
                Ok(TLVTag::CommonPrf16(u16::from_le_bytes(self.read_all()?)))
            }
            TLVTagType::CommonPrf32 => {
                Ok(TLVTag::CommonPrf32(u32::from_le_bytes(self.read_all()?)))
            }
            TLVTagType::ImplPrf16 => Ok(TLVTag::ImplPrf16(u16::from_le_bytes(self.read_all()?))),
            TLVTagType::ImplPrf32 => Ok(TLVTag::ImplPrf32(u32::from_le_bytes(self.read_all()?))),
            TLVTagType::FullQual48 => Ok(TLVTag::FullQual48(u64::from_le_bytes([
                self.read()?,
                self.read()?,
                self.read()?,
                self.read()?,
                self.read()?,
                self.read()?,
                0,
                0,
            ]))),
            TLVTagType::FullQual64 => Ok(TLVTag::FullQual64(u64::from_le_bytes(self.read_all()?))),
        }
    }

    fn value<'a>(&mut self, value_type: TLVValueType) -> Result<TLVValue<'a>, Error>
    where
        Self: BytesSlice<'a>,
    {
        if let Some(value) = self._fixed_value(value_type)? {
            Ok(value)
        } else {
            Ok(self._variable_value(value_type)?.unwrap())
        }
    }

    fn _fixed_value(
        &mut self,
        value_type: TLVValueType,
    ) -> Result<Option<TLVValue<'static>>, Error> {
        if value_type.is_slice() {
            return Ok(None);
        }

        let value = match value_type {
            TLVValueType::S8 => TLVValue::S8(i8::from_le_bytes(self.read_all()?)),
            TLVValueType::S16 => TLVValue::S16(i16::from_le_bytes(self.read_all()?)),
            TLVValueType::S32 => TLVValue::S32(i32::from_le_bytes(self.read_all()?)),
            TLVValueType::S64 => TLVValue::S64(i64::from_le_bytes(self.read_all()?)),
            TLVValueType::U8 => TLVValue::U8(u8::from_le_bytes(self.read_all()?)),
            TLVValueType::U16 => TLVValue::U16(u16::from_le_bytes(self.read_all()?)),
            TLVValueType::U32 => TLVValue::U32(u32::from_le_bytes(self.read_all()?)),
            TLVValueType::U64 => TLVValue::U64(u64::from_le_bytes(self.read_all()?)),
            TLVValueType::False => TLVValue::False,
            TLVValueType::True => TLVValue::True,
            TLVValueType::F32 => TLVValue::F32(f32::from_le_bytes(self.read_all()?)),
            TLVValueType::F64 => TLVValue::F64(f64::from_le_bytes(self.read_all()?)),
            TLVValueType::Null => TLVValue::Null,
            TLVValueType::Struct => TLVValue::Struct,
            TLVValueType::Array => TLVValue::Array,
            TLVValueType::List => TLVValue::List,
            TLVValueType::EndCnt => TLVValue::EndCnt,
            _ => unreachable!(),
        };

        Ok(Some(value))
    }

    fn _variable_value<'a>(
        &mut self,
        value_type: TLVValueType,
    ) -> Result<Option<TLVValue<'a>>, Error>
    where
        Self: BytesSlice<'a>,
    {
        if !value_type.is_slice() {
            return Ok(None);
        }

        let len = self.value_len(value_type)?;
        let slice = BytesSlice::read_slice(self, Some(len))?;

        let value = match value_type {
            TLVValueType::Utf8l => TLVValue::Utf8l(slice),
            TLVValueType::Utf16l => TLVValue::Utf16l(slice),
            TLVValueType::Utf32l => TLVValue::Utf32l(slice),
            TLVValueType::Utf64l => TLVValue::Utf64l(slice),
            TLVValueType::Str8l => TLVValue::Str8l(slice),
            TLVValueType::Str16l => TLVValue::Str16l(slice),
            TLVValueType::Str32l => TLVValue::Str32l(slice),
            TLVValueType::Str64l => TLVValue::Str64l(slice),
            _ => unreachable!(),
        };

        Ok(Some(value))
    }
}

impl<T> TLVRead for T where T: BytesRead {}
