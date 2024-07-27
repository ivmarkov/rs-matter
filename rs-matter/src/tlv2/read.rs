/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

use crate::error::{Error, ErrorCode};

use super::{TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType};

// For backwards compatibility
pub type TLV<'a> = TLVElement<'a>;

/// A decorator trait for reading TLV-encoded data from Rust `&[u8]` slices.
///
/// This trait is already implemented on the Rust `&[u8]` slice type, so users are not expected
/// to provide implementations of it.
///
/// To use this trait, it must be imported. Once this is done, any `&[u8]` slice can be treated as a `TLV`.
///
/// Semantically, a `TLV` is just a byte slice of TLV-encoded data, and the methods provided by this trait allow:
/// - Reading/parsing the _first_ TLV tag + value element at the beginning of the `&[u8]` slice;
/// - Navigating to the next TLV tag + value element in the slice, by simply returning a `&[u8]` sub-slice.
///
/// An empty `&[]` slice is also a valid TLV slice and designates the end of the TLV stream.
/// However, the only two valid operations on an empty TLV slice are:
/// - `is_empty()` (on the underlying `[u8]`), which returns `true` for empty TLV slices
/// - `next()`, which returns the empty TLV slice itself
///
/// All other methods will return an error if called on an empty TLV slice, as they have the semantics of operating
/// on the _first_ TLV element in the slice.
/// Since the empty slice has no elements, these methods would naturally fail.
///
/// Design approach:
///
/// The design trades memory efficiency for extra computations, in that it simply decorates a Rust `&[u8]` slice,
/// where all operations on the TLVs in the slice are done on-demand, without keeping any interim data. This makes
/// the storage of borrowed TLV data (`&str`, `Bytes`, `TLVArray` or any reference to an un-parsed TLV slice)
/// very efficient, as the TLV data is not copied or transformed in any way, and the size of the borrows is just a
/// regular Rust fat pointer (8 bytes on 32 bit archs and 16 bytes on 64 bit archs).
///
/// (Keeping interim data is still optionally possible, by using the `TLV::tag` and `TLV::value`
/// methods to read the tag and value of a TLV as enums.)
///
/// Representing the TLV stream as a raw `&[u8]` slice also trivializes the traversal of the stream as the stream traversal
/// is represented as returning sub-slices of the original slice.
///
/// Also, this representation naturally allows random-access to the TLV stream, which is necessary for a number of reasons:
/// - Deserialization of TLV structs into Rust structs (with the `FromTLV` derive macro) where the order of the TLV elements
///   of the struct is not known in advance
/// - Delayed in-place initialization of large Rust types with `FromTLV::init_from_tlv` which requires random access for reasons
///   beyond the possible unordering of the TLV struct elements.
///
/// In practice, random access - and in general - representation of the TLV stream as a `&[u8]` slice should be natural and
/// convenient, as the TLV stream usually comes from the network UDP/TCP memory buffers of the Matter transport protocol, and
/// these can and are borrowed as `&[u8]` slices in the upper-layer code for direct reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVElement<'a>(TLVSequence<'a>);

impl<'a> TLVElement<'a> {
    #[inline(always)]
    pub fn new(data: &'a [u8]) -> Self {
        Self(TLVSequence::new(data))
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    pub const fn raw_data(&self) -> &'a [u8] {
        self.0.raw_data()
    }

    /// Parse and return the TLV control byte of the first TLV in the slice.
    #[inline(always)]
    pub fn control(&self) -> Result<TLVControl, Error> {
        self.0.control()
    }

    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        self.0.raw_value()
    }

    /// Read, parse and return the tag of the first TLV in the slice.
    /// #[inline(always)]
    pub fn tag(&self) -> Result<TLVTag, Error> {
        let tag_type = self.control()?.tag_type;

        let slice = self
            .0
            .tag_start()?
            .get(..tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        let tag = match tag_type {
            TLVTagType::Anonymous => TLVTag::Anonymous,
            TLVTagType::Context => TLVTag::Context(slice[0]),
            TLVTagType::CommonPrf16 => {
                TLVTag::CommonPrf16(u16::from_le_bytes(slice.try_into().unwrap()))
            }
            TLVTagType::CommonPrf32 => {
                TLVTag::CommonPrf32(u32::from_le_bytes(slice.try_into().unwrap()))
            }
            TLVTagType::ImplPrf16 => {
                TLVTag::ImplPrf16(u16::from_le_bytes(slice.try_into().unwrap()))
            }
            TLVTagType::ImplPrf32 => {
                TLVTag::ImplPrf32(u32::from_le_bytes(slice.try_into().unwrap()))
            }
            TLVTagType::FullQual48 => TLVTag::FullQual64(u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], 0, 0,
            ])),
            TLVTagType::FullQual64 => {
                TLVTag::FullQual64(u64::from_le_bytes(slice.try_into().unwrap()))
            }
        };

        Ok(tag)
    }

    /// Read, parse and return the value of the first TLV in the slice.
    pub fn value(&self) -> Result<TLVValue<'a>, Error> {
        let control = self.control()?;

        let slice = self.0.container_value(control)?;

        let value = match control.value_type {
            TLVValueType::S8 => TLVValue::S8(i8::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::S16 => TLVValue::S16(i16::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::S32 => TLVValue::S32(i32::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::S64 => TLVValue::S64(i64::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::U8 => TLVValue::U8(u8::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::U16 => TLVValue::U16(u16::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::U32 => TLVValue::U32(u32::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::U64 => TLVValue::U64(u64::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::False => TLVValue::False,
            TLVValueType::True => TLVValue::True,
            TLVValueType::F32 => TLVValue::F32(f32::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::F64 => TLVValue::F64(f64::from_le_bytes(slice.try_into().unwrap())),
            TLVValueType::Utf8l => TLVValue::Utf8l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf16l => TLVValue::Utf16l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf32l => TLVValue::Utf32l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Utf64l => TLVValue::Utf64l(
                core::str::from_utf8(slice).map_err(|_| ErrorCode::TLVTypeMismatch)?,
            ),
            TLVValueType::Str8l => TLVValue::Str8l(slice),
            TLVValueType::Str16l => TLVValue::Str16l(slice),
            TLVValueType::Str32l => TLVValue::Str32l(slice),
            TLVValueType::Str64l => TLVValue::Str64l(slice),
            TLVValueType::Null => TLVValue::Null,
            TLVValueType::Struct => TLVValue::Struct(TLVSequence(slice)),
            TLVValueType::Array => TLVValue::Array(TLVSequence(slice)),
            TLVValueType::List => TLVValue::List(TLVSequence(slice)),
            TLVValueType::EndCnt => Err(ErrorCode::TLVTypeMismatch)?,
        };

        Ok(value)
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i8`.
    /// If the first TLV does not represent a TLV S8 value, the method will return an error.
    pub fn i8(&self) -> Result<i8, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S8) {
            Ok(i8::from_le_bytes(
                self.0
                    .value_start(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u8`.
    /// If the first TLV does not represent a TLV U8 value, the method will return an error.
    pub fn u8(&self) -> Result<u8, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U8) {
            Ok(u8::from_le_bytes(
                self.0
                    .value_start(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i16`.
    /// If the first TLV does not represent a TLV S8 or S16 value, the method will return an error.
    pub fn i16(&self) -> Result<i16, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S16) {
            Ok(i16::from_le_bytes(
                self.0
                    .value_start(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i8().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u16`.
    /// If the first TLV does not represent a TLV U8 or U16 value, the method will return an error.
    pub fn u16(&self) -> Result<u16, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U16) {
            Ok(u16::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u8().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i32`.
    /// If the first TLV does not represent a TLV S8, S16, S32 value, the method will return an error.
    pub fn i32(&self) -> Result<i32, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S32) {
            Ok(i32::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i16().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u32`.
    /// If the first TLV does not represent a TLV U8, U16, U32 value, the method will return an error.
    pub fn u32(&self) -> Result<u32, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U32) {
            Ok(u32::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u16().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i64`.
    /// If the first TLV does not represent a TLV S8, S16, S32, S64 value, the method will return an error.
    pub fn i64(&self) -> Result<i64, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::S64) {
            Ok(i64::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.i32().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u64`.
    /// If the first TLV does not represent a TLV U8, U16, U32, U64 value, the method will return an error.
    pub fn u64(&self) -> Result<u64, Error> {
        let control = self.control()?;

        if matches!(control.value_type, TLVValueType::U64) {
            Ok(u64::from_le_bytes(
                self.0
                    .value(control)?
                    .try_into()
                    .map_err(|_| ErrorCode::InvalidData)?,
            ))
        } else {
            self.u32().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV Octet String.
    /// If the first TLV does not represent a TLV Octet String value (Strl8, Strl16, Strl32 or Strl64), the method will return an error.
    pub fn str(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if !control.value_type.is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV UTF-8 String.
    /// If the first TLV does not represent a TLV UTF-8 String value (Utf8l, Utf16l, Utf32l or Utf64l), the method will return an error.
    pub fn utf8(&self) -> Result<&'a str, Error> {
        let control = self.control()?;

        if !control.value_type.is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        core::str::from_utf8(self.0.value(control)?).map_err(|_| ErrorCode::InvalidData.into())
    }

    /// Read, parse and return the value of the first TLV in the slice as a byte slice.
    /// If the first TLV does not represent either a TLV Octet String or a TLV UTF-8 String,
    /// the method will return an error.
    pub fn octets(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if control.value_type.variable_size_len() == 0 {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV boolean.
    /// If the first TLV does not represent a TLV boolean value (True or False), the method will return an error.
    pub fn bool(&self) -> Result<bool, Error> {
        let control = self.control()?;

        match control.value_type {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    /// Return `true` if the first TLV in the slice is a container (i.e. a TLV array, list or struct).
    pub fn is_container(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type.is_container())
    }

    /// Return `true` if the first TLV in the slice is a container end.
    pub fn is_container_end(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type.is_container_end())
    }

    /// Confirm that the first TLV in the slice is a null TLV.
    /// If the first TLV is not a null TLV, the method will return an error.
    pub fn null(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type, TLVValueType::Null) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is a struct container.
    /// If the first TLV is not a struct container, the method will return an error.
    pub fn structure(&self) -> Result<TLVSequence<'a>, Error> {
        self.r#struct()
    }

    pub fn r#struct(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Struct) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is an array container.
    /// If the first TLV is not an array container, the method will return an error.
    pub fn array(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Array) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is a list container.
    /// If the first TLV is not a list container, the method will return an error.
    pub fn list(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::List) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Enter the first container in the slice by returning a TLV sub-slice positioned at the
    /// first element in the container (or at the container end TLV, if the container is empty).
    /// If the first TLV is not a container, the method will return an error.
    pub fn container(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(
            self.control()?.value_type,
            TLVValueType::List | TLVValueType::Array | TLVValueType::Struct
        ) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is tagged with an anonymous tag.
    /// If the first TLV is not tagged with an anonymous tag, the method will return an error.
    pub fn confirm_anon(&self) -> Result<(), Error> {
        if matches!(self.control()?.tag_type, TLVTagType::Anonymous) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Retrieve the context ID of the first TLV in the slice.
    /// If the first TLV is not tagged with a context tag, the method will return `None`.
    pub fn try_ctx(&self) -> Result<Option<u8>, Error> {
        let control = self.control()?;

        if matches!(control.tag_type, TLVTagType::Context) {
            Ok(Some(
                *self
                    .0
                    .tag(control.tag_type)?
                    .get(0)
                    .ok_or(ErrorCode::TLVTypeMismatch)?,
            ))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVSequence<'a>(pub(crate) &'a [u8]);

impl<'a> TLVSequence<'a> {
    pub const EMPTY: Self = Self(&[]);

    #[inline(always)]
    const fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[inline(always)]
    pub const fn raw_data(&self) -> &'a [u8] {
        self.0
    }

    #[inline(always)]
    pub fn iter(&self) -> TLVContainerIter<'a> {
        TLVContainerIter::new(self.clone())
    }

    pub fn find_ctx(&self, ctx: u8) -> Result<TLVElement<'a>, Error> {
        for elem in self.iter() {
            let elem = elem?;

            if let Some(elem_ctx) = elem.try_ctx()? {
                if elem_ctx == ctx {
                    return Ok(elem);
                }
            }
        }

        Ok(TLVElement(Self::EMPTY))
    }

    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        self.container_value(control)
    }

    fn next_enter(&self) -> Result<Self, Error> {
        if self.is_empty() {
            return Ok(Self::EMPTY);
        }

        let control = self.control()?;

        Ok(Self(self.next_start(control)?))
    }

    fn container_next(&self) -> Result<Self, Error> {
        let control = self.control()?;

        if control.value_type.is_container_end() {
            control.confirm_container_end()?;

            return Ok(Self::EMPTY);
        }

        let mut next = self.next_enter()?;

        if control.value_type.is_container() {
            let mut level = 1;

            while level > 0 {
                let control = next.control()?;

                if control.value_type.is_container_end() {
                    control.confirm_container_end()?;
                    level -= 1;
                } else if control.value_type.is_container() {
                    level += 1;
                }

                next = next.next_enter()?;
            }
        }

        Ok(next)
    }

    #[inline(always)]
    fn control(&self) -> Result<TLVControl, Error> {
        TLVControl::parse(*self.0.get(0).ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    #[inline(always)]
    fn tag_start(&self) -> Result<&'a [u8], Error> {
        self.0.get(1..).ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn tag(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        self.tag_start()?
            .get(..tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn value_len_start(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        self.tag_start()?
            .get(tag_type.size()..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn value_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        self.value_len_start(control.tag_type)?
            .get(control.value_type.variable_size_len()..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        self.value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn container_value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.container_value_len(control)?;

        self.value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    #[inline(always)]
    fn value_len(&self, control: TLVControl) -> Result<usize, Error> {
        if let Some(fixed_size) = control.value_type.fixed_size() {
            return Ok(fixed_size);
        }

        let size_len = control.value_type.variable_size_len();

        let value_len_slice = self
            .value_len_start(control.tag_type)?
            .get(..size_len)
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        let len = match size_len {
            1 => u8::from_be_bytes(value_len_slice.try_into().unwrap()) as usize,
            2 => u16::from_le_bytes(value_len_slice.try_into().unwrap()) as usize,
            4 => u32::from_le_bytes(value_len_slice.try_into().unwrap()) as usize,
            8 => u64::from_le_bytes(value_len_slice.try_into().unwrap()) as usize,
            _ => unreachable!(),
        };

        Ok(len)
    }

    #[inline(always)]
    fn container_value_len(&self, control: TLVControl) -> Result<usize, Error> {
        if control.value_type.is_container() {
            let mut next = self.clone();
            let mut len = 0;
            let mut level = 1;

            while level > 0 {
                next = next.next_enter()?;
                len += next.len()?;

                let control = next.control()?;

                if control.value_type.is_container_end() {
                    control.confirm_container_end()?;
                    level -= 1;
                } else if control.value_type.is_container() {
                    level += 1;
                }
            }

            Ok(len)
        } else {
            self.value_len(control)
        }
    }

    #[inline(always)]
    fn len(&self) -> Result<usize, Error> {
        let control = self.control()?;

        self.value_len(control).map(|value_len| {
            1 + control.tag_type.size() + control.value_type.variable_size_len() + value_len
        })
    }

    #[inline(always)]
    fn next_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        self.value_start(control)?
            .get(value_len..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }
}

#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct TLVContainerIter<'a>(TLVSequence<'a>);

impl<'a> TLVContainerIter<'a> {
    pub const fn new(seq: TLVSequence<'a>) -> Self {
        Self(seq)
    }
}

impl<'a> Iterator for TLVContainerIter<'a> {
    type Item = Result<TLVElement<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .container_next()
            .map(|next_seq| (!next_seq.is_empty()).then(|| TLVElement(next_seq)))
            .transpose()
    }
}

// //#[cfg(test)]
// mod test {
//     use super::TLV;

//     fn test1() {
//         let slice: &[u8] = &[0, 1, 2];

//         test2(&slice.into());
//     }

//     fn test2(tlv: &TLV) {
//         tlv.control().unwrap();
//     }
// }
