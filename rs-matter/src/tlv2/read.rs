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
pub trait TLV<'a>: Clone {
    /// Parse and return the TLV control byte of the first TLV in the slice.
    #[inline(always)]
    fn control(&self) -> Result<TLVControl, Error> {
        if self.ptr().is_empty() {
            Err(ErrorCode::TLVTypeMismatch)?;
        }

        TLVControl::new(self.ptr()[0])
    }

    /// Return the length of the first TLV in the slice.
    #[inline(always)]
    fn tlv_len(&self) -> Result<usize, Error> {
        let control = self.control()?;

        self.value_size().map(|value_size| {
            1 + control.tag_type().size() + control.value_type().variable_size_len() + value_size
        })
    }

    /// Return the slice of the first TLV in the slice.
    #[inline(always)]
    fn tlv_slice(&self) -> Result<&'a [u8], Error> {
        self.ptr()
            .get(..self.tlv_len()?)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return the slice of the content of the first TLV in the slice.
    ///
    /// If the first TLV in the slice is not a container, this method will return an error.
    fn tlv_container_content_slice(&self) -> Result<&'a [u8], Error> {
        let start = self.enter_container()?;
        let mut len = 0;

        let mut tlv = start;

        while !tlv.is_container_end()? {
            len += tlv.tlv_len()?;
            tlv = tlv.container_next()?;
        }

        Ok(&self.ptr()[..len])
    }

    /// Return the slice containing the tag of the first TLV in the slice.
    ///
    /// The tag is encoded right after the first control byte, and might be 0 for anonymous tags, or a single byte for
    /// context tags.
    #[inline(always)]
    fn tag_slice(&self) -> Result<&'a [u8], Error> {
        let tag_type = self.control()?.tag_type();

        let slice = self
            .ptr()
            .get(1..1 + tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        Ok(slice)
    }

    /// Read, parse and return the tag of the first TLV in the slice.
    fn tag(&self) -> Result<TLVTag, Error> {
        let tag_type = self.control()?.tag_type();

        let slice = self.tag_slice()?;

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

    /// Return the size of the value of the first TLV in the slice.
    ///
    /// The size of the value (for variable-sized TLVs, i.e. for octet and utf8 strings)
    /// is encoded right after the tag, and will not be present for fixed-size TLVs.
    ///
    /// This method works for both fixed-size and variable-size TLVs and will return the size of the value in bytes.
    #[inline(always)]
    fn value_size(&self) -> Result<usize, Error> {
        let control = self.control()?;

        let value_type = control.value_type();
        if let Some(len) = value_type.fixed_size() {
            Ok(len)
        } else {
            let tag_len = control.tag_type().size();

            let size_len = value_type.variable_size_len();
            let len_slice = self
                .ptr()
                .get(1 + tag_len..1 + tag_len + size_len)
                .ok_or(ErrorCode::TLVTypeMismatch)?;

            let len = match size_len {
                1 => u8::from_be_bytes(len_slice.try_into().unwrap()) as usize,
                2 => u16::from_le_bytes(len_slice.try_into().unwrap()) as usize,
                4 => u32::from_le_bytes(len_slice.try_into().unwrap()) as usize,
                8 => u64::from_le_bytes(len_slice.try_into().unwrap()) as usize,
                _ => unreachable!(),
            };

            Ok(len)
        }
    }

    /// Return the slice of the value of the first TLV in the slice.
    #[inline(always)]
    fn value_slice(&self) -> Result<&'a [u8], Error> {
        let tag_len = self.control()?.tag_type().size();
        let value_len_size = self.control()?.value_type().variable_size_len();

        let offset = 1 + tag_len + value_len_size;

        let value_size = self.value_size()?;

        let slice = self
            .ptr()
            .get(offset..offset + value_size)
            .ok_or(ErrorCode::TLVTypeMismatch)?;

        Ok(slice)
    }

    /// Read, parse and return the value of the first TLV in the slice.
    fn value(&self) -> Result<TLVValue<'a>, Error> {
        let value_type = self.control()?.value_type();

        let slice = self.value_slice()?;

        let value = match value_type {
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
            TLVValueType::Struct => TLVValue::Struct,
            TLVValueType::Array => TLVValue::Array,
            TLVValueType::List => TLVValue::List,
            TLVValueType::EndCnt => TLVValue::EndCnt,
        };

        Ok(value)
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i8`.
    /// If the first TLV does not represent a TLV S8 value, the method will return an error.
    fn i8(&self) -> Result<i8, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::S8) {
            Ok(i8::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u8`.
    /// If the first TLV does not represent a TLV U8 value, the method will return an error.
    fn u8(&self) -> Result<u8, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::U8) {
            Ok(u8::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i16`.
    /// If the first TLV does not represent a TLV S8 or S16 value, the method will return an error.
    fn i16(&self) -> Result<i16, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::S16) {
            Ok(i16::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.i8().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u16`.
    /// If the first TLV does not represent a TLV U8 or U16 value, the method will return an error.
    fn u16(&self) -> Result<u16, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::U16) {
            Ok(u16::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.u8().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i32`.
    /// If the first TLV does not represent a TLV S8, S16, S32 value, the method will return an error.
    fn i32(&self) -> Result<i32, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::S32) {
            Ok(i32::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.i16().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u32`.
    /// If the first TLV does not represent a TLV U8, U16, U32 value, the method will return an error.
    fn u32(&self) -> Result<u32, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::U32) {
            Ok(u32::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.u16().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as an `i64`.
    /// If the first TLV does not represent a TLV S8, S16, S32, S64 value, the method will return an error.
    fn i64(&self) -> Result<i64, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::S64) {
            Ok(i64::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.i32().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a `u64`.
    /// If the first TLV does not represent a TLV U8, U16, U32, U64 value, the method will return an error.
    fn u64(&self) -> Result<u64, Error> {
        if matches!(self.control()?.value_type(), TLVValueType::U64) {
            Ok(u64::from_le_bytes(self.value_slice()?.try_into().unwrap()))
        } else {
            self.u32().map(|a| a.into())
        }
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV Octet String.
    /// If the first TLV does not represent a TLV Octet String value (Strl8, Strl16, Strl32 or Strl64), the method will return an error.
    fn str(&self) -> Result<&'a [u8], Error> {
        if !self.control()?.value_type().is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.value_slice()
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV UTF-8 String.
    /// If the first TLV does not represent a TLV UTF-8 String value (Utf8l, Utf16l, Utf32l or Utf64l), the method will return an error.
    fn utf8(&self) -> Result<&'a str, Error> {
        if !self.control()?.value_type().is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        core::str::from_utf8(self.value_slice()?).map_err(|_| ErrorCode::InvalidData.into())
    }

    /// Read, parse and return the value of the first TLV in the slice as a byte slice.
    /// If the first TLV does not represent either a TLV Octet String or a TLV UTF-8 String,
    /// the method will return an error.
    fn octets(&self) -> Result<&'a [u8], Error> {
        if self.control()?.value_type().variable_size_len() == 0 {
            Err(ErrorCode::Invalid)?;
        }

        self.value_slice()
    }

    /// Read, parse and return the value of the first TLV in the slice as a TLV boolean.
    /// If the first TLV does not represent a TLV boolean value (True or False), the method will return an error.
    fn bool(&self) -> Result<bool, Error> {
        match self.control()?.value_type() {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    /// Return `true` if the first TLV in the slice is a container (i.e. a TLV array, list or struct).
    fn is_container(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type().is_container())
    }

    /// Return `true` if the first TLV in the slice is a container end.
    fn is_container_end(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type().is_container_end())
    }

    /// Confirm that the first TLV in the slice is a null TLV.
    /// If the first TLV is not a null TLV, the method will return an error.
    fn confirm_null(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type(), TLVValueType::Null) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is a container.
    /// If the first TLV is not a container, the method will return an error.
    fn confirm_container(&self) -> Result<(), Error> {
        if matches!(
            self.control()?.value_type(),
            TLVValueType::Struct | TLVValueType::Array | TLVValueType::List
        ) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is a struct container.
    /// If the first TLV is not a struct container, the method will return an error.
    fn confirm_struct(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type(), TLVValueType::Struct) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is an array container.
    /// If the first TLV is not an array container, the method will return an error.
    fn confirm_array(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type(), TLVValueType::Array) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is a list container.
    /// If the first TLV is not a list container, the method will return an error.
    fn confirm_list(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type(), TLVValueType::List) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is an end container TLV.
    /// If the first TLV is not an end container TLV, the method will return an error.
    fn confirm_end_container(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type(), TLVValueType::EndCnt) {
            Ok(())
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Confirm that the first TLV in the slice is tagged with an anonymous tag.
    /// If the first TLV is not tagged with an anonymous tag, the method will return an error.
    fn confirm_anon(&self) -> Result<(), Error> {
        if matches!(self.control()?.tag_type(), TLVTagType::Anonymous) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Retrieve the context ID of the first TLV in the slice.
    /// If the first TLV is not tagged with a context tag, the method will return `None`.
    fn try_ctx(&self) -> Result<Option<u8>, Error> {
        if matches!(self.control()?.tag_type(), TLVTagType::Context) {
            Ok(Some(self.tag_slice()?[0]))
        } else {
            Ok(None)
        }
    }

    /// Enter the first container in the slice by returning a TLV sub-slice positioned at the
    /// first element in the container (or at the container end TLV, if the container is empty).
    /// If the first TLV is not a container, the method will return an error.
    fn enter_container(&self) -> Result<Self, Error>
    where
        Self: Sized,
    {
        self.confirm_container()?;
        self.next()
    }

    /// Enter the first struct container in the slice by returning a TLV sub-slice positioned at the
    /// first element in the struct (or at the container end TLV, if the struct is empty).
    /// If the first TLV is not a struct container, the method will return an error.
    fn enter_struct(&self) -> Result<Self, Error>
    where
        Self: Sized,
    {
        self.confirm_struct()?;
        self.next()
    }

    /// Enter the first array container in the slice by returning a TLV sub-slice positioned at the
    /// first element in the array (or at the container end TLV, if the array is empty).
    /// If the first TLV is not an array container, the method will return an error.
    fn enter_array(&self) -> Result<Self, Error>
    where
        Self: Sized,
    {
        self.confirm_array()?;
        self.next()
    }

    /// Enter the first list container in the slice by returning a TLV sub-slice positioned at the
    /// first element in the list (or at the container end TLV, if the list is empty).
    /// If the first TLV is not a list container, the method will return an error.
    fn enter_list(&self) -> Result<Self, Error>
    where
        Self: Sized,
    {
        self.confirm_list()?;
        self.next()
    }

    /// Find the first TLV in the slice tagged with a specific context ID.
    /// If no such TLV is found, the method will return an empty TLV.
    ///
    /// This method is useful for finding a specific TLV in a container whose elements are
    /// tagged with context tags (i.e. structs), because the TLV specification does not mandate
    /// that the elements of a TLV struct arrive in an ordered manner.
    fn find_ctx(&self, ctx: u8) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut tlv = self.clone();

        loop {
            if tlv.is_container_end()? {
                break Ok(Self::empty());
            }

            if tlv.try_ctx()? == Some(ctx) {
                break Ok(tlv);
            }

            tlv = tlv.container_next()?;
        }
    }

    /// Jumps to the next TLV in the slice
    fn container_next(&self) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if self.is_container_end()? {
            return Ok(self.clone());
        }

        if !self.is_container()? {
            return self.next();
        }

        let mut tlv = self.clone();
        let mut level: usize = 1;

        loop {
            tlv = tlv.next()?;

            if tlv.is_container()? {
                level += 1;
            } else if tlv.is_container_end()? {
                level -= 1;
            }

            if level == 0 {
                break;
            }
        }

        if tlv.is_container_end()? {
            tlv = tlv.next()?;
        }

        Ok(tlv)
    }

    /// Return the next TLV in the slice.
    /// If the end of the slice is reached, returns a TLV for an empty slice.
    ///
    /// A TLV for an empty slice is not parseable, as it designates the end of the TLV stream,
    /// i.e. all methods except `next` on an empty slice will return an error.
    ///
    /// A TLV slice can be checked for being empty by simply using `[u8]::is_empty()` or
    /// `TLV::ptr().is_empty()`.
    fn next(&self) -> Result<Self, Error>
    where
        Self: Sized;

    /// Construct an empty TLV slice.
    fn empty() -> Self
    where
        Self: Sized;

    /// Return the whole slice itself as a `&[u8]`.
    ///
    /// Users are not expected to call this method directly.
    /// It is only necessary so that the rest of the trait methods can get access to the underlying `[u8]` slice
    /// for which the `TLV` trait is implemented.
    fn ptr(&self) -> &'a [u8];
}

impl<'a> TLV<'a> for &'a [u8] {
    #[inline(always)]
    fn ptr(&self) -> &'a [u8] {
        self
    }

    fn empty() -> Self {
        &[]
    }

    fn next(&self) -> Result<Self, Error> {
        Ok(self.get(self.tlv_len()?..).unwrap_or(&[]))
    }
}

//#[cfg(test)]
mod test {
    use super::TLV;

    fn test1() {
        test2(&[0, 1, 2]);
    }

    fn test2(tlv: &[u8]) {
        tlv.control().unwrap();
    }
}
