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

use core::fmt;

use crate::error::{Error, ErrorCode};

use super::{pad, TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType};

/// A newtype for reading TLV-encoded data from Rust `&[u8]` slices.
///
/// Semantically, a `TLVElement` is just a byte slice of TLV-encoded data/stream, and the methods provided by this therefore
/// allow to parse - on the fly - the byte slice as TLV.
///
/// Note also, that - as per the Matter Core Spec:
/// - A valid TLV stream always represents a SINGLE TLV element (hence why this type is named `TLVElement` and why we claim
///   that it represents also a whole TLV stream)
/// - If there is a need to encode more than one TLV element, they should be encoded in a TLV container (array, list or struct),
///   hence we end up again with a single TLV element, which represents the whole container.
///
/// Parsing/reading/validating the TLV of the slice represented by a `TLVElement` is done on-demand. What this means is that:
/// - `TLVElement::new(slice)` always succeeds, even when the passed slice contains invalid TLV data
/// - As the various methods of `TLVElement` type are called, the data in the slice is parsed and validated on the fly. Hence why all methods
///   on `TLVElement` except `is_empty` are fallible.
///
/// A TLV element can currently be constructed from an empty `&[]` slice, but the empty slice does not actually represent a TLV element,
/// so all methods except `TLVElement::is_empty` would fail on a `TLVElement` constructed from an empty slice. The only reason why empty slices
/// are currently allowed is to simplify the `FromTLV` trait a bit by representing data which was not found (i.e. optional data in TLV structures)
/// as a TLVElement with an empty slice.
///
/// The design approach from above (on-demand parsing/validation) trades memory efficiency for extra computations, in that by simply decorating
/// a Rust `&[u8]` slice anbd post-poning everything else post-construction it ensures the size of a `TLVElement` is equal to the size of the wrapped
/// `&[u8]` slice - i.e., a regular Rust fat pointer (8 bytes on 32 bit archs and 16 bytes on 64 bit archs).
///
/// Furthermore, all accompanying types of `TLVElement`, like `TLVSequence`, `TLVContainerIter` and `TLVArray` are also just newtypes over byte slices
/// and therefore just as small.
///
/// (Keeping interim data is still optionally possible, by using the `TLV::tag` and `TLV::value`
/// methods to read the tag and value of a TLV as enums.)
///
/// As for representing the encoded TLV stream itself as a raw `&[u8]` slice - this trivializes the traversal of the stream
/// as the stream traversal is represented as returning sub-slices of the original slice. It also allows `FromTLV` implementations where
/// the data is borrowed directly from the `&[u8]` slice representing the encoded TLV stream without any data moves. Types that implement
/// such borrowing are e.g.:
/// - `&str` (used to represent borrowed TLV UTF-8 strings)
/// - `Bytes<'a>` (a newtype over `&'a [u8]` - used to represent TLV octet strings)
/// - `TLVArray`
/// - `TLVSequence` - discussed below
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
    /// Create a new `TLVElement` from a byte slice, where the byte slice contains an encoded TLV stream (a TLV element).
    #[inline(always)]
    pub fn new(data: &'a [u8]) -> Self {
        Self(TLVSequence(data))
    }

    /// Return `true` if the wrapped byte slice is the empty `&[]` slice.
    /// Empty byte slices do not represent valid TLV data, as the TLV data should be a valid TLV element,
    /// yet they are useful when implementing the `FromTLV` trait.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.0 .0.is_empty()
    }

    /// Return a copy of the wrapped TLV byte slice.
    #[inline(always)]
    pub const fn raw_data(&self) -> &'a [u8] {
        self.0 .0
    }

    /// Return the TLV control byte of the first TLV in the slice.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the first byte of the slice does
    /// not represent a valid TLV control byte or if the wrapped byte slice is empty.
    #[inline(always)]
    pub fn control(&self) -> Result<TLVControl, Error> {
        self.0.control()
    }

    /// Return a sub-slice of the wrapped byte slice that designates the encoded value
    /// of this `TLVElement` (i.e. the raw "value" aspect of the Tag-Length-Value encoding)
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// For getting a parsed value, use `value` or any of the other helper methods that
    /// retrieve a value of a certain type.
    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        self.0.raw_value()
    }

    /// Return a `TLVTag` enum representing the tag of this `TLVElement`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV
    /// byte slice contains malformed TLV data.
    #[inline(always)]
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

    /// Return a `TLVValue` enum representing the value of this `TLVElement`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
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

    /// Return the value of this TLV element as an `i8`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8 value.
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

    /// Return the value of this TLV element as a `u8`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8 value.
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

    /// Return the value of this TLV element as an `i16`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8 or S16 value.
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

    /// Return the value of this TLV element as a `u16`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8 or U16 value.
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

    /// Return the value of this TLV element as an `i32`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8, S16 or S32 value.
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

    /// Return the value of this TLV element as a `u32`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8, U16 or U32 value.
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

    /// Return the value of this TLV element as an `i64`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV S8, S16, S32 or S64 value.
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

    /// Return the value of this TLV element as a `u64`.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV U8, U16, U32 or U64 value.
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

    /// Return the value of this TLV element as a byte slice.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV Octet String.
    pub fn str(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if !control.value_type.is_str() {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Return the value of this TLV element as a UTF-8 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV UTF-8 String.
    pub fn utf8(&self) -> Result<&'a str, Error> {
        let control = self.control()?;

        if !control.value_type.is_utf8() {
            Err(ErrorCode::Invalid)?;
        }

        core::str::from_utf8(self.0.value(control)?).map_err(|_| ErrorCode::InvalidData.into())
    }

    /// Return the value of this TLV element as a UTF-16 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV UTF-8 String or a TLV octet string.
    pub fn octets(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        if control.value_type.variable_size_len() == 0 {
            Err(ErrorCode::Invalid)?;
        }

        self.0.value(control)
    }

    /// Return the value of this TLV element as a UTF-16 string.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV boolean.
    pub fn bool(&self) -> Result<bool, Error> {
        let control = self.control()?;

        match control.value_type {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    /// Return `true` if this TLV element is as a container (i.e., a struct, array or list).
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    pub fn is_container(&self) -> Result<bool, Error> {
        Ok(self.control()?.value_type.is_container())
    }

    /// Confirm that this TLV element contains a TLV null value.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV null value.
    pub fn null(&self) -> Result<(), Error> {
        if matches!(self.control()?.value_type, TLVValueType::Null) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Return the content of the struct container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV struct.
    pub fn structure(&self) -> Result<TLVSequence<'a>, Error> {
        self.r#struct()
    }

    /// Return the content of the struct container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV struct.
    ///
    /// (Same as method `structure` but with a special name to ease the `FromTLV` trait derivation for
    /// user types.)
    pub fn r#struct(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Struct) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::TLVTypeMismatch.into())
        }
    }

    /// Return the content of the array container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV array.
    pub fn array(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::Array) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Return the content of the list container represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV list.
    pub fn list(&self) -> Result<TLVSequence<'a>, Error> {
        if matches!(self.control()?.value_type, TLVValueType::List) {
            self.0.next_enter()
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    /// Return the content of the container (array, struct or list) represented by this TLV element.
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the value of the TLV element is not
    /// a TLV container.
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

    /// Confirm that this TLV element is tagged with the anonymous tag (`TLVTag::Anonymous`).
    ///
    /// Returns an error with code `ErrorCode::TLVTypeMismatch` if the wrapped TLV byte slice
    /// contains malformed TLV data.
    ///
    /// Returns an error with code `ErrorCode::InvalidData` if the tag of the TLV element is not
    /// the anonymous tag.
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

    fn fmt(&self, indent: usize, f: &mut fmt::Formatter) -> fmt::Result {
        pad(indent, f)?;

        let tag = self.tag().map_err(|_| fmt::Error)?;

        tag.fmt(f)?;

        if !matches!(tag.tag_type(), TLVTagType::Anonymous) {
            write!(f, ": ")?;
        }

        let value = self.value().map_err(|_| fmt::Error)?;

        value.fmt(indent, f)
    }
}

impl<'a> fmt::Display for TLVElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

/// A newtype for iterating over the `TLVElement` "child" instances contained in `TLVElement` which is a TLV container
/// (array, struct or list).
/// (Internally, `TLVSequence` might be used for other purposes, but the external contract is that only the one from above.)
///
/// Just like `TLVElement`, `TLVSequence` is a newtype over a byte slice - the byte sub-slice of the parent `TLVElement`
/// container where its value starts.
///
/// Unlike `TLVElement`, `TLVSequence` - as the name suggests - represents a sequence of 0, 1 or more `TLVElements`.
/// The only public API of `TLVSequence` however is the `iter` method which returns a `TLVContainerIter` iterator over
/// the `TLVElement` instances in the sequence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TLVSequence<'a>(pub(crate) &'a [u8]);

impl<'a> TLVSequence<'a> {
    const EMPTY: Self = Self(&[]);

    /// Return an iterator over the `TLVElement` instances in this `TLVSequence`.
    #[inline(always)]
    pub fn iter(&self) -> TLVContainerIter<'a> {
        TLVContainerIter::new(self.clone())
    }

    /// A convenience utility that returns the first `TLVElement` in the sequence
    /// which is tagged with a context tag (`TLVTag::Context`) where the context ID
    /// is matching the ID passed in the `ctx` parameter.
    ///
    /// If there is no TLV element tagged with a context tag with the matching ID, the method
    /// will return an empty `TLVElement`.
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

    /// Return a raw byte sub-slice representing the TLV-encoded elements and only those
    /// elements that belong to the TLV container whose elements are represented by this `TLVSequence` instance.
    ///
    /// This method is necessary, because both `TLVElement` instances, as well as `TLVSequence` instances - for optimization purposes -
    /// might be constructed during iteration on slices which are technically longer than the actual TLV-encoded data
    /// they represent.
    ///
    /// So in case the user is need of the actual, exact raw representation of a TLV container **value**, this method is provided.
    #[inline(always)]
    pub fn raw_value(&self) -> Result<&'a [u8], Error> {
        let control = self.control()?;

        self.container_value(control)
    }

    /// Return a sub-sequence representing the TLV-encoded elements after the first one on the sequence.
    ///
    /// As the name suggests, if the first TLV element in the sequence is a container, this method will return a sub-sequence
    /// which corresponds to the first element INSIDE the container.
    ///
    /// If the sequence is empty, or the sequence contains just one element, the method will return an empty `TLVSequence`.
    ///
    /// Note also that this method will also return sub-sequences where the first element might be a TLV `TLVValueType::EndCnt` marker,
    /// which - formally speaking - is not a TLVElement, but a TLV control byte that marks the end of a container.
    fn next_enter(&self) -> Result<Self, Error> {
        if self.0.is_empty() {
            return Ok(Self::EMPTY);
        }

        let control = self.control()?;

        Ok(Self(self.next_start(control)?))
    }

    /// Return a sub-sequence representing the TLV-encoded elements after the first one on the sequence.
    ///
    /// As the name suggests, if the first TLV element in the sequence is a container, this method will return a sub-sequence
    /// which corresponds to the elements AFTER the container element (i.e., the method "skips over" the elements of the container element).
    ///
    /// If the sequence is empty, or the sequence contains just one element, the method will return an empty `TLVSequence`.
    ///
    /// Unlike `next_enter`, this method will never return a TLV `TLVValueType::EndCnt` marker,
    /// which - formally speaking - is not a TLVElement, but a TLV control byte that marks the end of a container.
    ///
    /// Instead, if a TLV `TLVValueType::EndCnt` marker is encountered, the method will return the empty sequence.
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

    /// Return the TLV control byte of the first TLV in the sequence.
    #[inline(always)]
    fn control(&self) -> Result<TLVControl, Error> {
        TLVControl::parse(*self.0.get(0).ok_or(ErrorCode::TLVTypeMismatch)?)
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the tag payload
    /// of the first TLV in the sequence.
    ///
    /// If there is no tag payload (i.e., the tag is of type `TLVTagType::Anonymous`), the returned sub-slice
    /// will designate the start of the TLV element value or value length.
    #[inline(always)]
    fn tag_start(&self) -> Result<&'a [u8], Error> {
        self.0.get(1..).ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the tag payload
    /// of the first TLV in the sequence.
    ///
    /// If there is no tag payload (i.e., the tag is of type `TLVTagType::Anonymous`), the returned sub-slice
    /// will be the empty slice.
    #[inline(always)]
    fn tag(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        self.tag_start()?
            .get(..tag_type.size())
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the value length field
    /// of the first TLV in the sequence.
    ///
    /// The value length field is the field that designates the length of the value of the TLV element.
    /// If the TLV element control byte designates an element with a fixed size or a container element,
    /// the returned sub-slice will designate the start of the value field.
    #[inline(always)]
    fn value_len_start(&self, tag_type: TLVTagType) -> Result<&'a [u8], Error> {
        self.tag_start()?
            .get(tag_type.size()..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return a sub-slice of the wrapped byte slice that designates the START of the value field of
    /// the first TLV in the sequence.
    ///
    /// The value field is the field that designates the actual value of the TLV element.
    #[inline(always)]
    fn value_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        self.value_len_start(control.tag_type)?
            .get(control.value_type.variable_size_len()..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the value payload
    /// of the first TLV element in the sequence.
    ///
    /// For container elements, this method will return the empty slice. Use `container_value` (a more computationally expensive method)
    /// to get the exact taw slice of the first TLV element value that also works for containers.
    #[inline(always)]
    fn value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        self.value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return a sub-slice of the wrapped byte slice that designates the exact raw slice representing the value payload
    /// of the first TLV element in the sequence.
    #[inline(always)]
    fn container_value(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.container_value_len(control)?;

        self.value_start(control)?
            .get(..value_len)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    /// Return the length of the value field of the first TLV element in the sequence.
    ///
    /// - For elements that do have a fixed size, the fixed size will be returned.
    /// - For UTF-8 and octet strings, the actual string length will be returned.
    /// - For containers, a length of 0 will be returned. Use `container_value_len`
    ///   (much more computationally expensive method) to get the exact length of the container.
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

    /// Return the length of the value field of the first TLV element in the sequence, regardless of the
    /// element type (fixed size, variable size, or container).
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

    /// Return the length of the first TLV element in the sequence.
    ///
    /// For containers, the return length will NOT include the elements contained inside
    /// the container, nor the one-byte `EndCnt` marker.
    #[inline(always)]
    fn len(&self) -> Result<usize, Error> {
        let control = self.control()?;

        self.value_len(control).map(|value_len| {
            1 + control.tag_type.size() + control.value_type.variable_size_len() + value_len
        })
    }

    /// Returns a sub-slice representing the start of the next TLV element in the sequence.
    /// If the sequence contains just one element, the method will return an empty slice.
    /// If the sequence contains no elements, the method will return an error with code `ErrorCode::TLVTypeMismatch`.
    ///
    /// Just like `next_enter` (wich is based on `next_start`) this method does "enter" container elements,
    /// and might return a sub-slice where the first element is the special `EndCnt` marker.
    #[inline(always)]
    fn next_start(&self, control: TLVControl) -> Result<&'a [u8], Error> {
        let value_len = self.value_len(control)?;

        self.value_start(control)?
            .get(value_len..)
            .ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    pub(crate) fn fmt(&self, indent: usize, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for elem in self.iter() {
            if first {
                first = false;
            } else {
                writeln!(f, ",")?;
            }

            let elem = elem.map_err(|_| fmt::Error)?;

            elem.fmt(indent, f)?;
        }

        Ok(())
    }
}

impl<'a> fmt::Display for TLVSequence<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt(0, f)
    }
}

/// A type representing an iterator over the elements of a `TLVSequence`.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct TLVContainerIter<'a>(TLVSequence<'a>);

impl<'a> TLVContainerIter<'a> {
    /// Create a new `TLVContainerIter` instance.
    const fn new(seq: TLVSequence<'a>) -> Self {
        Self(seq)
    }
}

impl<'a> Iterator for TLVContainerIter<'a> {
    type Item = Result<TLVElement<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .container_next()
            .map(|next_seq| (!next_seq.0.is_empty()).then(|| TLVElement(next_seq)))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use log::info;

    use super::TLVElement;
    use crate::error::ErrorCode;

    // #[test]
    // fn test_short_length_tag() {
    //     // The 0x36 is an array with a tag, but we leave out the tag field
    //     let b = [0x15, 0x36];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(tlv_iter.next(), None);
    // }

    // #[test]
    // fn test_invalid_value_type() {
    //     // The 0x24 is a a tagged integer, here we leave out the integer value
    //     let b = [0x15, 0x1f, 0x0];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(tlv_iter.next(), None);
    // }

    #[test]
    fn test_short_length_value_immediate() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [0x15, 0x24, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    // #[test]
    // fn test_short_length_value_string() {
    //     // This is a tagged string, with tag 0 and length 0xb, but we only have 4 bytes in the string
    //     let b = [0x15, 0x30, 0x00, 0x0b, 0x73, 0x6d, 0x61, 0x72];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(tlv_iter.next(), None);
    // }

    // #[test]
    // fn test_valid_tag() {
    //     // The 0x36 is an array with a tag, here tag is 0
    //     let b = [0x15, 0x36, 0x0];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(
    //         tlv_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(0),
    //             element_type: ElementType::Array(&[]),
    //         })
    //     );
    // }

    // #[test]
    // fn test_valid_value_immediate() {
    //     // The 0x24 is a a tagged integer, here the integer is 2
    //     let b = [0x15, 0x24, 0x1, 0x2];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(
    //         tlv_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(1),
    //             element_type: ElementType::U8(2),
    //         })
    //     );
    // }

    // #[test]
    // fn test_valid_value_string() {
    //     // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
    //     let b = [0x15, 0x30, 0x5, 0x04, 0x73, 0x6d, 0x61, 0x72];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(
    //         tlv_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(5),
    //             element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
    //         })
    //     );
    // }

    // #[test]
    // fn test_valid_value_string16() {
    //     // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
    //     let b = [
    //         0x15, 0x31, 0x1, 0xd8, 0x1, 0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3,
    //         0x2, 0x1, 0x2, 0x2, 0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa,
    //         0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30,
    //         0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20,
    //         0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b,
    //         0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x30,
    //         0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32, 0x33, 0x34,
    //         0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
    //         0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31, 0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4,
    //         0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
    //         0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82,
    //         0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6,
    //         0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30,
    //         0x30, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
    //         0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80, 0xdd,
    //         0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda, 0x14, 0x62,
    //         0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1, 0x8f, 0xe1, 0xab,
    //         0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc, 0xc6, 0xd9, 0xb5, 0xfa, 0xb6,
    //         0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17, 0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70,
    //         0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13,
    //         0x1, 0x1, 0xff, 0x4, 0x8, 0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6,
    //         0x3, 0x55, 0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6,
    //         0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5,
    //         0x15, 0xec, 0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30,
    //         0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd, 0x22,
    //         0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc, 0xdc, 0x31,
    //         0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2,
    //         0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9, 0xc8, 0xcf, 0x2e, 0x1, 0x88,
    //         0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b, 0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a,
    //         0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea, 0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54,
    //         0x94, 0x3b, 0xe5, 0x7d, 0x53, 0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2,
    //         0x3, 0x6c, 0xd2, 0x9b, 0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71,
    //         0x82, 0x19, 0x26, 0x2, 0x3e, 0x0, 0x0, 0x0,
    //     ];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(
    //         tlv_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(1),
    //             element_type: ElementType::Str16l(&[
    //                 0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2,
    //                 0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa, 0x6, 0x8, 0x2a,
    //                 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30, 0x16, 0x6,
    //                 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54,
    //                 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa,
    //                 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46,
    //                 0x46, 0x31, 0x30, 0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31,
    //                 0x34, 0x32, 0x33, 0x34, 0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31,
    //                 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31,
    //                 0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74,
    //                 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x49, 0x31, 0x14,
    //                 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1,
    //                 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6,
    //                 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30, 0x30,
    //                 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
    //                 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80,
    //                 0xdd, 0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda,
    //                 0x14, 0x62, 0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1,
    //                 0x8f, 0xe1, 0xab, 0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc,
    //                 0xc6, 0xd9, 0xb5, 0xfa, 0xb6, 0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17,
    //                 0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70, 0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66,
    //                 0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x8,
    //                 0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55, 0x1d, 0xf,
    //                 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d,
    //                 0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5, 0x15, 0xec,
    //                 0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30, 0x1f,
    //                 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd,
    //                 0x22, 0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc,
    //                 0xdc, 0x31, 0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce,
    //                 0x3d, 0x4, 0x3, 0x2, 0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9,
    //                 0xc8, 0xcf, 0x2e, 0x1, 0x88, 0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b,
    //                 0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a, 0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea,
    //                 0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54, 0x94, 0x3b, 0xe5, 0x7d, 0x53,
    //                 0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2, 0x3, 0x6c, 0xd2, 0x9b,
    //                 0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71, 0x82, 0x19
    //             ]),
    //         })
    //     );
    //     assert_eq!(
    //         tlv_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(2),
    //             element_type: ElementType::U32(62),
    //         })
    //     );
    // }

    // #[test]
    // fn test_no_iterator_for_int() {
    //     // The 0x24 is a a tagged integer, here the integer is 2
    //     let b = [0x15, 0x24, 0x1, 0x2];
    //     let tlvlist = TLVList::new(&b);
    //     let mut tlv_iter = tlvlist.iter();
    //     // Skip the 0x15
    //     tlv_iter.next();
    //     assert_eq!(tlv_iter.next().unwrap().enter(), None);
    // }

    // #[test]
    // fn test_struct_iteration_with_mix_values() {
    //     // This is a struct with 3 valid values
    //     let b = [
    //         0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
    //         0x61, 0x72,
    //     ];
    //     let mut root_iter = get_root_node_struct(&b).unwrap().enter().unwrap();
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(0),
    //             element_type: ElementType::U8(2),
    //         })
    //     );
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(2),
    //             element_type: ElementType::U32(135246),
    //         })
    //     );
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(3),
    //             element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
    //         })
    //     );
    // }

    // #[test]
    // fn test_struct_find_element_mix_values() {
    //     // This is a struct with 3 valid values
    //     let b = [
    //         0x15, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10,
    //         0x02, 0x00,
    //     ];
    //     let root = get_root_node_struct(&b).unwrap();

    //     assert_eq!(
    //         root.find_tag(0).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(0),
    //             element_type: ElementType::U8(2),
    //         }
    //     );
    //     assert_eq!(
    //         root.find_tag(2).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(2),
    //             element_type: ElementType::U32(135246),
    //         }
    //     );
    //     assert_eq!(
    //         root.find_tag(3).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(3),
    //             element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
    //         }
    //     );
    // }

    // #[test]
    // fn test_list_iteration_with_mix_values() {
    //     // This is a list with 3 valid values
    //     let b = [
    //         0x17, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
    //         0x61, 0x72,
    //     ];
    //     let mut root_iter = get_root_node_list(&b).unwrap().enter().unwrap();
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(0),
    //             element_type: ElementType::U8(2),
    //         })
    //     );
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(2),
    //             element_type: ElementType::U32(135246),
    //         })
    //     );
    //     assert_eq!(
    //         root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(3),
    //             element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
    //         })
    //     );
    // }

    // #[test]
    // fn test_complex_structure_invoke_cmd() {
    //     // This is what we typically get in an invoke command
    //     let b = [
    //         0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x25, 0x0, 0x2, 0x0, 0x26, 0x1, 0x6, 0x0, 0x0, 0x0,
    //         0x26, 0x2, 0x1, 0x0, 0x0, 0x0, 0x18, 0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
    //     ];

    //     let root = get_root_node_struct(&b).unwrap();

    //     let mut cmd_list_iter = root
    //         .find_tag(0)
    //         .unwrap()
    //         .confirm_array()
    //         .unwrap()
    //         .enter()
    //         .unwrap();
    //     info!("Command list iterator: {:?}", cmd_list_iter);

    //     // This is an array of CommandDataIB, but we'll only use the first element
    //     let cmd_data_ib = cmd_list_iter.next().unwrap();

    //     let cmd_path = cmd_data_ib.find_tag(0).unwrap();
    //     let cmd_path = cmd_path.confirm_list().unwrap();
    //     assert_eq!(
    //         cmd_path.find_tag(0).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(0),
    //             element_type: ElementType::U16(2),
    //         }
    //     );
    //     assert_eq!(
    //         cmd_path.find_tag(1).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(1),
    //             element_type: ElementType::U32(6),
    //         }
    //     );
    //     assert_eq!(
    //         cmd_path.find_tag(2).unwrap(),
    //         TLVElement {
    //             tag_type: TagType::Context(2),
    //             element_type: ElementType::U32(1),
    //         }
    //     );
    //     assert_eq!(
    //         cmd_path.find_tag(3).map_err(|e| e.code()),
    //         Err(ErrorCode::NoTagFound)
    //     );

    //     // This is the variable of the invoke command
    //     assert_eq!(
    //         cmd_data_ib.find_tag(1).unwrap().enter().unwrap().next(),
    //         None
    //     );
    // }

    // #[test]
    // fn test_read_past_end_of_container() {
    //     let b = [0x15, 0x35, 0x0, 0x24, 0x1, 0x2, 0x18, 0x24, 0x0, 0x2, 0x18];

    //     let mut sub_root_iter = get_root_node_struct(&b)
    //         .unwrap()
    //         .find_tag(0)
    //         .unwrap()
    //         .enter()
    //         .unwrap();
    //     assert_eq!(
    //         sub_root_iter.next(),
    //         Some(TLVElement {
    //             tag_type: TagType::Context(1),
    //             element_type: ElementType::U8(2),
    //         })
    //     );
    //     assert_eq!(sub_root_iter.next(), None);
    //     // Call next, even after the first next returns None
    //     assert_eq!(sub_root_iter.next(), None);
    //     assert_eq!(sub_root_iter.next(), None);
    // }

    // #[test]
    // fn test_basic_list_iterator() {
    //     // This is the input we have
    //     let b = [
    //         0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x24, 0x0, 0x2, 0x24, 0x2, 0x6, 0x24, 0x3, 0x1, 0x18,
    //         0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
    //     ];

    //     let dummy_pointer = &b[1..];
    //     // These are the decoded elements that we expect from this input
    //     let verify_matrix: [(TagType, ElementType); 13] = [
    //         (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
    //         (TagType::Context(0), ElementType::Array(dummy_pointer)),
    //         (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
    //         (TagType::Context(0), ElementType::List(dummy_pointer)),
    //         (TagType::Context(0), ElementType::U8(2)),
    //         (TagType::Context(2), ElementType::U8(6)),
    //         (TagType::Context(3), ElementType::U8(1)),
    //         (TagType::Anonymous, ElementType::EndCnt),
    //         (TagType::Context(1), ElementType::Struct(dummy_pointer)),
    //         (TagType::Anonymous, ElementType::EndCnt),
    //         (TagType::Anonymous, ElementType::EndCnt),
    //         (TagType::Anonymous, ElementType::EndCnt),
    //         (TagType::Anonymous, ElementType::EndCnt),
    //     ];

    //     let mut list_iter = TLVList::new(&b).iter();
    //     let mut index = 0;
    //     loop {
    //         let element = list_iter.next();
    //         match element {
    //             None => break,
    //             Some(a) => {
    //                 assert_eq!(a.tag_type, verify_matrix[index].0);
    //                 assert_eq!(
    //                     core::mem::discriminant(&a.element_type),
    //                     core::mem::discriminant(&verify_matrix[index].1)
    //                 );
    //             }
    //         }
    //         index += 1;
    //     }
    //     // After the end, purposefully try a few more next
    //     assert_eq!(list_iter.next(), None);
    //     assert_eq!(list_iter.next(), None);
    // }
}
