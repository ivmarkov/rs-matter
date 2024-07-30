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

use num::FromPrimitive;

use crate::error::{Error, ErrorCode};

pub use rs_matter_macros::{FromTLV, ToTLV};

pub use read::*;
pub use toiter::*;
pub use traits::*;
pub use write::*;

mod read;
mod toiter;
mod traits;
mod write;

/// Represents the TLV tag type encoded in the control byte of each TLV element.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVTagType {
    Anonymous = 0,
    Context = 1,
    CommonPrf16 = 2,
    CommonPrf32 = 3,
    ImplPrf16 = 4,
    ImplPrf32 = 5,
    FullQual48 = 6,
    FullQual64 = 7,
}

impl TLVTagType {
    /// Return the size of the tag data following the control byte
    /// in the TLV element representation.
    pub const fn size(&self) -> usize {
        match self {
            Self::Anonymous => 0,
            Self::Context => 1,
            Self::CommonPrf16 => 2,
            Self::CommonPrf32 => 4,
            Self::ImplPrf16 => 2,
            Self::ImplPrf32 => 4,
            Self::FullQual48 => 6,
            Self::FullQual64 => 8,
        }
    }
}

impl fmt::Display for TLVTagType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => write!(f, "Anonymous"),
            Self::Context => write!(f, "Context"),
            Self::CommonPrf16 => write!(f, "CommonPrf16"),
            Self::CommonPrf32 => write!(f, "CommonPrf32"),
            Self::ImplPrf16 => write!(f, "ImplPrf16"),
            Self::ImplPrf32 => write!(f, "ImplPrf32"),
            Self::FullQual48 => write!(f, "FullQual48"),
            Self::FullQual64 => write!(f, "FullQual64"),
        }
    }
}

/// Represents the TLV value type encoded in the control byte of each TLV element.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, num_derive::FromPrimitive)]
#[repr(u8)]
pub enum TLVValueType {
    S8 = 0,
    S16 = 1,
    S32 = 2,
    S64 = 3,
    U8 = 4,
    U16 = 5,
    U32 = 6,
    U64 = 7,
    False = 8,
    True = 9,
    F32 = 10,
    F64 = 11,
    Utf8l = 12,
    Utf16l = 13,
    Utf32l = 14,
    Utf64l = 15,
    Str8l = 16,
    Str16l = 17,
    Str32l = 18,
    Str64l = 19,
    Null = 20,
    Struct = 21,
    Array = 22,
    List = 23,
    EndCnt = 24,
}

impl TLVValueType {
    /// Return the size of the value corresponding to this value type.
    ///
    /// If the value type has a variable size (i.e. octet and Utf8 strings), this function returns `None`.
    pub const fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::S8 => Some(1),
            Self::S16 => Some(2),
            Self::S32 => Some(4),
            Self::S64 => Some(8),
            Self::U8 => Some(1),
            Self::U16 => Some(2),
            Self::U32 => Some(4),
            Self::U64 => Some(8),
            Self::F32 => Some(4),
            Self::F64 => Some(8),
            Self::Utf8l
            | Self::Utf16l
            | Self::Utf32l
            | Self::Utf64l
            | Self::Str8l
            | Self::Str16l
            | Self::Str32l
            | Self::Str64l => None,
            _ => Some(0),
        }
    }

    /// Return the size of the length field for variable size value types.
    ///
    /// if the value type has a fixed size, this function returns 0.
    /// Variable size types are only octet strings and utf8 strings.
    pub const fn variable_size_len(&self) -> usize {
        match self {
            Self::Utf8l | Self::Str8l => 1,
            Self::Utf16l | Self::Str16l => 2,
            Self::Utf32l | Self::Str32l => 4,
            Self::Utf64l | Self::Str64l => 8,
            _ => 0,
        }
    }

    /// Convenience method to check if the value type is a container type
    /// (container start or end).
    pub const fn is_container(&self) -> bool {
        self.is_container_start() || self.is_container_end()
    }

    /// Convenience method to check if the value type is a container start type.
    pub const fn is_container_start(&self) -> bool {
        matches!(self, Self::Struct | Self::Array | Self::List)
    }

    /// Convenience method to check if the value type is a container end type.
    pub const fn is_container_end(&self) -> bool {
        matches!(self, Self::EndCnt)
    }

    /// Convenience method to check if the value type is an Octet String type.
    pub const fn is_str(&self) -> bool {
        matches!(
            self,
            Self::Str8l | Self::Str16l | Self::Str32l | Self::Str64l
        )
    }

    /// Convenience method to check if the value type is a UTF-8 String type.
    pub const fn is_utf8(&self) -> bool {
        matches!(
            self,
            Self::Utf8l | Self::Utf16l | Self::Utf32l | Self::Utf64l
        )
    }
}

impl fmt::Display for TLVValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S8 => write!(f, "S8"),
            Self::S16 => write!(f, "S16"),
            Self::S32 => write!(f, "S32"),
            Self::S64 => write!(f, "S64"),
            Self::U8 => write!(f, "U8"),
            Self::U16 => write!(f, "U16"),
            Self::U32 => write!(f, "U32"),
            Self::U64 => write!(f, "U64"),
            Self::False => write!(f, "False"),
            Self::True => write!(f, "True"),
            Self::F32 => write!(f, "F32"),
            Self::F64 => write!(f, "F64"),
            Self::Utf8l => write!(f, "Utf8l"),
            Self::Utf16l => write!(f, "Utf16l"),
            Self::Utf32l => write!(f, "Utf32l"),
            Self::Utf64l => write!(f, "Utf64l"),
            Self::Str8l => write!(f, "Str8l"),
            Self::Str16l => write!(f, "Str16l"),
            Self::Str32l => write!(f, "Str32l"),
            Self::Str64l => write!(f, "Str64l"),
            Self::Null => write!(f, "Null"),
            Self::Struct => write!(f, "Struct"),
            Self::Array => write!(f, "Array"),
            Self::List => write!(f, "List"),
            Self::EndCnt => write!(f, "EndCnt"),
        }
    }
}

/// Represents the control byte of a TLV element (i.e. the tag type and the value type).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TLVControl {
    pub tag_type: TLVTagType,
    pub value_type: TLVValueType,
}

impl TLVControl {
    const TAG_SHIFT_BITS: u8 = 5;
    const TAG_MASK: u8 = 0xe0;
    const TYPE_MASK: u8 = 0x1f;

    /// Create a new TLV control byte by parsing the provided tag type and value type.
    #[inline(always)]
    pub const fn new(tag_type: TLVTagType, value_type: TLVValueType) -> Self {
        Self {
            tag_type,
            value_type,
        }
    }

    /// Create a new TLV control byte by parsing the provided control byte
    /// into a tag type and a value type.
    ///
    /// The function will return an error if the provided control byte is invalid.
    #[inline(always)]
    pub fn parse(control: u8) -> Result<Self, Error> {
        let tag_type = FromPrimitive::from_u8((control & Self::TAG_MASK) >> Self::TAG_SHIFT_BITS)
            .ok_or(ErrorCode::TLVTypeMismatch)?;
        let value_type =
            FromPrimitive::from_u8(control & Self::TYPE_MASK).ok_or(ErrorCode::TLVTypeMismatch)?;

        Ok(Self::new(tag_type, value_type))
    }

    /// Return the raw control byte.
    #[inline(always)]
    pub const fn as_raw(&self) -> u8 {
        ((self.tag_type as u8) << Self::TAG_SHIFT_BITS) | (self.value_type as u8)
    }

    #[inline(always)]
    pub fn is_container_end(&self) -> bool {
        matches!(self.tag_type, TLVTagType::Anonymous) && self.value_type.is_container_end()
    }

    #[inline(always)]
    pub fn confirm_container_end(&self) -> Result<(), Error> {
        if !self.is_container_end() {
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(())
    }
}

/// For backwards compatibility
pub type TagType = TLVTag;

/// A high-level representation of a TLV tag (tag type and tag value).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TLVTag {
    Anonymous,
    Context(u8),
    CommonPrf16(u16),
    CommonPrf32(u32),
    ImplPrf16(u16),
    ImplPrf32(u32),
    FullQual48(u64),
    FullQual64(u64),
}

impl TLVTag {
    /// Return the tag type of the TLV tag.
    pub const fn tag_type(&self) -> TLVTagType {
        match self {
            Self::Anonymous => TLVTagType::Anonymous,
            Self::Context(_) => TLVTagType::Context,
            Self::CommonPrf16(_) => TLVTagType::CommonPrf16,
            Self::CommonPrf32(_) => TLVTagType::CommonPrf32,
            Self::ImplPrf16(_) => TLVTagType::ImplPrf16,
            Self::ImplPrf32(_) => TLVTagType::ImplPrf32,
            Self::FullQual48(_) => TLVTagType::FullQual48,
            Self::FullQual64(_) => TLVTagType::FullQual64,
        }
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLVTag::Anonymous => Ok(()),
            TLVTag::Context(tag) => write!(f, "{}", tag),
            TLVTag::CommonPrf16(tag) => write!(f, "CommonPrf16({})", tag),
            TLVTag::CommonPrf32(tag) => write!(f, "CommonPrf32({})", tag),
            TLVTag::ImplPrf16(tag) => write!(f, "ImplPrf16({})", tag),
            TLVTag::ImplPrf32(tag) => write!(f, "ImplPrf32({})", tag),
            TLVTag::FullQual48(tag) => write!(f, "FullQual48({})", tag),
            TLVTag::FullQual64(tag) => write!(f, "FullQual64({})", tag),
        }
    }
}

impl fmt::Display for TLVTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLVTag::Anonymous => write!(f, "Anonymous"),
            TLVTag::Context(tag) => write!(f, "Context({})", tag),
            _ => self.fmt(f),
        }
    }
}

/// For backwards compatibility
pub type ElementType<'a> = TLVValue<'a>;

/// A high-level representation of a TLV value.
#[derive(Debug, Clone, PartialEq)]
pub enum TLVValue<'a> {
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    False,
    True,
    F32(f32),
    F64(f64),
    Utf8l(&'a str),
    Utf16l(&'a str),
    Utf32l(&'a str),
    Utf64l(&'a str),
    Str8l(&'a [u8]),
    Str16l(&'a [u8]),
    Str32l(&'a [u8]),
    Str64l(&'a [u8]),
    Null,
    Struct(TLVSequence<'a>),
    Array(TLVSequence<'a>),
    List(TLVSequence<'a>),
}

impl<'a> TLVValue<'a> {
    /// Return the value type of the TLV value.
    pub const fn value_type(&self) -> TLVValueType {
        match self {
            Self::S8(_) => TLVValueType::S8,
            Self::S16(_) => TLVValueType::S16,
            Self::S32(_) => TLVValueType::S32,
            Self::S64(_) => TLVValueType::S64,
            Self::U8(_) => TLVValueType::U8,
            Self::U16(_) => TLVValueType::U16,
            Self::U32(_) => TLVValueType::U32,
            Self::U64(_) => TLVValueType::U64,
            Self::False => TLVValueType::False,
            Self::True => TLVValueType::True,
            Self::F32(_) => TLVValueType::F32,
            Self::F64(_) => TLVValueType::F64,
            Self::Utf8l(_) => TLVValueType::Utf8l,
            Self::Utf16l(_) => TLVValueType::Utf16l,
            Self::Utf32l(_) => TLVValueType::Utf32l,
            Self::Utf64l(_) => TLVValueType::Utf64l,
            Self::Str8l(_) => TLVValueType::Str8l,
            Self::Str16l(_) => TLVValueType::Str16l,
            Self::Str32l(_) => TLVValueType::Str32l,
            Self::Str64l(_) => TLVValueType::Str64l,
            Self::Null => TLVValueType::Null,
            Self::Struct(_) => TLVValueType::Struct,
            Self::Array(_) => TLVValueType::Array,
            Self::List(_) => TLVValueType::List,
        }
    }

    fn fmt(&self, indent: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::S8(a) => write!(f, "S8({})", a),
            Self::S16(a) => write!(f, "S16({})", a),
            Self::S32(a) => write!(f, "S32({})", a),
            Self::S64(a) => write!(f, "S64({})", a),
            Self::U8(a) => write!(f, "U8({})", a),
            Self::U16(a) => write!(f, "U16({})", a),
            Self::U32(a) => write!(f, "U32({})", a),
            Self::U64(a) => write!(f, "U64({})", a),
            Self::F32(a) => write!(f, "F32({})", a),
            Self::F64(a) => write!(f, "F64({})", a),
            Self::Null => write!(f, "Null"),
            Self::Struct(elements) => {
                write!(f, "{{\n")?;
                elements.fmt(indent + 1, f)?;
                pad(indent, f)?;
                write!(f, "}}")
            }
            Self::Array(elements) => {
                write!(f, "[\n")?;
                elements.fmt(indent + 1, f)?;
                pad(indent, f)?;
                write!(f, "]")
            }
            Self::List(elements) => {
                write!(f, "(\n")?;
                elements.fmt(indent + 1, f)?;
                pad(indent, f)?;
                write!(f, ")")
            }
            Self::True => write!(f, "True"),
            Self::False => write!(f, "False"),
            Self::Utf8l(a) | Self::Utf16l(a) | Self::Utf32l(a) | Self::Utf64l(a) => {
                write!(f, "\"{}\"", a)
            }
            Self::Str8l(a) | Self::Str16l(a) | Self::Str32l(a) | Self::Str64l(a) => {
                write!(f, "({}){:02X?}", a.len(), a)
            }
        }
    }
}

/// For backwards compatibility
pub fn get_root_node(data: &[u8]) -> Result<TLVElement<'_>, Error> {
    // TODO: Check for trailing data
    TLVList::new(TLVElement::new(data))?.single_child()
}

/// For backwards compatibility
pub fn get_root_node_struct(data: &[u8]) -> Result<TLVElement<'_>, Error> {
    let element = get_root_node(data)?;

    element.structure()?;

    Ok(element)
}

/// Retrive the single TLV element from the provided TLV data slice.
/// The slice is interpreted as a TLV list of TLV elements and is expected to have exactly one element.
///
/// Returns an error if the TLV data is malformed, if the data does not represent a TLV list, or if the
/// list does not contain exactly one element.
pub fn list_single_elem(data: &[u8]) -> Result<TLVElement<'_>, Error> {
    // TODO: Check for trailing data

    let mut iter = TLVList::new(TLVElement::new(data))?.into_iter();

    let list_element = iter.next().ok_or(ErrorCode::TLVNotFound)??;

    if iter.next().is_some() {
        return Err(ErrorCode::InvalidData.into());
    }

    Ok(list_element)
}

impl<'a> fmt::Display for TLVValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt(0, f)
    }
}

pub(crate) fn pad(ident: usize, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for _ in 0..ident {
        write!(f, "  ")?;
    }

    Ok(())
}
