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
use core::marker::PhantomData;

use num::FromPrimitive;

use crate::error::{Error, ErrorCode};
use crate::utils::init;

pub use rs_matter_macros::{FromTLV, ToTLV};

pub use io::*;
pub use read::*;
pub use toiter::*;
pub use traits::*;
pub use write::*;

mod io;
mod read;
mod tlv2;
mod toiter;
mod traits;
mod write;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, num_derive::FromPrimitive)]
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

    pub fn confirm_anonymous(&self) -> Result<(), Error> {
        if matches!(self, Self::Anonymous) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    pub fn confirm_context(&self) -> Result<(), Error> {
        if matches!(self, Self::Context) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
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
    pub fn present(value_type: Option<Self>) -> Result<Self, Error> {
        value_type.ok_or(ErrorCode::TLVTypeMismatch.into())
    }

    pub fn confirm(&self, is: Self) -> Result<(), Error> {
        if *self != is {
            Err(ErrorCode::InvalidData)?;
        }

        Ok(())
    }

    pub const fn is_container(&self) -> bool {
        self.is_container_start() || self.is_container_end()
    }

    pub const fn is_container_start(&self) -> bool {
        matches!(self, Self::Struct | Self::Array | Self::List)
    }

    pub const fn is_container_end(&self) -> bool {
        matches!(self, Self::EndCnt)
    }

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

    pub const fn variable_size_len(&self) -> usize {
        match self {
            Self::Utf8l | Self::Str8l => 1,
            Self::Utf16l | Self::Str16l => 2,
            Self::Utf32l | Self::Str32l => 4,
            Self::Utf64l | Self::Str64l => 8,
            _ => 0,
        }
    }

    pub const fn is_slice(&self) -> bool {
        self.variable_size_len() != 0
    }

    pub const fn is_str(&self) -> bool {
        matches!(
            self,
            Self::Str8l | Self::Str16l | Self::Str32l | Self::Str64l
        )
    }

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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TLVControl(u8);

impl TLVControl {
    const TAG_SHIFT_BITS: u8 = 5;
    const TAG_MASK: u8 = 0xe0;
    const TYPE_MASK: u8 = 0x1f;

    pub fn new(control: u8) -> Result<Self, Error> {
        let this = Self::new_unchecked(control);

        this.try_tag_type().ok_or(ErrorCode::InvalidData)?;
        this.try_value_type().ok_or(ErrorCode::InvalidData)?;

        Ok(this)
    }

    pub const fn from(tag_type: TLVTagType, value_type: TLVValueType) -> Self {
        Self::new_unchecked(((tag_type as u8) << Self::TAG_SHIFT_BITS) | (value_type as u8))
    }

    pub const fn new_unchecked(control: u8) -> Self {
        Self(control)
    }

    pub const fn into_raw(self) -> u8 {
        self.0
    }

    fn tag_type(&self) -> TLVTagType {
        self.try_tag_type().unwrap()
    }

    fn value_type(&self) -> TLVValueType {
        self.try_value_type().unwrap()
    }

    fn try_tag_type(&self) -> Option<TLVTagType> {
        let tag_type = (self.0 & Self::TAG_MASK) >> Self::TAG_SHIFT_BITS;

        FromPrimitive::from_u8(tag_type)
    }

    fn try_value_type(&self) -> Option<TLVValueType> {
        let element_type = self.0 & Self::TYPE_MASK;

        FromPrimitive::from_u8(element_type)
    }
}

pub type TagType = TLVTag;

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

    pub fn confirm_anonymous(&self) -> Result<(), Error> {
        if matches!(self, Self::Anonymous) {
            Ok(())
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }

    pub fn confirm_context(&self) -> Result<u8, Error> {
        if let Self::Context(n) = self {
            Ok(*n)
        } else {
            Err(ErrorCode::InvalidData.into())
        }
    }
}

impl fmt::Display for TLVTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TLVTag::Anonymous => write!(f, "Anonymous")?,
            TLVTag::Context(tag) => write!(f, "Context({})", tag)?,
            TLVTag::CommonPrf16(tag) => write!(f, "CommonPrf16({})", tag)?,
            TLVTag::CommonPrf32(tag) => write!(f, "CommonPrf32({})", tag)?,
            TLVTag::ImplPrf16(tag) => write!(f, "ImplPrf16({})", tag)?,
            TLVTag::ImplPrf32(tag) => write!(f, "ImplPrf32({})", tag)?,
            TLVTag::FullQual48(tag) => write!(f, "FullQual48({})", tag)?,
            TLVTag::FullQual64(tag) => write!(f, "FullQual64({})", tag)?,
        }

        Ok(())
    }
}

pub type ElementType<'a> = TLVValue<'a>;

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
    Utf8l(&'a [u8]),
    Utf16l(&'a [u8]),
    Utf32l(&'a [u8]),
    Utf64l(&'a [u8]),
    Str8l(&'a [u8]),
    Str16l(&'a [u8]),
    Str32l(&'a [u8]),
    Str64l(&'a [u8]),
    Null,
    Struct,
    Array,
    List,
    EndCnt,
}

impl<'a> TLVValue<'a> {
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
            Self::Struct => TLVValueType::Struct,
            Self::Array => TLVValueType::Array,
            Self::List => TLVValueType::List,
            Self::EndCnt => TLVValueType::EndCnt,
        }
    }
}

impl<'a> fmt::Display for TLVValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Struct => write!(f, "{{"),
            Self::Array => write!(f, "["),
            Self::List => write!(f, "["),
            Self::EndCnt => write!(f, ">"),
            Self::True => write!(f, "True"),
            Self::False => write!(f, "False"),
            Self::Str8l(a)
            | Self::Utf8l(a)
            | Self::Str16l(a)
            | Self::Utf16l(a)
            | Self::Str32l(a)
            | Self::Utf32l(a)
            | Self::Str64l(a)
            | Self::Utf64l(a) => {
                if let Ok(s) = core::str::from_utf8(a) {
                    write!(f, "len[{}]\"{}\"", s.len(), s)
                } else {
                    write!(f, "len[{}]{:x?}", a.len(), a)
                }
            }
            other => write!(f, "{:?}", other),
        }
    }
}

pub type TLVElement<'a> = TLV<'a>;

pub struct TLV<'a> {
    pub tag: TLVTag,
    pub value: TLVValue<'a>,
}

impl<'a> TLV<'a> {
    pub const fn new(tag: TLVTag, value: TLVValue<'a>) -> Self {
        Self { tag, value }
    }
}
