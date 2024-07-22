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

//! TLV support for octets representing valid utf8 sequences (i.e. utf8 strings).
//! 
//! - `&str` is used for serializing and deserializing borrowed utf8 strings
//! - `String<N>` (from `heapless`) is used for serializing and deserializing owned strings of fixed length N
//!
//! Note that (for now) `String<N>` has no efficient in-place initialization, so it should not be used for
//! holding large strings, or else a stack overflow might occur.

use core::iter::empty;

use heapless::String;

use crate::error::{Error, ErrorCode};

use super::{
    BytesRead, BytesSlice, BytesWrite, FromTLV, FromTLVOwned, TLVRead, TLVTag, TLVValueType,
    TLVWrite, ToTLV,
};

impl<'a> FromTLV<'a> for &'a str {
    fn from_tlv<I>(value_type: TLVValueType, mut read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>,
    {
        core::str::from_utf8(read.utf8(value_type)?).map_err(|_| ErrorCode::TLVTypeMismatch.into())
    }
}

impl ToTLV for &str {
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        write.utf8(tag, self.as_bytes())
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::toiter::ToTLVIter;

        empty().utf8(tag, self.as_bytes())
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::toiter::ToTLVIter;

        empty().utf8(tag, self.as_bytes())
    }
}

impl<const N: usize> FromTLVOwned for String<N> {
    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<String<N>, Error>
    where
        I: BytesRead,
    {
        todo!()
    }
}

impl<'a, const N: usize> FromTLV<'a> for String<N> {
    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<String<N>, Error>
    where
        I: BytesSlice<'a>,
    {
        Self::from_tlv_owned(value_type, read)
    }
}

impl<const N: usize> ToTLV for String<N> {
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        write.utf8(tag, self.as_bytes())
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::toiter::ToTLVIter;

        empty().utf8(tag, self.as_bytes())
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::toiter::ToTLVIter;

        empty().utf8i(tag, self.len(), self.into_bytes().into_iter())
    }
}
