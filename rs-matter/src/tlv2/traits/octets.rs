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

//! TLV support for octet strings (i.e. byte arrays).
//!
//! Support is provided via two dedicated newtypes:
//! - `Octets<'a>` newtype which wraps an ordinary `&[u8]` - for borrowed byte arrays
//! - `OctetsOwned<const N>` newtype which wraps a `Vec<u8, N>` for owned byte arrays of fixed length N
//!
//! Newtype wrapping is necessary because naked Rust slices, arrays and the naked `Vec` type
//! serialize and deserialize as TLV arrays, rather than as octet strings.
//!
//! I.e. serializing `[0; 3]` will result in a TLV array with 3 elements of type u8 and value 0, rather than a TLV
//! octet string containing 3 zero bytes.

use core::fmt::Debug;
use core::hash::Hash;

use crate::error::{Error, ErrorCode};
use crate::utils::init::{self, init, AsFallibleInit};
use crate::utils::vec::Vec;

use super::{FromTLV, TLVElement, TLVTag, TLVWrite, TLVWriteStorage, ToTLV2};

/// For backwards compatibility
pub type OctetStr<'a> = Octets<'a>;

/// For backwards compatibility
pub type OctetStrOwned<const N: usize> = OctetsOwned<N>;

/// Newtype for borrowed byte arrays
///
/// When deserializing, this type grabs the octet slice directly from the byte reader and therefore requires
/// the reader to have in-memory representation of its data (i.e. a `ByteSlice` reader)
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Octets<'a>(pub &'a [u8]);

impl<'a> Octets<'a> {
    pub const fn new(slice: &'a [u8]) -> Self {
        Self(slice)
    }
}

impl<'a> FromTLV<'a> for Octets<'a> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Octets(tlv.str()?))
    }
}

impl<'a> ToTLV2 for Octets<'a> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        TLVWrite::new(write).str(tag, self.0)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        use crate::tlv2::toiter::ToTLVIter;

        core::iter::empty().str(tag, self.0)
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        use crate::tlv2::toiter::ToTLVIter;

        core::iter::empty().str(tag, self.0)
    }
}

/// Newtype for owned byte arrays with a fixed maximum length
/// (represented by a `Vec<u8, N>`)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct OctetsOwned<const N: usize> {
    pub vec: Vec<u8, N>,
}

impl<const N: usize> OctetsOwned<N> {
    /// Create a new empty `OctetsOwned` instance
    pub const fn new() -> Self {
        Self {
            vec: Vec::<u8, N>::new(),
        }
    }

    /// Create an in-place initializer for an empty `OctetsOwned` instance
    pub fn init() -> impl init::Init<Self> {
        init!(Self {
            vec <- Vec::<u8, N>::init(),
        })
    }
}

impl<'a, const N: usize> FromTLV<'a> for OctetsOwned<N> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self {
            vec: tlv.str()?.try_into().map_err(|_| ErrorCode::NoSpace)?,
        })
    }

    fn init_from_tlv(tlv: TLVElement<'a>) -> impl init::Init<Self, Error> {
        init::Init::chain(OctetsOwned::init().as_fallible(), move |bytes| {
            bytes
                .vec
                .extend_from_slice(tlv.str()?)
                .map_err(|_| ErrorCode::NoSpace)?;

            Ok(())
        })
    }
}

impl<const N: usize> ToTLV2 for OctetsOwned<N> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        TLVWrite::new(write).str(tag, &self.vec)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        use crate::tlv2::toiter::ToTLVIter;

        core::iter::empty().str(tag, &self.vec)
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        use crate::tlv2::toiter::ToTLVIter;

        core::iter::empty().stri(tag, self.vec.len(), self.vec.into_iter().map(Result::Ok))
    }
}
