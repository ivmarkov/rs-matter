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

//! TLV support for Rust slices `&[T]`.
//! Rust slices are serialized as TLV arrays.
//!
//! Note that only serialization `(trait `ToTLV`) is supported for Rust slices,
//! because deserialization (`FromTLV`) requires the deserialized Rust type
//! to be `Sized`, which slices aren't.
//!
//! (Deserializing strings as `&str` and octets as `Bytes<'a>` (which is really a newtype over
//! `&'a [u8]`) is supported, but that's because their deserialization works by borrowing their
//! content 1:1 from inside the buffer of the deserializer, which is not possible for a generic
//! `T` and only possible when `T` is a `u8`.)

use core::iter::empty;

use crate::error::Error;

use super::{TLVTag, TLVWrite, ToTLV};

impl<'a, T: ToTLV> ToTLV for &'a [T]
where
    T: ToTLV,
{
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: TLVWrite,
    {
        to_tlv_array(tag, self.iter(), &mut write)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        into_tlv_array_iter(tag, self.iter())
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        into_tlv_array_iter(tag, self.into_iter())
    }
}

pub(crate) fn to_tlv_array<I, O>(tag: &TLVTag, iter: I, mut write: O) -> Result<(), Error>
where
    I: Iterator,
    I::Item: ToTLV,
    O: TLVWrite,
{
    write.start_array(tag)?;

    for i in iter {
        i.to_tlv(&TLVTag::Anonymous, &mut write)?;
    }

    write.end_container()
}

pub(crate) fn into_tlv_array_iter<I>(tag: TLVTag, iter: I) -> impl Iterator<Item = u8>
where
    I: Iterator,
    I::Item: ToTLV,
{
    use crate::tlv2::toiter::ToTLVIter;

    empty()
        .start_array(tag)
        .chain(iter.flat_map(|t| t.into_tlv_iter(TLVTag::Anonymous)))
        .end_container()
}
