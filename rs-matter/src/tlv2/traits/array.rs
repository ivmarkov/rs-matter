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

//! TLV support for Rust built-in arrays.
//! Rust bilt-in arrays are serialized and deserialized as TLV arrays.
//! 
//! Note that the implementation below CANNOT efficiently in-place initialize the arrays,
//! as that would imply that the array elements should implement the unsafe `Zeroed` trait.
//! 
//! Since that would restruct the use-cases where built-in arrays can be utilized,
//! the implementation below requires `Default` instead for the array elements.

use crate::error::{Error, ErrorCode};
use crate::utils::vec::Vec;

use super::{
    into_tlv_array_iter, vec_extend, vec_extend_owned, BytesRead, BytesSlice, BytesWrite, FromTLV,
    FromTLVOwned, TLVRead, TLVTag, TLVValueType, ToTLV,
};

impl<T, const N: usize> FromTLVOwned for [T; N]
where
    T: FromTLVOwned + Default,
{
    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesRead,
    {
        let mut vec = Vec::<T, N>::new();

        read.array(value_type)?;

        vec_extend_owned(&mut vec, read)?;

        while !vec.is_full() {
            vec.push(Default::default())
                .map_err(|_| ErrorCode::NoSpace)?;
        }

        return Ok(vec.into_array().map_err(|_| ErrorCode::NoSpace).unwrap());
    }
}

impl<'a, T, const N: usize> FromTLV<'a> for [T; N]
where
    T: FromTLV<'a> + Default,
{
    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>,
    {
        let mut vec = Vec::<T, N>::new();

        read.array(value_type)?;

        vec_extend(&mut vec, read)?;

        while !vec.is_full() {
            vec.push(Default::default())
                .map_err(|_| ErrorCode::NoSpace)?;
        }

        return Ok(vec.into_array().map_err(|_| ErrorCode::NoSpace).unwrap());
    }
}

impl<T, const N: usize> ToTLV for [T; N]
where
    T: ToTLV,
{
    fn to_tlv<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        self.as_slice().to_tlv(tag, write)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.as_slice().into_tlv_iter(tag)
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        into_tlv_array_iter(tag, self.into_iter())
    }
}
