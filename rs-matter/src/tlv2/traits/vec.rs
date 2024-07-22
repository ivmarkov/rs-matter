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

//! TLV support for the `Vec<T, N>` type.
//! `Vec<T, N>` is serialized and deserialized as a TLV array.
//! 
//! Unlike Rust `[T;N]` arrays, the `Vec` type can be efficiently deserialized in-place, so use it
//! when the array holds large structures (like fabrics, certificates, sessions and so on).
//! 
//! Of course, the `Vec` type is always owned (even if the deserialized elements `T` do borrow from the 
//! deserializer), so it might consume more memory than necessary, as its memory is statically allocated
//! to be N * size_of(T) bytes.

use crate::error::{Error, ErrorCode};
use crate::utils::init::{self, AsFallibleInit};
use crate::utils::vec::Vec;

use super::{
    into_tlv_array_iter, BytesRead, BytesSlice, BytesWrite, FromTLV, FromTLVOwned, TLVIter,
    TLVRead, TLVTag, TLVValueType, ToTLV,
};

impl<T, const N: usize> FromTLVOwned for Vec<T, N>
where
    T: FromTLVOwned + 'static,
{
    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesRead,
    {
        let mut vec = Vec::<T, N>::new();

        read.array(value_type)?;

        vec_extend_owned(&mut vec, read)?;

        return Ok(vec);
    }

    fn init_from_tlv_owned<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        init::Init::chain(Vec::<T, N>::init().as_fallible(), move |vec| {
            read.array(value_type)?;

            vec_extend_init_owned(vec, read)?;

            Ok(())
        })
    }
}

impl<'a, T, const N: usize> FromTLV<'a> for Vec<T, N>
where
    T: FromTLV<'a> + 'a,
{
    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>,
    {
        let mut vec = Vec::<T, N>::new();

        read.array(value_type)?;

        vec_extend(&mut vec, read)?;

        return Ok(vec);
    }

    fn init_from_tlv<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        init::Init::chain(Vec::<T, N>::init().as_fallible(), move |vec| {
            read.array(value_type)?;

            // TODO vec_extend_init(vec, read)?;

            let mut iter = TLVIter::new(read);

            while let Some((tag, value_type)) = iter.try_next_tag()? {
                tag.confirm_anonymous()?;

                let value = T::init_from_tlv(value_type, iter.read().clone());

                vec.push_init(value, || ErrorCode::NoSpace.into())?;
            }

            Ok(())
        })
    }
}

impl<T, const N: usize> ToTLV for Vec<T, N>
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

pub(crate) fn vec_extend<'a, T, const N: usize, I>(
    vec: &mut Vec<T, N>,
    read: I,
) -> Result<(), Error>
where
    T: FromTLV<'a> + 'a,
    I: BytesRead + BytesSlice<'a>,
{
    let mut iter = TLVIter::new(read);

    while let Some((tag, value)) = iter.try_next()? {
        tag.confirm_anonymous()?;

        vec.push(value).map_err(|_| ErrorCode::NoSpace)?;
    }

    Ok(())
}

pub(crate) fn vec_extend_owned<T, const N: usize, I>(
    vec: &mut Vec<T, N>,
    read: I,
) -> Result<(), Error>
where
    T: FromTLVOwned + 'static,
    I: BytesRead,
{
    let mut iter = TLVIter::new(read);

    while let Some((tag, value)) = iter.try_next_owned()? {
        tag.confirm_anonymous()?;

        vec.push(value).map_err(|_| ErrorCode::NoSpace)?;
    }

    Ok(())
}

pub(crate) fn vec_extend_init<'a, T, const N: usize, I>(
    vec: &mut Vec<T, N>,
    read: I,
) -> Result<(), Error>
where
    T: FromTLV<'a>,
    I: BytesRead + BytesSlice<'a> + Clone + 'a,
{
    let mut iter = TLVIter::new(read);

    while let Some((tag, value)) = iter.try_next_init()? {
        tag.confirm_anonymous()?;

        vec.push_init(value, || ErrorCode::NoSpace.into())?;
    }

    Ok(())
}

pub(crate) fn vec_extend_init_owned<T, const N: usize, I>(
    vec: &mut Vec<T, N>,
    read: I,
) -> Result<(), Error>
where
    T: FromTLVOwned + 'static,
    I: BytesRead + Clone,
{
    let mut iter = TLVIter::new(read);

    while let Some((tag, value)) = iter.try_next_init_owned()? {
        tag.confirm_anonymous()?;

        vec.push_init(value, || ErrorCode::NoSpace.into())?;
    }

    Ok(())
}
