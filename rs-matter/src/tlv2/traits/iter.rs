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

use core::marker::PhantomData;

use crate::error::{Error, ErrorCode};
use crate::tlv2::{TLVControl, TLVTagType};
use crate::utils::init;

use super::{BytesRead, BytesSlice, FromTLV, FromTLVOwned, TLVRead, TLVTag, TLVValueType};

/// An iterator over a TLV-encoded data.
/// 
/// `TLVIter` can be used to iterate any TLV container type - struct, list or array. 
/// Either a complete one, or the remainder of a container.
/// 
/// It can also be used to iterate a complete TLV stream or even a single TLV element which does not live inside a container
/// (with constructor `TLVIter::new_eof`).
/// 
/// This iterator reads TLV-encoded data from a `BytesRead` source and can materialize thew data in various ways:
/// - As a borrowed reference to the source data (if `T` is `FromTLV` and if the source is `BytesSlice`)
/// - As an owned value (if `T` is `FromTLVOwned`)
/// - As an initializer for either borrowed, or owned `T`
/// 
/// The `Iterator` trait is implemented on this type with the variant wheret the data is deserialized as a borrowed reference (`FromTLV`).
/// Use the methods implemented directly on `TLVIter` if you would like to deserialize the data in a different way.
pub struct TLVIter<I> {
    read: I,
    endct: bool,
    finished: bool,
}

impl<I> TLVIter<I>
where
    I: BytesRead,
{
    /// Create a new `TLVIter` from a `BytesRead` source.
    /// 
    /// The instance will iterate until a TLV container end element is reached.
    pub const fn new(read: I) -> Self {
        Self {
            read,
            endct: true,
            finished: false,
        }
    }

    /// Create a new `TLVIter` from a `BytesRead` source.
    /// 
    /// The instance will iterate until the end of the TLV stream.
    pub const fn new_eof(read: I) -> Self {
        Self {
            read,
            endct: false,
            finished: false,
        }
    }

    /// Get a reference to the underlying `BytesRead` source.
    pub fn read(&self) -> &I {
        &self.read
    }

    /// Get a mutable reference to the underlying `BytesRead` source.
    pub fn read_mut(&mut self) -> &mut I {
        &mut self.read
    }

    // pub fn enter<X>(&mut self) -> Result<TLVIter<&mut I, X>, Error> {
    //     let control = self.read.next()?;

    //     let control = TLVControl::new(control)?;

    //     if !control.value_type().is_container_start() {
    //         return Err(ErrorCode::InvalidData.into());
    //     }

    //     Ok(TLVIter::new(self.read.clone()))
    // }

    /// Try to read the next TLV tag and value type.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// 
    /// Returns the tag and value type of the next TLV element.
    /// 
    /// NOTE: Use this method with care, as the value right after the tag needs to be "manually" read by the user,
    /// possibly by using `TLVRead` methods.
    pub fn try_next(&mut self) -> Result<Option<TLVControl>, Error> {
        if self.finished {
            return Ok(None);
        }

        let Some(control) = self.read.try_control()? else {
            if self.endct {
                return Err(ErrorCode::InvalidData.into());
            } else {
                return Ok(None);
            }
        };

        if self.endct && control.value_type().is_container_end() {
            self.finished = true;

            return Ok(None);
        }

        Ok(Some(control))
    }

    pub fn try_next_anon(&mut self) -> Result<Option<TLVValueType>, Error> {
        let Some(control) = self.try_next()? else {
            return Ok(None);
        };

        control.tag_type().confirm_anonymous()?;

        Ok(Some(control.value_type()))
    }

    pub fn try_next_context(&mut self) -> Result<Option<(u8, TLVValueType)>, Error> {
        let Some(control) = self.try_next()? else {
            return Ok(None);
        };

        control.tag_type().confirm_context()?;

        Ok(Some((self.read.read()?, control.value_type())))
    }

    /// Try to read the next TLV tag and value type.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// 
    /// Returns the tag and value type of the next TLV element.
    /// 
    /// NOTE: Use this method with care, as the value right after the tag needs to be "manually" read by the user,
    /// possibly by using `TLVRead` methods.
    pub fn tag(&mut self, tag_type: TLVTagType) -> Result<TLVTag, Error> {
        self.read.tag(tag_type)
    }

    /// Try to read the next TLV element and its tag.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// Otherwise, the tag and value of the next TLV element are returned.
    /// 
    /// The value is read and materialized as a borrowed reference (i.e. `T` needs to implement `FromTLV`
    /// and the reader needs to implement `BytesSlice`).
    pub fn try_next<'a, T>(&mut self) -> Result<Option<(TLVTag, T)>, Error>
    where
        I: BytesSlice<'a>,
        T: FromTLV<'a>,
    {
        let Some((tag, value_type)) = self.try_next_tag()? else {
            return Ok(None);
        };

        let value = T::from_tlv(value_type, &mut self.read)?;

        Ok(Some((tag, value)))
    }

    /// Try to read the next TLV element and its tag.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// Otherwise, the tag and an in-place initializer for the value of the next TLV element are returned.
    /// 
    /// The value is read and materialized as a borrowed reference (i.e. `T` needs to implement `FromTLV`
    /// and the reader needs to implement `BytesSlice`).
    /// 
    /// TODO: Signature not correct
    pub fn try_next_init<'a, T>(
        &mut self,
    ) -> Result<Option<(TLVTag, impl init::Init<T, Error> + 'a)>, Error>
    where
        I: BytesSlice<'a> + Clone + 'a,
        T: FromTLV<'a>,
    {
        let Some((tag, value_type)) = self.try_next_tag()? else {
            return Ok(None);
        };

        let value = T::init_from_tlv(value_type, self.read.clone());

        Ok(Some((tag, value)))
    }

    /// Try to read the next TLV element and its tag.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// Otherwise, the tag and value of the next TLV element are returned.
    /// 
    /// The value is read and materialized as an owned value (i.e. `T` needs to implement `FromTLVOwned`).
    pub fn try_next_owned<T>(&mut self) -> Result<Option<(TLVTag, T)>, Error>
    where
        T: FromTLVOwned,
    {
        let Some((tag, value_type)) = self.try_next_tag()? else {
            return Ok(None);
        };

        let value = T::from_tlv_owned(value_type, &mut self.read)?;

        Ok(Some((tag, value)))
    }

    /// Try to read the next TLV element and its tag.
    /// 
    /// If the end of the TLV stream is reached (either container end or stream end), `Ok(None)` is returned.
    /// Otherwise, the tag and an in-place initializer for the value of the next TLV element are returned.
    /// 
    /// The value is read and materialized as an owned value (i.e. `T` needs to implement `FromTLVOwned`).
    pub fn try_next_init_owned<T>(
        &mut self,
    ) -> Result<Option<(TLVTag, impl init::Init<T, Error>)>, Error>
    where
        I: Clone,
        T: FromTLVOwned,
    {
        let Some((tag, value_type)) = self.try_next_tag()? else {
            return Ok(None);
        };

        let value = T::init_from_tlv_owned(value_type, self.read.clone());

        Ok(Some((tag, value)))
    }
}

impl<I> From<I> for TLVIter<I>
where
    I: BytesRead,
{
    fn from(read: I) -> Self {
        Self::new(read)
    }
}

impl<'a, I, T> Iterator for TLVIter<I>
where
    I: BytesSlice<'a>,
    T: FromTLV<'a>,
{
    type Item = Result<(TLVTag, T), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().transpose()
    }
}
