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

//! TLV support for TLV optional values and TLV nullable types via `Maybe` and `Option`.
//! - `Option<T>` and `Optional<T>` both represent an optional value in a TLV struct
//! - `Nullable<T>` represents a nullable TLV type, where `T` is the non-nullable subdomain of the type.
//!    i.e. `Nullable<u8>` represents the nullable variation of the TLV `U8` type.
//!
//! To elaborate, `null` and optional are two different notions in the TLV spec:
//! - Optional values apply only to TLV structs, and have the semantics
//!   that the value is not provided in the TLV stream for that struct
//! - `null` is a property of the type DOMAIN and therefore applies to all TLV types,
//!   and has the semantics that the value is provided, but is null
//!
//! Therefore, `Optional<Nullable<T>>` is completely valid (in the context of a struct member)
//! and means that this struct member is optional, but additionally - when provided - can be null.
//!
//! In terms of memory optimizations:
//! - Use `Option<T>` only when the optional T value is small, as `Option` cannot be in-place initialized;
//!   otherwise, use `Optional<T>` (which is equivalent to `Maybe<T, AsOptional>` and `Maybe<T, ()>`).
//! - Use `Nullable<T>` (which is equivalent to `Maybe<T, AsNull>`) to represent
//!   the nullable variations of the TLV types. This type can always be initialized in-place.
//!
//! Using `Optional` (or `Option`) **outside** of struct members has no TLV meaning but won't fail either:
//! - During deserialization, a stream containing a value of type `T` would be deserialized as `Some(T)` if the user has
//!   provided an `Option<T>` or an `Optional<T>` type declaration instead of just `T`
//! - During serialization, a value of `Some(T)` would be serialized as `T`, while a value `None` would simply not be serialized

use core::fmt::Debug;
use core::iter::empty;

use crate::error::Error;
use crate::utils::init;
use crate::utils::maybe::Maybe;

use super::{FromTLV, TLVElement, TLVTag, TLVValueType, TLVWrite, TLVWriteStorage, ToTLV2};

/// A tag for `Maybe` that makes it behave as an optional struct value per the TLV spec.
pub type AsOptional = ();

/// A tag for `Maybe` that makes it behave as a nullable type per the TLV spec.
#[derive(Debug)]
pub struct AsNullable;

/// Represents optional values as per the TLV spec.
///
/// Note that `Option<T>` also represents optional values, but `Option<T>`
/// cannot be created in-place, which is necessary when large values are involved.
///
/// Therefore, using `Optional<T>` is recommended over `Option<T>` when the optional value is large.
pub type Optional<T> = Maybe<T, AsOptional>;

/// Represents nullable values as per the TLV spec.
pub type Nullable<T> = Maybe<T, AsNullable>;

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Maybe<T, AsNullable> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        match tlv.control()?.value_type {
            TLVValueType::Null => Ok(Maybe::none()),
            _ => Ok(Maybe::some(T::from_tlv(tlv)?)),
        }
    }

    fn init_from_tlv(tlv: TLVElement<'a>) -> impl init::Init<Self, Error> {
        unsafe {
            init::init_from_closure(move |slot| {
                let init = match tlv.control()?.value_type {
                    TLVValueType::Null => None,
                    _ => Some(T::init_from_tlv(tlv)),
                };

                init::Init::__init(Maybe::init(init), slot)
            })
        }
    }
}

impl<T: ToTLV2> ToTLV2 for Maybe<T, AsNullable> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        match self.as_ref() {
            None => TLVWrite::new(write).null(tag),
            Some(s) => s.to_tlv2(tag, write),
        }
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::toiter::ToTLVIter;
        use crate::tlv2::Either;

        match self.as_ref() {
            None => Either::First(empty().null(tag)),
            Some(s) => Either::Second(s.to_tlv_iter(tag)),
        }
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8>
    where
        Self: Sized,
    {
        use crate::tlv2::toiter::ToTLVIter;
        use crate::tlv2::Either;

        match self.into_option() {
            None => Either::First(empty().null(tag)),
            Some(s) => Either::Second(s.into_tlv_iter(tag)),
        }
    }
}

impl<'a, T: FromTLV<'a> + 'a> FromTLV<'a> for Maybe<T, AsOptional> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        if tlv.is_empty() {
            Ok(Self::none())
        } else {
            Ok(Self::some(T::from_tlv(tlv)?))
        }
    }

    fn init_from_tlv(tlv: TLVElement<'a>) -> impl init::Init<Self, Error> {
        if tlv.is_empty() {
            Self::init(None)
        } else {
            Self::init(Some(T::init_from_tlv(tlv)))
        }
    }
}

impl<T: ToTLV2> ToTLV2 for Maybe<T, AsOptional> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        match self.as_ref() {
            None => Ok(()),
            Some(s) => s.to_tlv2(tag, write),
        }
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::Either;

        match self.as_ref() {
            None => Either::First(empty()),
            Some(s) => Either::Second(s.to_tlv_iter(tag)),
        }
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8>
    where
        Self: Sized,
    {
        use crate::tlv2::Either;

        match self.into_option() {
            None => Either::First(empty()),
            Some(s) => Either::Second(s.into_tlv_iter(tag)),
        }
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Option<T> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        if tlv.is_empty() {
            return Ok(None);
        }

        Ok(Some(T::from_tlv(tlv)?))
    }
}

impl<T: ToTLV2> ToTLV2 for Option<T> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        match self.as_ref() {
            None => Ok(()),
            Some(s) => s.to_tlv2(tag, write),
        }
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        use crate::tlv2::Either;

        match self.as_ref() {
            None => Either::First(empty()),
            Some(s) => Either::Second(s.to_tlv_iter(tag)),
        }
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8>
    where
        Self: Sized,
    {
        use crate::tlv2::Either;

        match self {
            None => Either::First(empty()),
            Some(s) => Either::Second(s.into_tlv_iter(tag)),
        }
    }
}
