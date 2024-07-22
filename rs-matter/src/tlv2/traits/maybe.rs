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
//! - optional values apply only to TLV structs, and have the semantics 
//!   that the value is not provided in the TLV stream for that struct
//! - `null` is a property of the type DOMAIN and therefore applies to all TLV types, 
//!   and has the semantics that the value is provided, but is null
//! 
//! Therefore, `Optional<Nullable<T>>` is completely valid (in the context of a struct member)
//! and means that this struct member is optional, but additionally - when provided - can be null.
//!
//! In terms of in-memory optimizations:
//! - Use `Option<T>` only when the optional T value is small, as `Option` cannot be in-place initialized;
//!   otherwise, use `Optional<T>` (which is equivalent to `Maybe<T, AsOptional>` and `Maybe<T, ()>`).
//! - Use `Nullable<T>` (which is equivalent to `Maybe<T, AsNull>`) to represent 
//!   the nullable variations of the TLV types. This can always be initialized in-place.
//! 
//! Using `Optional` (or `Option`) **outside** of struct members has no TLV meaning but won't fail either:
//! - During deserialization, a stream containing a value of type `T` would be deserialized as `Some(T)` if the user has 
//!   provided a `Option<T>` or `Optional<T>` type declaration instead of just `T`
//! - During serialization, a value of `Some(T)` would be serialized as `T`, while a value `None` would simply not be serialized

use core::fmt::Debug;
use core::hash::Hash;
use core::iter::empty;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use std::ops::{Deref, DerefMut};

use crate::error::Error;
use crate::utils::init;

use super::{
    BytesRead, BytesSlice, BytesWrite, FromTLV, FromTLVOwned, TLVTag, TLVValueType, TLVWrite, ToTLV,
};

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

/// Represents a type similar in spirit to the built-in `Option` type.
/// Unlike `Option` however, `Maybe` does have in-place initializer support.
#[derive(Debug)]
pub struct Maybe<T, G = ()> {
    some: bool,
    value: MaybeUninit<T>,
    _tag: PhantomData<G>,
}

impl<T, G> Maybe<T, G> {
    pub fn new(value: Option<T>) -> Self {
        match value {
            Some(v) => Self::some(v),
            None => Self::none(),
        }
    }

    pub const fn none() -> Self {
        Self {
            some: false,
            value: MaybeUninit::uninit(),
            _tag: PhantomData,
        }
    }

    pub const fn some(value: T) -> Self {
        Self {
            some: true,
            value: MaybeUninit::new(value),
            _tag: PhantomData,
        }
    }

    pub fn init_none() -> impl init::Init<Self> {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(false);

                Ok(())
            })
        }
    }

    pub fn init_some<I: init::Init<T, E>, E>(value: I) -> impl init::Init<Self, E> {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(true);

                value.__init(addr_of_mut!((*slot).value) as _)?;

                Ok(())
            })
        }
    }

    pub fn as_mut(&mut self) -> Option<&mut T> {
        if self.some {
            Some(unsafe { self.value.assume_init_mut() })
        } else {
            None
        }
    }

    pub fn as_ref(&self) -> Option<&T> {
        if self.some {
            Some(unsafe { self.value.assume_init_ref() })
        } else {
            None
        }
    }

    pub fn as_deref(&self) -> Option<&T::Target>
    where
        T: Deref,
    {
        match self.as_ref() {
            Some(t) => Some(t.deref()),
            None => None,
        }
    }

    pub fn as_deref_mut(&mut self) -> Option<&mut T::Target>
    where
        T: DerefMut,
    {
        match self.as_mut() {
            Some(t) => Some(t.deref_mut()),
            None => None,
        }
    }

    pub fn into_option(self) -> Option<T> {
        if self.some {
            Some(unsafe { self.value.assume_init() })
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.some
    }

    pub fn is_some(&self) -> bool {
        self.some
    }
}

impl<T, G> Default for Maybe<T, G> {
    fn default() -> Self {
        Self::none()
    }
}

impl<T, G> From<Option<T>> for Maybe<T, G> {
    fn from(value: Option<T>) -> Self {
        Self::new(value)
    }
}

impl<T, G> From<Maybe<T, G>> for Option<T> {
    fn from(value: Maybe<T, G>) -> Self {
        value.into_option()
    }
}

impl<T, G> Clone for Maybe<T, G>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Maybe::<_, G>::new(self.as_ref().cloned())
    }
}

impl<T, G> Copy for Maybe<T, G> where T: Copy {}

impl<T, G> PartialEq for Maybe<T, G>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<T, G> Eq for Maybe<T, G> where T: Eq {}

impl<T, G> Hash for Maybe<T, G>
where
    T: Hash,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state)
    }
}

impl<T: FromTLVOwned> FromTLVOwned for Maybe<T, AsNullable> {
    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Maybe<T, AsNullable>, Error>
    where
        I: BytesRead,
    {
        match value_type {
            TLVValueType::Null => Ok(Maybe::none()),
            _ => Ok(Maybe::some(T::from_tlv_owned(value_type, read)?)),
        }
    }

    fn init_from_tlv_owned<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                let null = matches!(value_type, TLVValueType::Null);

                addr_of_mut!((*slot).some).write(null);

                if !null {
                    init::Init::__init(
                        T::init_from_tlv_owned(value_type, read),
                        addr_of_mut!((*slot).value) as _,
                    )?;
                }

                Ok(())
            })
        }
    }
}

impl<'a, T: FromTLV<'a>> FromTLV<'a> for Maybe<T, AsNullable> {
    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Maybe<T, AsNullable>, Error>
    where
        I: BytesSlice<'a>,
    {
        match value_type {
            TLVValueType::Null => Ok(Maybe::none()),
            _ => Ok(Maybe::some(T::from_tlv(value_type, read)?)),
        }
    }

    fn init_from_tlv<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                let null = matches!(value_type, TLVValueType::Null);

                addr_of_mut!((*slot).some).write(null);

                if !null {
                    init::Init::__init(
                        T::init_from_tlv(value_type, read),
                        addr_of_mut!((*slot).value) as _,
                    )?;
                }

                Ok(())
            })
        }
    }
}

impl<T: ToTLV> ToTLV for Maybe<T, AsNullable> {
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        match self.as_ref() {
            None => write.null(tag),
            Some(s) => s.to_tlv(tag, write),
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

impl<T: FromTLVOwned> FromTLVOwned for Maybe<T, AsOptional> {
    fn from_tlv_owned_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> Result<Maybe<T, AsOptional>, Error>
    where
        I: BytesRead,
    {
        match value_type {
            None => Ok(Maybe::none()),
            Some(value_type) => Self::from_tlv_owned(value_type, read),
        }
    }

    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Maybe<T, AsOptional>, Error>
    where
        I: BytesRead,
    {
        Ok(Maybe::some(T::from_tlv_owned(value_type, read)?))
    }

    fn init_from_tlv_owned_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                if let Some(value_type) = value_type {
                    init::Init::__init(
                        Self::init_from_tlv_owned(value_type, read),
                        addr_of_mut!((*slot).value) as _,
                    )?;
                } else {
                    addr_of_mut!((*slot).some).write(false);
                }

                Ok(())
            })
        }
    }

    fn init_from_tlv_owned<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(true);

                init::Init::__init(
                    T::init_from_tlv_owned(value_type, read),
                    addr_of_mut!((*slot).value) as _,
                )
            })
        }
    }
}

impl<'a, T: FromTLV<'a> + 'a> FromTLV<'a> for Maybe<T, AsOptional> {
    fn from_tlv_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> Result<Maybe<T, AsOptional>, Error>
    where
        I: BytesSlice<'a>,
    {
        match value_type {
            None => Ok(Maybe::none()),
            Some(value_type) => Self::from_tlv(value_type, read),
        }
    }

    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Maybe<T, AsOptional>, Error>
    where
        I: BytesSlice<'a>,
    {
        Ok(Maybe::some(T::from_tlv(value_type, read)?))
    }

    fn init_from_tlv_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                if let Some(value_type) = value_type {
                    init::Init::__init(
                        Self::init_from_tlv(value_type, read),
                        addr_of_mut!((*slot).value) as _,
                    )?;
                } else {
                    addr_of_mut!((*slot).some).write(false);
                }

                Ok(())
            })
        }
    }

    fn init_from_tlv<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot: *mut Self| {
                addr_of_mut!((*slot).some).write(true);

                init::Init::__init(
                    T::init_from_tlv(value_type, read),
                    addr_of_mut!((*slot).value) as _,
                )
            })
        }
    }
}

impl<T: ToTLV> ToTLV for Maybe<T, AsOptional> {
    fn to_tlv<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        match self.as_ref() {
            None => Ok(()),
            Some(s) => s.to_tlv(tag, write),
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

impl<T: FromTLVOwned> FromTLVOwned for Option<T> {
    fn from_tlv_owned_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> Result<Option<T>, Error>
    where
        I: BytesRead,
    {
        match value_type {
            None => Ok(None),
            Some(value_type) => Self::from_tlv_owned(value_type, read),
        }
    }

    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Option<T>, Error>
    where
        I: BytesRead,
    {
        Ok(Some(T::from_tlv_owned(value_type, read)?))
    }
}

impl<'a, T: FromTLV<'a> + 'a> FromTLV<'a> for Option<T> {
    fn from_tlv_maybe<I>(value_type: Option<TLVValueType>, read: I) -> Result<Option<T>, Error>
    where
        I: BytesSlice<'a>,
    {
        match value_type {
            None => Ok(None),
            Some(value_type) => Self::from_tlv(value_type, read),
        }
    }

    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Option<T>, Error>
    where
        I: BytesSlice<'a>,
    {
        Ok(Some(T::from_tlv(value_type, read)?))
    }
}

impl<T: ToTLV> ToTLV for Option<T> {
    fn to_tlv<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        match self.as_ref() {
            None => Ok(()),
            Some(s) => s.to_tlv(tag, write),
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
