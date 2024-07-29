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

//! A container type (`TLVArray`) and an iterator type (`TLVArrayIter`) that represents and iterates directly over serialized TLV arrays.
//! As such, the memory prepresentation of `TLVArray` / `TLVArrayIter` is just a byte slice (`&[u8]`),
//! and the array elements are materialized only when the array is iterated over.

use core::marker::PhantomData;

use crate::error::Error;
use crate::utils::init;

use super::{
    EitherIter, FromTLV, TLVContainerIter, TLVElement, TLVTag, TLVWrite, TLVWriteStorage, ToTLV2,
    ToTLVIter,
};

/// `TLVArray` is an efficient (memory-wise) way to represent a serialized TLV array, in that
/// it does not materialize the array elements until the array is iterated over.
///
/// Therefore, `TLVArray` is just a wrapper (newtype) of the serialized TLV array `&[u8]` slice.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct TLVArray<'a, T> {
    tlv: TLVElement<'a>,
    _type: PhantomData<fn() -> T>,
}

impl<'a, T> TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVArray` from a TLV slice.
    pub fn new(tlv: TLVElement<'a>) -> Result<Self, Error> {
        tlv.array()?;

        Ok(Self::new_unchecked(tlv))
    }

    /// Creates a new `TLVArray` from a TLV slice.
    /// The constructor does not check whether the passed slice is a valid TLV array.
    pub const fn new_unchecked(tlv: TLVElement<'a>) -> Self {
        Self {
            tlv,
            _type: PhantomData,
        }
    }

    /// Returns an iterator over the elements of the array.
    pub fn iter(&self) -> TLVArrayIter<'a, T> {
        TLVArrayIter::new(self.tlv.array().unwrap().iter())
    }
}

impl<'a, T> IntoIterator for TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;
    type IntoIter = TLVArrayIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> FromTLV<'a> for TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        Self::new(tlv.clone())
    }
}

impl<'a, T> ToTLV2 for TLVArray<'a, T> {
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        let mut tw = TLVWrite::new(write);

        tw.start_array(tag)?;

        let seq = self.tlv.array()?;

        for byte in seq.raw_value()? {
            tw.storage_mut().write(*byte)?;
        }

        Ok(())
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        core::iter::empty()
            .start_array(tag)
            .chain(ToTLVIter::flatten(
                self.tlv
                    .array()
                    .and_then(move |array| array.raw_value())
                    .map(move |value| value.into_iter().copied().map(Result::Ok)),
            ))
            .end_container()
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        core::iter::empty()
            .start_array(tag)
            .chain(ToTLVIter::flatten(
                self.tlv
                    .array()
                    .and_then(move |array| array.raw_value())
                    .map(move |value| value.into_iter().copied().map(Result::Ok)),
            ))
            .end_container()
    }
}

/// An iterator over a serialized TLV array.
#[repr(transparent)]
pub struct TLVArrayIter<'a, T> {
    iter: TLVContainerIter<'a>,
    _type: PhantomData<fn() -> T>,
}

impl<'a, T> TLVArrayIter<'a, T>
where
    T: FromTLV<'a>,
{
    /// Create a new `TLVArrayIter` from a TLV slice.
    ///
    /// The slice is expected to be positioned at the 1st, 2nd or Nth element of the array,
    /// or at the array end, but NOT at the beginning of the array (`TLVVAlueType::Array`).
    ///
    /// In other words, pass the outcome of `tlv.enter_array()` to this constructor function.
    pub const fn new(iter: TLVContainerIter<'a>) -> Self {
        Self {
            iter,
            _type: PhantomData,
        }
    }

    pub fn try_next(&mut self) -> Option<Result<T, Error>> {
        let tlv = self.iter.next()?;

        Some(tlv.and_then(|tlv| tlv.confirm_anon().and_then(|_| T::from_tlv(&tlv))))
    }

    pub fn try_next_init(&mut self) -> Option<Result<impl init::Init<T, Error> + 'a, Error>> {
        let tlv = self.iter.next()?;

        Some(tlv.and_then(|tlv| tlv.confirm_anon().map(move |_| T::init_from_tlv(tlv))))
    }
}

impl<'a, T> Iterator for TLVArrayIter<'a, T>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next()
    }
}

/// A container type that can represent either a serialized TLV array or a slice of elements.
///
/// Necessary for the few cases in the code where deserialized TLV structures are mutated -
/// post deserialization - with custom array data.
#[derive(Debug, Clone)]
pub enum TLVArrayOrSlice<'a, T> {
    Array(TLVArray<'a, T>),
    Slice(&'a [T]),
}

impl<'a, T> TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a> + Clone,
{
    /// Creates a new `TLVArrayOrSlice` from a TLV slice.
    pub const fn new_array(array: TLVArray<'a, T>) -> Self {
        Self::Array(array)
    }

    /// Creates a new `TLVArrayOrSlice` from a slice.
    pub const fn new_slice(slice: &'a [T]) -> Self {
        Self::Slice(slice)
    }

    /// Returns an iterator over the elements of the array.
    pub fn iter(&self) -> Result<TLVArrayOrSliceIter<'a, T>, Error> {
        match self {
            Self::Array(array) => Ok(TLVArrayOrSliceIter::Array(array.iter())),
            Self::Slice(slice) => Ok(TLVArrayOrSliceIter::Slice(slice.iter())),
        }
    }
}

impl<'a, T> FromTLV<'a> for TLVArrayOrSlice<'a, T>
where
    T: FromTLV<'a> + Clone,
{
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(Self::new_array(TLVArray::new(tlv.clone())?))
    }
}

impl<'a, T> ToTLV2 for TLVArrayOrSlice<'a, T>
where
    T: ToTLV2,
{
    fn to_tlv2<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: TLVWriteStorage,
    {
        match self {
            Self::Array(array) => array.to_tlv2(tag, write),
            Self::Slice(slice) => slice.to_tlv2(tag, write),
        }
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        match self {
            Self::Array(array) => EitherIter::First(array.to_tlv_iter(tag)),
            Self::Slice(slice) => EitherIter::Second(slice.to_tlv_iter(tag)),
        }
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        match self {
            Self::Array(array) => EitherIter::First(array.into_tlv_iter(tag)),
            Self::Slice(slice) => EitherIter::Second(slice.into_tlv_iter(tag)),
        }
    }
}

/// An iterator over the `TLVArrayOrSlice` elements.
pub enum TLVArrayOrSliceIter<'a, T> {
    Array(TLVArrayIter<'a, T>),
    Slice(core::slice::Iter<'a, T>),
}

impl<'a, T> Iterator for TLVArrayOrSliceIter<'a, T>
where
    T: FromTLV<'a> + Clone,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Array(array) => array.next(),
            Self::Slice(slice) => slice.next().cloned().map(|t| Ok(t)),
        }
    }
}

// impl<'a, T: ToTLV + FromTLV<'a> + Clone> TLVArray<'a, T> {
//     pub fn get_index(&self, index: usize) -> T {
//         for (curr, element) in self.iter().enumerate() {
//             if curr == index {
//                 return element;
//             }
//         }
//         panic!("Out of bounds");
//     }
// }

// // impl<'a, 'b, T> PartialEq<TLVArray<'b, T>> for TLVArray<'a, T>
// // where
// //     T: ToTLV + FromTLV<'a> + Clone + PartialEq,
// //     'b: 'a,
// // {
// //     fn eq(&self, other: &TLVArray<'b, T>) -> bool {
// //         let mut iter1 = self.iter();
// //         let mut iter2 = other.iter();
// //         loop {
// //             match (iter1.next(), iter2.next()) {
// //                 (None, None) => return true,
// //                 (Some(x), Some(y)) => {
// //                     if x != y {
// //                         return false;
// //                     }
// //                 }
// //                 _ => return false,
// //             }
// //         }
// //     }
// // }

// // impl<'a, T> PartialEq<&[T]> for TLVArray<'a, T>
// // where
// //     T: ToTLV + FromTLV<'a> + Clone + PartialEq,
// // {
// //     fn eq(&self, other: &&[T]) -> bool {
// //         let mut iter1 = self.iter();
// //         let mut iter2 = other.iter();
// //         loop {
// //             match (iter1.next(), iter2.next()) {
// //                 (None, None) => return true,
// //                 (Some(x), Some(y)) => {
// //                     if x != *y {
// //                         return false;
// //                     }
// //                 }
// //                 _ => return false,
// //             }
// //         }
// //     }
// // }

// impl<'a, T> FromTLV<'a> for TLVArray<'a, T> {
//     fn from_tlv(t: TLVElement<'a>) -> Result<Self, Error> {
//         TLVArray::new(t)
//     }
// }

// impl<'a, T> ToTLV for TLVArray<'a, T> {
//     fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
//         tw.start_array(tag_type)?;
//         for a in self.iter() {
//             a.to_tlv(tw, TagType::Anonymous)?;
//         }
//         tw.end_container()
//         // match *self {
//         //     Self::Slice(s) => {
//         //         tw.start_array(tag_type)?;
//         //         for a in s {
//         //             a.to_tlv(tw, TagType::Anonymous)?;
//         //         }
//         //         tw.end_container()
//         //     }
//         //     Self::Ptr(t) => t.to_tlv(tw, tag_type), <-- TODO: this fails the unit tests of Cert from/to TLV
//         // }
//     }

//     fn tlv_iter(&self, tag: TagType) -> impl Iterator<Item = u8> + '_ {
//         empty()
//             .start_array(tag)
//             .chain(self.iter().flat_map(move |i| i.into_tlv_iter(TagType::Anonymous)))
//             .end_container()
//     }

//     fn into_tlv_iter(self, tag: TagType) -> impl Iterator<Item = u8> where Self: Sized {
//         empty()
//             .start_array(tag)
//             .chain(self.into_iter().flat_map(move |i| i.into_tlv_iter(TagType::Anonymous)))
//             .end_container()
//     }
// }

// impl<'a, T: Debug + ToTLV + FromTLV<'a> + Clone> Debug for TLVArray<'a, T> {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "TLVArray [")?;
//         let mut first = true;
//         for i in self.iter() {
//             if !first {
//                 write!(f, ", ")?;
//             }

//             write!(f, "{:?}", i)?;
//             first = false;
//         }
//         write!(f, "]")
//     }
// }
