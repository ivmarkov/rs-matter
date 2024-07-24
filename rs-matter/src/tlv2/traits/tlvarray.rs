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

use crate::tlv2::{TLVTag, ToTLVIter};
use crate::utils::init;
use crate::{error::Error, tlv2::TLVWrite};

use super::{FromTLV, ToTLV, TLV};

/// `TLVArray` is an efficient (memory-wise) way to represent a serialized TLV array, in that
/// it does not materialize the array elements until the array is iterated over.
///
/// Therefore, `TLVArray` is just a wrapper (newtype) of the serialized TLV array `&[u8]` slice.
#[derive(Debug, Copy, Clone)]
#[repr(transparent)]
pub struct TLVArray<'a, T> {
    tlv: &'a [u8],
    _type: PhantomData<fn() -> T>,
}

impl<'a, T> TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    /// Creates a new `TLVArray` from a TLV slice.
    pub fn new(tlv: &'a [u8]) -> Result<Self, Error> {
        tlv.confirm_array()?;

        Ok(Self::new_unchecked(tlv))
    }

    /// Creates a new `TLVArray` from a TLV slice.
    /// The constructor does not check whether the passed slice is a valid TLV array.
    pub const fn new_unchecked(tlv: &'a [u8]) -> Self {
        Self {
            tlv,
            _type: PhantomData,
        }
    }

    /// Returns an iterator over the elements of the array.
    pub fn iter(&self) -> Result<TLVArrayIter<'a, T>, Error> {
        Ok(TLVArrayIter::new(self.tlv.enter_array()?))
    }
}

impl<'a, T> IntoIterator for TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;
    type IntoIter = TLVArrayIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        if let Ok(iter) = self.iter() {
            iter
        } else {
            // Delay the error until the iterator is traversed
            TLVArrayIter::new(&[])
        }
    }
}

impl<'a, T> FromTLV<'a> for TLVArray<'a, T>
where
    T: FromTLV<'a>,
{
    fn from_tlv(tlv: &'a [u8]) -> Result<Self, Error> {
        Self::new(tlv)
    }
}

impl<'a, T> ToTLV for TLVArray<'a, T> {
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: TLVWrite,
    {
        write.start_array(tag)?;

        write._write_raw_data(self.tlv.tlv_container_content_slice()?.into_iter().copied())?;

        write.end_container()
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        core::iter::empty()
            .start_array(tag)
            .chain(
                self.tlv
                    .tlv_container_content_slice()
                    .unwrap()
                    .into_iter()
                    .copied(),
            )
            .end_container()
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        core::iter::empty()
            .start_array(tag)
            .chain(
                self.tlv
                    .tlv_container_content_slice()
                    .unwrap()
                    .into_iter()
                    .copied(),
            )
            .end_container()
    }
}

/// An iterator over a serialized TLV array.
#[repr(transparent)]
pub struct TLVArrayIter<'a, T> {
    current: &'a [u8],
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
    pub const fn new(tlv: &'a [u8]) -> Self {
        Self {
            current: tlv,
            _type: PhantomData,
        }
    }

    pub fn try_next(&mut self) -> Result<Option<T>, Error> {
        let tlv = self.try_next_tlv()?;

        if tlv.is_container_end()? {
            return Ok(None);
        }

        tlv.confirm_anon()?;

        Ok(Some(T::from_tlv(tlv)?))
    }

    pub fn try_next_init(&mut self) -> Result<Option<impl init::Init<T, Error> + 'a>, Error> {
        let tlv = self.try_next_tlv()?;

        if tlv.is_container_end()? {
            return Ok(None);
        }

        tlv.confirm_anon()?;

        Ok(Some(T::init_from_tlv(self.current)))
    }

    fn try_next_tlv(&mut self) -> Result<&'a [u8], Error> {
        let tlv = self.current.clone();

        if !tlv.is_container_end()? {
            self.current = tlv.container_next()?;
        }

        Ok(tlv)
    }
}

impl<'a, T> Iterator for TLVArrayIter<'a, T>
where
    T: FromTLV<'a>,
{
    type Item = Result<T, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.try_next().transpose()
    }
}

// // TODO: Uncomment once impl type aliases in traits are stabilized
// // pub struct TLVArrayInitIter<'a, T> {
// //     current: TLVElement<'a>,
// //     _type: PhantomData<fn() -> T>,
// // }

// // impl<'a, T> Iterator for TLVArrayInitIter<'a, T>
// // where
// //     T: FromTLV<'a>,
// // {
// //     type Item = Result<impl Init<T, Error>, Error>;

// //     fn next(&mut self) -> Option<Self::Item> {
// //         match self.current.is_container_end() {
// //             Ok(true) => None,
// //             Ok(false) => match self.current.next() {
// //                 Ok(Some(t)) => {
// //                     self.current = t;
// //                     Some(T::init_from_tlv(t))
// //                 }
// //                 Ok(None) => None,
// //                 Err(err) => Some(Err(err)),
// //             }
// //             Err(err) => Some(Err(err)),
// //         }
// //     }
// // }

// impl<'a, T> TLVArray<'a, T> {
//     pub fn new(element: TLVElement<'a>) -> Result<Self, Error> {
//         element.confirm_array()?;

//         Ok(Self::new_unchecked(element))
//     }

//     pub const fn new_unchecked(element: TLVElement<'a>) -> Self {
//         Self {
//             start: element,
//             _type: PhantomData,
//         }
//     }

//     pub fn iter(&self) -> TLVArrayIter<'a, T> {
//         TLVArrayIter {
//             current: self.start,
//             _type: PhantomData,
//         }
//     }
// }

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
