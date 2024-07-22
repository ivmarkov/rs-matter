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

//! An efficient, multi-purpose `TLVArray` enum type that can be used to represent three different internal
//! representations of TLV data with a single type:
//! - `TLVArray::Ptr` - TLV Array data borrowed directly from the TLV deserializer (only possible when the deserializer is a `BytesSlice`)
//!   - Note that the elements of the array are nevertheless still materialized in that case
//!   - Note also that this representation does not have an efficient index operation, as it needs to scan
//!     the TLV data to locate the element, as the data does not have a uniform size
//! - `TLVArray::Slice` - TLV Array data borrowed from the application code (i.e. a wrapper around `&[T]`)
//!   - This representation CANNOT be deserialized (only serialized) as Rust slices do not support deserialization,
//!     so trying to serialize this enum variant will panic
//! - `TLVArray::Vec` - TLV Array data owned by the application code (i.e. a wrapper around `Vec<T>`)
//!   - This representation can be serialized and deserialized

use core::iter::empty;
use std::marker::PhantomData;

use crate::tlv2::{SliceReader, TLVTagType};
use crate::{error::Error, utils::vec::Vec};
use crate::utils::init;

use super::{
    BytesRead, BytesSlice, BytesWrite, FromTLV, TLVIter, TLVRead, TLVTag, TLVValue, TLVValueType, TLVWrite, ToTLVIter
};

#[derive(Debug, Copy, Clone)]
pub struct TLVArray<'a, T> {
    tlv_data: &'a [u8],
    _type: PhantomData<fn() -> T>,
}

impl<'a, T> TLVArray<'a, T> 
where 
    T: FromTLV<'a>,
{
    pub const fn new(tlv_data: &'a [u8]) -> Self {
        Self {
            tlv_data,
            _type: PhantomData,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Result<T, Error>> + 'a {
        TLVIter::new(SliceReader::new(self.tlv_data))
            .map(|r| r.and_then(|(tag, value)| tag.confirm_anonymous().map(|_| value)))
    }
}

pub struct TLVArrayIter<'a, T> {
    current: TLVIter<'a>,
    _type: PhantomData<fn() -> T>,
}

// #[derive(Debug, Clone)]
// pub enum TLVArrayIter<'a, T> {
//     Ptr(SliceReader<'a>),
//     Slice(core::slice::Iter<'a, T>),
// }

// impl<'a, T> Iterator for TLVArrayIter<'a, T>
// where
//     T: FromTLV<'a> + Clone,
// {
//     type Item = Result<T, Error>;

//     fn next(&mut self) -> Option<Self::Item> {
//         match self {
//             Self::Ptr(r) => match r.next() {
//                 Some(t) => Some(T::from_tlv(t?)),
//                 None => None,
//             },
//             Self::Slice(i) => match i.next() {
//                 Some(t) => Some(Ok(t.clone())),
//                 None => None,
//             },
//         }
//     }
// }

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
