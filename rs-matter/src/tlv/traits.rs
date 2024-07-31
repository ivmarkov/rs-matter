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

use core::iter::empty;

use crate::error::Error;
use crate::utils::init;

use super::{
    EitherIter, TLVElement, TLVSequenceIter, TLVTag, TLVValue, TLVValueType, TLVWrite, ToTLVIter,
};

pub use container::*;
pub use maybe::*;
pub use octets::*;
pub use str::*;

mod array;
mod bitflags;
mod container;
mod maybe;
mod octets;
mod primitive;
mod slice;
mod str;
mod vec;

/// A trait representing Rust types that can deserialize themselves from
/// a TLV-encoded byte slice.
pub trait FromTLV<'a>: Sized + 'a {
    /// Deserialize the type from a TLV-encoded element.
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error>;

    /// Generate an in-place initializer for the type that initializes
    /// the type from a TLV-encoded element.
    fn init_from_tlv(tlv: TLVElement<'a>) -> impl init::Init<Self, Error> {
        unsafe {
            init::init_from_closure(move |slot| {
                core::ptr::write(slot, Self::from_tlv(&tlv)?);

                Ok(())
            })
        }
    }
}

// pub trait ToTLV {
//     /// Serialize the type to a TLV-encoded stream.
//     fn to_tlv(&self, tw: &mut TLVWriter, tag: TLVTag) -> Result<(), Error>;
// }

// impl<T> ToTLV for T
// where
//     T: ToTLV,
// {
//     fn to_tlv(&self, tw: &mut TLVWriter, tag: TLVTag) -> Result<(), Error> {
//         self.to_tlv2(&tag, tw)
//     }
// }

/// A trait representing Rust types that can serialize themselves to
/// a TLV-encoded stream.
pub trait ToTLV {
    /// Serialize the type to a TLV-encoded stream.
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error>;

    /// Serialize the type as an iterator of bytes by potentially borrowing
    /// data from the type.
    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>>;

    /// Serialize the type as an iterator of bytes by consuming the type.
    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>>;
}

impl<T> ToTLV for &T
where
    T: ToTLV,
{
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, tw: W) -> Result<(), Error> {
        (*self).to_tlv(tag, tw)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        (*self).to_tlv_iter(tag)
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        self.to_tlv_iter(tag)
    }
}

impl<'a> FromTLV<'a> for TLVElement<'a> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        Ok(tlv.clone())
    }
}

impl<'a> ToTLV for TLVElement<'a> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.raw_value(tag, self.control()?.value_type, self.raw_value()?)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        ToTLVIter::flatten(
            self.control()
                .and_then(move |control| self.raw_value().map(|raw_value| (control, raw_value)))
                .map(move |(control, raw_value)| {
                    empty().raw_value(
                        tag,
                        control.value_type,
                        raw_value.iter().copied().map(Result::Ok),
                    )
                }),
        )
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        ToTLVIter::flatten(
            self.control()
                .and_then(move |control| self.raw_value().map(|raw_value| (control, raw_value)))
                .map(move |(control, raw_value)| {
                    empty().raw_value(
                        tag,
                        control.value_type,
                        raw_value.iter().copied().map(Result::Ok),
                    )
                }),
        )
    }
}

impl<'a> FromTLV<'a> for TLVValue<'a> {
    fn from_tlv(tlv: &TLVElement<'a>) -> Result<Self, Error> {
        tlv.value()
    }
}

impl<'a> ToTLV for TLVValue<'a> {
    fn to_tlv<W: TLVWrite>(&self, tag: &TLVTag, mut tw: W) -> Result<(), Error> {
        tw.tlv(tag, self)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        empty().tlv(tag, self.clone())
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = Result<u8, Error>> {
        empty().tlv(tag, self)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::{FromTLV, OctetStr, TLVWriter, TagType, ToTLV};
//     use crate::{tlv::TLVList, utils::writebuf::WriteBuf};
//     use rs_matter_macros::{FromTLV, ToTLV};

//     #[derive(ToTLV)]
//     struct TestDerive {
//         a: u16,
//         b: u32,
//     }
//     #[test]
//     fn test_derive_totlv() {
//         let mut buf = [0; 20];
//         let mut writebuf = WriteBuf::new(&mut buf);
//         let mut tw = TLVWriter::new(&mut writebuf);

//         let abc = TestDerive {
//             a: 0x1010,
//             b: 0x20202020,
//         };
//         abc.to_tlv(&mut tw, TagType::Anonymous).unwrap();
//         assert_eq!(
//             buf,
//             [21, 37, 0, 0x10, 0x10, 38, 1, 0x20, 0x20, 0x20, 0x20, 24, 0, 0, 0, 0, 0, 0, 0, 0]
//         );
//     }

//     #[derive(FromTLV)]
//     struct TestDeriveSimple {
//         a: u16,
//         b: u32,
//     }

//     #[test]
//     fn test_derive_fromtlv() {
//         let b = [
//             21, 37, 0, 10, 0, 38, 1, 20, 0, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0,
//         ];
//         let root = TLVList::new(&b).iter().next().unwrap();
//         let test = TestDeriveSimple::from_tlv(&root).unwrap();
//         assert_eq!(test.a, 10);
//         assert_eq!(test.b, 20);
//     }

//     #[derive(FromTLV)]
//     #[tlvargs(lifetime = "'a")]
//     struct TestDeriveStr<'a> {
//         a: u16,
//         b: OctetStr<'a>,
//     }

//     #[test]
//     fn test_derive_fromtlv_str() {
//         let b = [21, 37, 0, 10, 0, 0x30, 0x01, 0x03, 10, 11, 12, 0];
//         let root = TLVList::new(&b).iter().next().unwrap();
//         let test = TestDeriveStr::from_tlv(&root).unwrap();
//         assert_eq!(test.a, 10);
//         assert_eq!(test.b, OctetStr(&[10, 11, 12]));
//     }

//     #[derive(FromTLV, Debug)]
//     struct TestDeriveOption {
//         a: u16,
//         b: Option<u16>,
//         c: Option<u16>,
//     }

//     #[test]
//     fn test_derive_fromtlv_option() {
//         let b = [21, 37, 0, 10, 0, 37, 2, 11, 0];
//         let root = TLVList::new(&b).iter().next().unwrap();
//         let test = TestDeriveOption::from_tlv(&root).unwrap();
//         assert_eq!(test.a, 10);
//         assert_eq!(test.b, None);
//         assert_eq!(test.c, Some(11));
//     }

//     #[derive(FromTLV, ToTLV, Debug)]
//     struct TestDeriveFabScoped {
//         a: u16,
//         #[tagval(0xFE)]
//         fab_idx: u16,
//     }
//     #[test]
//     fn test_derive_fromtlv_fab_scoped() {
//         let b = [21, 37, 0, 10, 0, 37, 0xFE, 11, 0];
//         let root = TLVList::new(&b).iter().next().unwrap();
//         let test = TestDeriveFabScoped::from_tlv(&root).unwrap();
//         assert_eq!(test.a, 10);
//         assert_eq!(test.fab_idx, 11);
//     }

//     #[test]
//     fn test_derive_totlv_fab_scoped() {
//         let mut buf = [0; 20];
//         let mut writebuf = WriteBuf::new(&mut buf);
//         let mut tw = TLVWriter::new(&mut writebuf);

//         let abc = TestDeriveFabScoped { a: 20, fab_idx: 3 };

//         abc.to_tlv(&mut tw, TagType::Anonymous).unwrap();
//         assert_eq!(
//             buf,
//             [21, 36, 0, 20, 36, 0xFE, 3, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//         );
//     }

//     #[derive(ToTLV, FromTLV, PartialEq, Debug)]
//     enum TestDeriveEnum {
//         ValueA(u32),
//         ValueB(u32),
//     }

//     #[test]
//     fn test_derive_from_to_tlv_enum() {
//         // Test FromTLV
//         let b = [21, 36, 0, 100, 24, 0];
//         let root = TLVList::new(&b).iter().next().unwrap();
//         let mut enum_val = TestDeriveEnum::from_tlv(&root).unwrap();
//         assert_eq!(enum_val, TestDeriveEnum::ValueA(100));

//         // Modify the value and test ToTLV
//         enum_val = TestDeriveEnum::ValueB(10);

//         // Test ToTLV
//         let mut buf = [0; 20];
//         let mut writebuf = WriteBuf::new(&mut buf);
//         let mut tw = TLVWriter::new(&mut writebuf);

//         enum_val.to_tlv(&mut tw, TagType::Anonymous).unwrap();
//         assert_eq!(
//             buf,
//             [21, 36, 1, 10, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//         );
//     }
// }
