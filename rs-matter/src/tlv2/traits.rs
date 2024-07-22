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
    BytesRead, BytesSlice, BytesWrite, TLVRead, TLVTag, TLVValue, TLVValueType, TLVWrite, ToTLVIter,
};

pub use array::*;
pub use bitflags::*;
pub use iter::*;
pub use maybe::*;
pub use octets::*;
pub use primitive::*;
pub use slice::*;
pub use str::*;
pub use tlvarray::*;
pub use vec::*;

mod array;
mod bitflags;
mod iter;
mod maybe;
mod octets;
mod primitive;
mod slice;
mod str;
mod tlvarray;
mod vec;

pub trait FromTLVOwned: Sized + 'static {
    fn from_tlv_owned<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesRead;

    fn init_from_tlv_owned<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot| {
                core::ptr::write(slot, Self::from_tlv_owned(value_type, read)?);

                Ok(())
            })
        }
    }

    fn from_tlv_owned_maybe<I>(value_type: Option<TLVValueType>, read: I) -> Result<Self, Error>
    where
        I: BytesRead,
    {
        Self::from_tlv_owned(TLVValueType::present(value_type)?, read)
    }

    fn init_from_tlv_owned_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> impl init::Init<Self, Error>
    where
        I: BytesRead + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot| {
                init::Init::__init(
                    Self::init_from_tlv_owned(TLVValueType::present(value_type)?, read),
                    slot,
                )
            })
        }
    }
}

pub trait FromTLV<'a>: Sized + 'a {
    fn from_tlv<I>(value_type: TLVValueType, read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>;

    fn init_from_tlv<I>(value_type: TLVValueType, read: I) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot| {
                core::ptr::write(slot, Self::from_tlv(value_type, read)?);

                Ok(())
            })
        }
    }

    fn from_tlv_maybe<I>(value_type: Option<TLVValueType>, read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>,
    {
        Self::from_tlv(TLVValueType::present(value_type)?, read)
    }

    fn init_from_tlv_maybe<I>(
        value_type: Option<TLVValueType>,
        read: I,
    ) -> impl init::Init<Self, Error>
    where
        I: BytesSlice<'a> + Clone,
    {
        unsafe {
            init::init_from_closure(move |slot| {
                init::Init::__init(
                    Self::init_from_tlv(TLVValueType::present(value_type)?, read),
                    slot,
                )
            })
        }
    }
}

pub trait ToTLV {
    fn to_tlv<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: BytesWrite;

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8>;

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8>;
}

impl<T> ToTLV for &T
where
    T: ToTLV,
{
    fn to_tlv<O>(&self, tag: &TLVTag, write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        (*self).to_tlv(tag, write)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        (*self).to_tlv_iter(tag)
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        self.to_tlv_iter(tag)
    }
}

impl<'a> FromTLV<'a> for TLVValue<'a> {
    fn from_tlv<I>(value_type: TLVValueType, mut read: I) -> Result<Self, Error>
    where
        I: BytesSlice<'a>,
    {
        read.value(value_type)
    }
}

impl<'a> ToTLV for TLVValue<'a> {
    fn to_tlv<O>(&self, tag: &TLVTag, mut write: O) -> Result<(), Error>
    where
        O: BytesWrite,
    {
        write.tag(tag, self.value_type())?;
        write.value(self)
    }

    fn to_tlv_iter(&self, tag: TLVTag) -> impl Iterator<Item = u8> {
        empty().tag(tag, self.value_type()).value(self.clone())
    }

    fn into_tlv_iter(self, tag: TLVTag) -> impl Iterator<Item = u8> {
        empty().tag(tag, self.value_type()).value(self)
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
