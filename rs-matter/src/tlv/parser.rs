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

use byteorder::{ByteOrder, LittleEndian};

use num::FromPrimitive;
use num_traits::ToBytes;

use core::fmt;

use crate::error::{Error, ErrorCode};

use super::{Either6, TagType, TLVTagType};

// pub struct TLVList<'a> {
//     buf: &'a [u8],
// }

// impl<'a> TLVList<'a> {
//     pub fn new(buf: &'a [u8]) -> TLVList<'a> {
//         TLVList { buf }
//     }
// }

// impl<'a> Display for TLVList<'a> {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let tlvlist = self;

//         const MAX_DEPTH: usize = 9;
//         const SPACE_BUF: &str = "                                ";

//         let space: [&str; MAX_DEPTH] = [
//             &SPACE_BUF[0..0],
//             &SPACE_BUF[0..4],
//             &SPACE_BUF[0..8],
//             &SPACE_BUF[0..12],
//             &SPACE_BUF[0..16],
//             &SPACE_BUF[0..20],
//             &SPACE_BUF[0..24],
//             &SPACE_BUF[0..28],
//             &SPACE_BUF[0..32],
//         ];

//         let mut stack: [char; MAX_DEPTH] = [' '; MAX_DEPTH];
//         let mut index = 0_usize;
//         let iter = tlvlist.iter();
//         for a in iter {
//             match a.element_type {
//                 ElementType::Struct(_) => {
//                     if index < MAX_DEPTH {
//                         writeln!(f, "{}{}", space[index], a)?;
//                         stack[index] = '}';
//                         index += 1;
//                     } else {
//                         writeln!(f, "<<Too Deep>>")?;
//                     }
//                 }
//                 ElementType::Array(_) | ElementType::List(_) => {
//                     if index < MAX_DEPTH {
//                         writeln!(f, "{}{}", space[index], a)?;
//                         stack[index] = ']';
//                         index += 1;
//                     } else {
//                         writeln!(f, "<<Too Deep>>")?;
//                     }
//                 }
//                 ElementType::EndCnt => {
//                     if index > 0 {
//                         index -= 1;
//                         writeln!(f, "{}{}", space[index], stack[index])?;
//                     } else {
//                         writeln!(f, "<<Incorrect TLV List>>")?;
//                     }
//                 }
//                 _ => writeln!(f, "{}{}", space[index], a)?,
//             }
//         }

//         Ok(())
//     }
// }

// pub struct TLVContainerIterator<'a> {
//     nesting: usize,
//     element: TLVElement<'a>,
// }

// impl<'a> Iterator for TLVContainerIterator<'a> {
//     type Item = TLVElement<'a>;

//     fn next(&mut self) -> Option<Self::Item> {
//         let element = self.element;
//         let next = element.next().ok()?;
//         let element_type = next.element_type().ok()?;

//         if element_type.is_container_start() {
//             self.nesting += 1;
//         } else if element_type.is_container_end() {
//             self.nesting -= 1;
//         }

//         self.element = next;

//         if self.nesting == 0 {
//             None
//         } else {
//             Some(element)
//         }
//     }
// }

#[derive(Copy, Clone, Debug)]
pub struct TLVElement<'a>(&'a [u8]);

// impl<'a> PartialEq for TLVElement<'a> {
//     fn eq(&self, other: &Self) -> bool {
//         match self.element_type {
//             ElementType::Struct(buf) | ElementType::Array(buf) | ElementType::List(buf) => {
//                 let mut our_iter = TLVListIterator::from_buf(buf);
//                 let mut their = match other.element_type {
//                     ElementType::Struct(buf) | ElementType::Array(buf) | ElementType::List(buf) => {
//                         TLVListIterator::from_buf(buf)
//                     }
//                     _ => {
//                         // If we are a container, the other must be a container, else this is a mismatch
//                         return false;
//                     }
//                 };
//                 let mut nest_level = 0_u8;
//                 loop {
//                     let ours = our_iter.next();
//                     let theirs = their.next();
//                     if core::mem::discriminant(&ours) != core::mem::discriminant(&theirs) {
//                         // One of us reached end of list, but the other didn't, that's a mismatch
//                         return false;
//                     }
//                     if ours.is_none() {
//                         // End of list
//                         break;
//                     }
//                     // guaranteed to work
//                     let ours = ours.unwrap();
//                     let theirs = theirs.unwrap();

//                     if let ElementType::EndCnt = ours.element_type {
//                         if nest_level == 0 {
//                             break;
//                         }
//                         nest_level -= 1;
//                     } else {
//                         if is_container(&ours.element_type) {
//                             nest_level += 1;
//                             // Only compare the discriminants in case of array/list/structures,
//                             // instead of actual element values. Those will be subsets within this same
//                             // list that will get validated anyway
//                             if core::mem::discriminant(&ours.element_type)
//                                 != core::mem::discriminant(&theirs.element_type)
//                             {
//                                 return false;
//                             }
//                         } else if ours.element_type != theirs.element_type {
//                             return false;
//                         }

//                         if ours.tag_type != theirs.tag_type {
//                             return false;
//                         }
//                     }
//                 }
//                 true
//             }
//             _ => self.tag_type == other.tag_type && self.element_type == other.element_type,
//         }
//     }
// }

impl<'a> TLVElement<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if let Some(this) = Self::new_unchecked(data) {
            this.validate()?;
            Ok(this)
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub const fn new_unchecked(data: &'a [u8]) -> Option<Self> {
        if data.is_empty() {
            None
        } else {
            Some(Self(data))
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        let _ = self.tag()?;
        let _ = self.element()?;

        Ok(())
    }

    pub fn types(&self) -> Result<(TLVTagType, TLVValueType), Error> {
        let control = self.0[0];

        let tag_type = (control & TAG_MASK) >> TAG_SHIFT_BITS;
        let element_type = control & TYPE_MASK;

        let tag_type = FromPrimitive::from_u8(tag_type).ok_or(ErrorCode::InvalidData)?;
        let element_type = FromPrimitive::from_u8(element_type).ok_or(ErrorCode::InvalidData)?;

        Ok((tag_type, element_type))
    }

    pub fn tag_type(&self) -> Result<TLVTagType, Error> {
        self.types().map(|t| t.0)
    }

    pub fn element_type(&self) -> Result<TLVValueType, Error> {
        self.types().map(|t| t.1)
    }

    pub fn tag(&self) -> Result<TagType, Error> {
        let tag_type = self.types()?.0;

        tag_type.read(&self.0[1..])
    }

    pub fn element(&self) -> Result<ElementType<'a>, Error> {
        let (tag_type, element_type) = self.types()?;

        element_type.read(&self.0[1 + tag_type.size()..])
    }

    pub fn is_container(&self) -> Result<bool, Error> {
        Ok(self.element_type()?.is_container())
    }

    pub fn is_container_start(&self) -> Result<bool, Error> {
        Ok(self.element_type()?.is_container_start())
    }

    pub fn is_container_end(&self) -> Result<bool, Error> {
        Ok(self.element_type()?.is_container_end())
    }

    pub fn next_unchecked(&self) -> Result<Option<Self>, Error> {
        let (tag_type, element_type) = self.types()?;

        let size = 1 + tag_type.size() + element_type.size(&self.0[1 + tag_type.size()..])?;
        let next = &self.0[size..];

        Ok(Self::new_unchecked(next))
    }

    pub fn next(&self) -> Result<Option<Self>, Error> {
        let next = self.next_unchecked()?;

        if let Some(next) = next {
            next.validate()?;
        }

        Ok(next)
    }

    pub fn size(&self) -> Result<usize, Error> {
        let (tag_type, element_type) = self.types()?;

        let tag_size = tag_type.size();
        let element_size = element_type.size(&self.0[1 + tag_size..])?;

        Ok(1 + tag_size + element_size)
    }

    pub fn element_slice(&self) -> Result<&'a [u8], Error> {
        Ok(&self.0[..self.size()?])
    }

    // pub fn iter(&self) -> Result<Option<TLVContainerIterator<'a>>, Error> {
    //     if !self.element_type()?.is_container_start() {
    //         return Ok(None);
    //     }

    //     Ok(Some(TLVContainerIterator {
    //         nesting: 1,
    //         element: *self,
    //     }))
    // }

    pub fn next_over(&self) -> Result<Option<Self>, Error> {
        let element_type = self.element_type()?;
        if !element_type.is_container_start() {
            return self.next();
        }

        let mut nesting = 0;
        let mut element = *self;

        loop {
            let element_type = element.element_type()?;

            if element_type.is_container_start() {
                nesting += 1;
            } else if element_type.is_container_end() {
                nesting -= 1;
            }

            if nesting == 0 {
                break;
            }

            if let Some(next_element) = element.next()? {
                element = next_element;
            } else {
                Err(ErrorCode::InvalidData)?;
            }
        }

        element.next()
    }

        // pub fn enter(&self) -> Option<TLVContainerIterator<'a>> {
    //     let buf = match self.element_type {
    //         ElementType::Struct(buf) | ElementType::Array(buf) | ElementType::List(buf) => buf,
    //         _ => return None,
    //     };
    //     let list_iter = TLVListIterator { buf, current: 0 };
    //     Some(TLVContainerIterator {
    //         list_iter,
    //         prev_container: false,
    //         iterator_consumed: false,
    //     })
    // }

    // pub fn new(tag: TagType, value: ElementType<'a>) -> Self {
    //     Self {
    //         tag_type: tag,
    //         element_type: value,
    //     }
    // }

    pub fn i8(&self) -> Result<i8, Error> {
        match self.element()? {
            ElementType::S8(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn u8(&self) -> Result<u8, Error> {
        match self.element()? {
            ElementType::U8(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn i16(&self) -> Result<i16, Error> {
        match self.element()? {
            ElementType::S8(a) => Ok(a.into()),
            ElementType::S16(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn u16(&self) -> Result<u16, Error> {
        match self.element()? {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn i32(&self) -> Result<i32, Error> {
        match self.element()? {
            ElementType::S8(a) => Ok(a.into()),
            ElementType::S16(a) => Ok(a.into()),
            ElementType::S32(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn u32(&self) -> Result<u32, Error> {
        match self.element()? {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a.into()),
            ElementType::U32(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn i64(&self) -> Result<i64, Error> {
        match self.element()? {
            ElementType::S8(a) => Ok(a.into()),
            ElementType::S16(a) => Ok(a.into()),
            ElementType::S32(a) => Ok(a.into()),
            ElementType::S64(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn u64(&self) -> Result<u64, Error> {
        match self.element()? {
            ElementType::U8(a) => Ok(a.into()),
            ElementType::U16(a) => Ok(a.into()),
            ElementType::U32(a) => Ok(a.into()),
            ElementType::U64(a) => Ok(a),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn slice(&self) -> Result<&'a [u8], Error> {
        match self.element()? {
            ElementType::Str8l(s)
            | ElementType::Utf8l(s)
            | ElementType::Str16l(s)
            | ElementType::Utf16l(s) => Ok(s),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn str(&self) -> Result<&'a str, Error> {
        match self.element()? {
            ElementType::Str8l(s)
            | ElementType::Utf8l(s)
            | ElementType::Str16l(s)
            | ElementType::Utf16l(s) => {
                Ok(core::str::from_utf8(s).map_err(|_| Error::from(ErrorCode::InvalidData))?)
            }
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn bool(&self) -> Result<bool, Error> {
        match self.element_type()? {
            TLVValueType::False => Ok(false),
            TLVValueType::True => Ok(true),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn null(&self) -> Result<(), Error> {
        match self.element_type()? {
            TLVValueType::Null => Ok(()),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn confirm_container(&self) -> Result<&TLVElement<'a>, Error> {
        match self.element_type()? {
            TLVValueType::Struct | TLVValueType::Array | TLVValueType::List => Ok(self),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }
    
    pub fn confirm_struct(&self) -> Result<&TLVElement<'a>, Error> {
        match self.element_type()? {
            ElementType::Struct => Ok(self),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn confirm_array(&self) -> Result<&TLVElement<'a>, Error> {
        match self.element_type()? {
            ElementType::Array => Ok(self),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    pub fn confirm_list(&self) -> Result<&TLVElement<'a>, Error> {
        match self.element_type()? {
            ElementType::List => Ok(self),
            _ => Err(ErrorCode::TLVTypeMismatch.into()),
        }
    }

    // pub fn find_tag(&self, tag: u32) -> Result<TLVElement<'a>, Error> {
    //     let match_tag: TagType = TagType::Context(tag as u8);

    //     let iter = self.enter().ok_or(ErrorCode::TLVTypeMismatch)?;
    //     for a in iter {
    //         if match_tag == a.tag_type {
    //             return Ok(a);
    //         }
    //     }
    //     Err(ErrorCode::NoTagFound.into())
    // }

    pub fn check_ctx_tag(&self, tag: u8) -> Result<bool, Error> {
        if let TagType::Context(our_tag) = self.tag()? {
            if our_tag == tag {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl<'a> fmt::Display for TLVElement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tag().map_err(|_| fmt::Error)? {
            TagType::Anonymous => (),
            TagType::Context(tag) => write!(f, "{}: ", tag)?,
            other => write!(f, "{}: ", other)?,
        }

        write!(f, "{}", self.element().map_err(|_| fmt::Error)?)
    }
}

// pub fn print_tlv_list(b: &[u8]) {
//     info!("TLV list:\n{}\n---------", TLVList::new(b));
// }

#[cfg(test)]
mod tests {
    use log::info;

    use super::{
        get_root_node_list, get_root_node_struct, ElementType, TLVElement, TLVList, TagType,
    };
    use crate::error::ErrorCode;

    #[test]
    fn test_short_length_tag() {
        // The 0x36 is an array with a tag, but we leave out the tag field
        let b = [0x15, 0x36];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_invalid_value_type() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [0x15, 0x1f, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_immediate() {
        // The 0x24 is a a tagged integer, here we leave out the integer value
        let b = [0x15, 0x24, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_short_length_value_string() {
        // This is a tagged string, with tag 0 and length 0xb, but we only have 4 bytes in the string
        let b = [0x15, 0x30, 0x00, 0x0b, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next(), None);
    }

    #[test]
    fn test_valid_tag() {
        // The 0x36 is an array with a tag, here tag is 0
        let b = [0x15, 0x36, 0x0];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::Array(&[]),
            })
        );
    }

    #[test]
    fn test_valid_value_immediate() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::U8(2),
            })
        );
    }

    #[test]
    fn test_valid_value_string() {
        // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
        let b = [0x15, 0x30, 0x5, 0x04, 0x73, 0x6d, 0x61, 0x72];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(5),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_valid_value_string16() {
        // This is a tagged string, with tag 0 and length 4, and we have 4 bytes in the string
        let b = [
            0x15, 0x31, 0x1, 0xd8, 0x1, 0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3,
            0x2, 0x1, 0x2, 0x2, 0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa,
            0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30,
            0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20,
            0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b,
            0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x30,
            0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31, 0x34, 0x32, 0x33, 0x34,
            0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33,
            0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31, 0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4,
            0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
            0x50, 0x41, 0x49, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82,
            0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6,
            0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30,
            0x30, 0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
            0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80, 0xdd,
            0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda, 0x14, 0x62,
            0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1, 0x8f, 0xe1, 0xab,
            0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc, 0xc6, 0xd9, 0xb5, 0xfa, 0xb6,
            0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17, 0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70,
            0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66, 0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13,
            0x1, 0x1, 0xff, 0x4, 0x8, 0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6,
            0x3, 0x55, 0x1d, 0xf, 0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6,
            0x3, 0x55, 0x1d, 0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5,
            0x15, 0xec, 0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30,
            0x1f, 0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd, 0x22,
            0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc, 0xdc, 0x31,
            0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2,
            0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9, 0xc8, 0xcf, 0x2e, 0x1, 0x88,
            0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b, 0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a,
            0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea, 0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54,
            0x94, 0x3b, 0xe5, 0x7d, 0x53, 0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2,
            0x3, 0x6c, 0xd2, 0x9b, 0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71,
            0x82, 0x19, 0x26, 0x2, 0x3e, 0x0, 0x0, 0x0,
        ];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::Str16l(&[
                    0x30, 0x82, 0x1, 0xd4, 0x30, 0x82, 0x1, 0x7a, 0xa0, 0x3, 0x2, 0x1, 0x2, 0x2,
                    0x8, 0x3e, 0x6c, 0xe6, 0x50, 0x9a, 0xd8, 0x40, 0xcd, 0x30, 0xa, 0x6, 0x8, 0x2a,
                    0x86, 0x48, 0xce, 0x3d, 0x4, 0x3, 0x2, 0x30, 0x30, 0x31, 0x18, 0x30, 0x16, 0x6,
                    0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x20, 0x54,
                    0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x41, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa,
                    0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1, 0xc, 0x4, 0x46, 0x46,
                    0x46, 0x31, 0x30, 0x20, 0x17, 0xd, 0x32, 0x31, 0x30, 0x36, 0x32, 0x38, 0x31,
                    0x34, 0x32, 0x33, 0x34, 0x33, 0x5a, 0x18, 0xf, 0x39, 0x39, 0x39, 0x39, 0x31,
                    0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x46, 0x31,
                    0x18, 0x30, 0x16, 0x6, 0x3, 0x55, 0x4, 0x3, 0xc, 0xf, 0x4d, 0x61, 0x74, 0x74,
                    0x65, 0x72, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x50, 0x41, 0x49, 0x31, 0x14,
                    0x30, 0x12, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x1,
                    0xc, 0x4, 0x46, 0x46, 0x46, 0x31, 0x31, 0x14, 0x30, 0x12, 0x6, 0xa, 0x2b, 0x6,
                    0x1, 0x4, 0x1, 0x82, 0xa2, 0x7c, 0x2, 0x2, 0xc, 0x4, 0x38, 0x30, 0x30, 0x30,
                    0x30, 0x59, 0x30, 0x13, 0x6, 0x7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x2, 0x1, 0x6,
                    0x8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1, 0x7, 0x3, 0x42, 0x0, 0x4, 0x80,
                    0xdd, 0xf1, 0x1b, 0x22, 0x8f, 0x3e, 0x31, 0xf6, 0x3b, 0xcf, 0x57, 0x98, 0xda,
                    0x14, 0x62, 0x3a, 0xeb, 0xbd, 0xe8, 0x2e, 0xf3, 0x78, 0xee, 0xad, 0xbf, 0xb1,
                    0x8f, 0xe1, 0xab, 0xce, 0x31, 0xd0, 0x8e, 0xd4, 0xb2, 0x6, 0x4, 0xb6, 0xcc,
                    0xc6, 0xd9, 0xb5, 0xfa, 0xb6, 0x4e, 0x7d, 0xe1, 0xc, 0xb7, 0x4b, 0xe0, 0x17,
                    0xc9, 0xec, 0x15, 0x16, 0x5, 0x6d, 0x70, 0xf2, 0xcd, 0xb, 0x22, 0xa3, 0x66,
                    0x30, 0x64, 0x30, 0x12, 0x6, 0x3, 0x55, 0x1d, 0x13, 0x1, 0x1, 0xff, 0x4, 0x8,
                    0x30, 0x6, 0x1, 0x1, 0xff, 0x2, 0x1, 0x0, 0x30, 0xe, 0x6, 0x3, 0x55, 0x1d, 0xf,
                    0x1, 0x1, 0xff, 0x4, 0x4, 0x3, 0x2, 0x1, 0x6, 0x30, 0x1d, 0x6, 0x3, 0x55, 0x1d,
                    0xe, 0x4, 0x16, 0x4, 0x14, 0xaf, 0x42, 0xb7, 0x9, 0x4d, 0xeb, 0xd5, 0x15, 0xec,
                    0x6e, 0xcf, 0x33, 0xb8, 0x11, 0x15, 0x22, 0x5f, 0x32, 0x52, 0x88, 0x30, 0x1f,
                    0x6, 0x3, 0x55, 0x1d, 0x23, 0x4, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6a, 0xfd,
                    0x22, 0x77, 0x1f, 0x51, 0x1f, 0xec, 0xbf, 0x16, 0x41, 0x97, 0x67, 0x10, 0xdc,
                    0xdc, 0x31, 0xa1, 0x71, 0x7e, 0x30, 0xa, 0x6, 0x8, 0x2a, 0x86, 0x48, 0xce,
                    0x3d, 0x4, 0x3, 0x2, 0x3, 0x48, 0x0, 0x30, 0x45, 0x2, 0x21, 0x0, 0x96, 0xc9,
                    0xc8, 0xcf, 0x2e, 0x1, 0x88, 0x60, 0x5, 0xd8, 0xf5, 0xbc, 0x72, 0xc0, 0x7b,
                    0x75, 0xfd, 0x9a, 0x57, 0x69, 0x5a, 0xc4, 0x91, 0x11, 0x31, 0x13, 0x8b, 0xea,
                    0x3, 0x3c, 0xe5, 0x3, 0x2, 0x20, 0x25, 0x54, 0x94, 0x3b, 0xe5, 0x7d, 0x53,
                    0xd6, 0xc4, 0x75, 0xf7, 0xd2, 0x3e, 0xbf, 0xcf, 0xc2, 0x3, 0x6c, 0xd2, 0x9b,
                    0xa6, 0x39, 0x3e, 0xc7, 0xef, 0xad, 0x87, 0x14, 0xab, 0x71, 0x82, 0x19
                ]),
            })
        );
        assert_eq!(
            tlv_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(62),
            })
        );
    }

    #[test]
    fn test_no_iterator_for_int() {
        // The 0x24 is a a tagged integer, here the integer is 2
        let b = [0x15, 0x24, 0x1, 0x2];
        let tlvlist = TLVList::new(&b);
        let mut tlv_iter = tlvlist.iter();
        // Skip the 0x15
        tlv_iter.next();
        assert_eq!(tlv_iter.next().unwrap().enter(), None);
    }

    #[test]
    fn test_struct_iteration_with_mix_values() {
        // This is a struct with 3 valid values
        let b = [
            0x15, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];
        let mut root_iter = get_root_node_struct(&b).unwrap().enter().unwrap();
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_struct_find_element_mix_values() {
        // This is a struct with 3 valid values
        let b = [
            0x15, 0x30, 0x3, 0x04, 0x73, 0x6d, 0x61, 0x72, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10,
            0x02, 0x00,
        ];
        let root = get_root_node_struct(&b).unwrap();

        assert_eq!(
            root.find_tag(0).unwrap(),
            TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            }
        );
        assert_eq!(
            root.find_tag(2).unwrap(),
            TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            }
        );
        assert_eq!(
            root.find_tag(3).unwrap(),
            TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            }
        );
    }

    #[test]
    fn test_list_iteration_with_mix_values() {
        // This is a list with 3 valid values
        let b = [
            0x17, 0x24, 0x0, 0x2, 0x26, 0x2, 0x4e, 0x10, 0x02, 0x00, 0x30, 0x3, 0x04, 0x73, 0x6d,
            0x61, 0x72,
        ];
        let mut root_iter = get_root_node_list(&b).unwrap().enter().unwrap();
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(135246),
            })
        );
        assert_eq!(
            root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(3),
                element_type: ElementType::Str8l(&[0x73, 0x6d, 0x61, 0x72]),
            })
        );
    }

    #[test]
    fn test_complex_structure_invoke_cmd() {
        // This is what we typically get in an invoke command
        let b = [
            0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x25, 0x0, 0x2, 0x0, 0x26, 0x1, 0x6, 0x0, 0x0, 0x0,
            0x26, 0x2, 0x1, 0x0, 0x0, 0x0, 0x18, 0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
        ];

        let root = get_root_node_struct(&b).unwrap();

        let mut cmd_list_iter = root
            .find_tag(0)
            .unwrap()
            .confirm_array()
            .unwrap()
            .enter()
            .unwrap();
        info!("Command list iterator: {:?}", cmd_list_iter);

        // This is an array of CommandDataIB, but we'll only use the first element
        let cmd_data_ib = cmd_list_iter.next().unwrap();

        let cmd_path = cmd_data_ib.find_tag(0).unwrap();
        let cmd_path = cmd_path.confirm_list().unwrap();
        assert_eq!(
            cmd_path.find_tag(0).unwrap(),
            TLVElement {
                tag_type: TagType::Context(0),
                element_type: ElementType::U16(2),
            }
        );
        assert_eq!(
            cmd_path.find_tag(1).unwrap(),
            TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::U32(6),
            }
        );
        assert_eq!(
            cmd_path.find_tag(2).unwrap(),
            TLVElement {
                tag_type: TagType::Context(2),
                element_type: ElementType::U32(1),
            }
        );
        assert_eq!(
            cmd_path.find_tag(3).map_err(|e| e.code()),
            Err(ErrorCode::NoTagFound)
        );

        // This is the variable of the invoke command
        assert_eq!(
            cmd_data_ib.find_tag(1).unwrap().enter().unwrap().next(),
            None
        );
    }

    #[test]
    fn test_read_past_end_of_container() {
        let b = [0x15, 0x35, 0x0, 0x24, 0x1, 0x2, 0x18, 0x24, 0x0, 0x2, 0x18];

        let mut sub_root_iter = get_root_node_struct(&b)
            .unwrap()
            .find_tag(0)
            .unwrap()
            .enter()
            .unwrap();
        assert_eq!(
            sub_root_iter.next(),
            Some(TLVElement {
                tag_type: TagType::Context(1),
                element_type: ElementType::U8(2),
            })
        );
        assert_eq!(sub_root_iter.next(), None);
        // Call next, even after the first next returns None
        assert_eq!(sub_root_iter.next(), None);
        assert_eq!(sub_root_iter.next(), None);
    }

    #[test]
    fn test_basic_list_iterator() {
        // This is the input we have
        let b = [
            0x15, 0x36, 0x0, 0x15, 0x37, 0x0, 0x24, 0x0, 0x2, 0x24, 0x2, 0x6, 0x24, 0x3, 0x1, 0x18,
            0x35, 0x1, 0x18, 0x18, 0x18, 0x18,
        ];

        let dummy_pointer = &b[1..];
        // These are the decoded elements that we expect from this input
        let verify_matrix: [(TagType, ElementType); 13] = [
            (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
            (TagType::Context(0), ElementType::Array(dummy_pointer)),
            (TagType::Anonymous, ElementType::Struct(dummy_pointer)),
            (TagType::Context(0), ElementType::List(dummy_pointer)),
            (TagType::Context(0), ElementType::U8(2)),
            (TagType::Context(2), ElementType::U8(6)),
            (TagType::Context(3), ElementType::U8(1)),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Context(1), ElementType::Struct(dummy_pointer)),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
            (TagType::Anonymous, ElementType::EndCnt),
        ];

        let mut list_iter = TLVList::new(&b).iter();
        let mut index = 0;
        loop {
            let element = list_iter.next();
            match element {
                None => break,
                Some(a) => {
                    assert_eq!(a.tag_type, verify_matrix[index].0);
                    assert_eq!(
                        core::mem::discriminant(&a.element_type),
                        core::mem::discriminant(&verify_matrix[index].1)
                    );
                }
            }
            index += 1;
        }
        // After the end, purposefully try a few more next
        assert_eq!(list_iter.next(), None);
        assert_eq!(list_iter.next(), None);
    }
}
