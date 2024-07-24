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

use crate::error::Error;

use super::{TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType};

/// A trait for serializing data as TLV to a storage where bytes can be synchronously
/// written to.
///
/// The trait operates in an append-only manner without requiring access to the serialized
/// TLV data, so it can be implemented with an in-memory storage, or a file storage, or anything
/// that can output a byte to somewhere (like the `Write` Rust traits).
///
/// The one method that needs to be implemented by user code is `TLVWrite::write`.
///
/// For iterator-style TLV serialization look at the `ToTLVIter` trait.
pub trait TLVWrite {
    /// Write a TLV tag and value to the TLV stream.
    fn tlv(&mut self, tag: &TLVTag, value: &TLVValue) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, value.value_type(), &[])?;

        match value {
            TLVValue::Str8l(a) => self._write_raw_data((a.len() as u8).to_le_bytes()),
            TLVValue::Str16l(a) => self._write_raw_data((a.len() as u16).to_le_bytes()),
            TLVValue::Str32l(a) => self._write_raw_data((a.len() as u32).to_le_bytes()),
            TLVValue::Str64l(a) => self._write_raw_data((a.len() as u64).to_le_bytes()),
            TLVValue::Utf8l(a) => self._write_raw_data((a.len() as u8).to_le_bytes()),
            TLVValue::Utf16l(a) => self._write_raw_data((a.len() as u16).to_le_bytes()),
            TLVValue::Utf32l(a) => self._write_raw_data((a.len() as u32).to_le_bytes()),
            TLVValue::Utf64l(a) => self._write_raw_data((a.len() as u64).to_le_bytes()),
            _ => Ok(()),
        }?;

        match value {
            TLVValue::S8(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::S16(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::S32(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::S64(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::U8(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::U16(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::U32(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::U64(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::False => Ok(()),
            TLVValue::True => Ok(()),
            TLVValue::F32(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::F64(a) => self._write_raw_data(a.to_le_bytes()),
            TLVValue::Utf8l(a)
            | TLVValue::Utf16l(a)
            | TLVValue::Utf32l(a)
            | TLVValue::Utf64l(a) => self._write_raw_data(a.as_bytes().into_iter().copied()),
            TLVValue::Str8l(a)
            | TLVValue::Str16l(a)
            | TLVValue::Str32l(a)
            | TLVValue::Str64l(a) => self._write_raw_data(a.into_iter().copied()),
            TLVValue::Null => Ok(()),
            TLVValue::Struct => Ok(()),
            TLVValue::Array => Ok(()),
            TLVValue::List => Ok(()),
            TLVValue::EndCnt => Ok(()),
        }
    }

    /// Write a tag and a TLV S8 value to the TLV stream.
    fn i8(&mut self, tag: &TLVTag, data: i8) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::S8, &data.to_le_bytes())
    }

    /// Write a tag and a TLV U8 value to the TLV stream.
    fn u8(&mut self, tag: &TLVTag, data: u8) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::U8, &data.to_le_bytes())
    }

    /// Write a tag and a TLV S16 or (if the data is small enough) S8 value to the TLV stream.
    fn i16(&mut self, tag: &TLVTag, data: i16) -> Result<(), Error> {
        if data >= i8::MIN as i16 && data <= i8::MAX as i16 {
            self.i8(tag, data as i8)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::S16, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U16 or (if the data is small enough) U8 value to the TLV stream.
    fn u16(&mut self, tag: &TLVTag, data: u16) -> Result<(), Error> {
        if data <= u8::MAX as u16 {
            self.u8(tag, data as u8)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::U16, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV S32 or (if the data is small enough) S16 or S8 value to the TLV stream.
    fn i32(&mut self, tag: &TLVTag, data: i32) -> Result<(), Error> {
        if data >= i16::MIN as i32 && data <= i16::MAX as i32 {
            self.i16(tag, data as i16)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::S32, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U32 or (if the data is small enough) U16 or U8 value to the TLV stream.
    fn u32(&mut self, tag: &TLVTag, data: u32) -> Result<(), Error> {
        if data <= u16::MAX as u32 {
            self.u16(tag, data as u16)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::U32, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV S64 or (if the data is small enough) S32, S16, or S8 value to the TLV stream.
    fn i64(&mut self, tag: &TLVTag, data: i64) -> Result<(), Error> {
        if data >= i32::MIN as i64 && data <= i32::MAX as i64 {
            self.i32(tag, data as i32)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::S64, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV U64 or (if the data is small enough) U32, U16, or U8 value to the TLV stream.
    fn u64(&mut self, tag: &TLVTag, data: u64) -> Result<(), Error> {
        if data <= u32::MAX as u64 {
            self.u32(tag, data as u32)
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::U64, &data.to_le_bytes())
        }
    }

    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is a slice of u8 bytes.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn str(&mut self, tag: &TLVTag, data: &[u8]) -> Result<(), Error> {
        self.stri(tag, data.len(), data.into_iter().copied())
    }

    /// Write a tag and a TLV Octet String to the TLV stream, where the Octet String is
    /// anything that can be turned into an iterator of u8 bytes.
    ///
    /// The exact octet string type (Str8l, Str16l, Str32l, or Str64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE: The length of the Octet String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    fn stri<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Str8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Str16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Str32l, &(len as u32).to_le_bytes())?;
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::Str64l, &(len as u64).to_le_bytes())?;
        }

        self._write_raw_data(data)
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is a str.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    fn utf8(&mut self, tag: &TLVTag, data: &str) -> Result<(), Error> {
        self.utf8i(tag, data.len(), data.as_bytes().into_iter().copied())
    }

    /// Write a tag and a TLV UTF-8 String to the TLV stream, where the UTF-8 String is
    /// anything that can be turned into an iterator of u8 bytes.
    ///
    /// The exact UTF-8 string type (Utf8l, Utf16l, Utf32l, or Utf64l) is chosen based on the length of the data,
    /// whereas the smallest type filling the provided data length is chosen.
    ///
    /// NOTE 1: The length of the UTF-8 String must be provided by the user and it must match the
    /// number of bytes returned by the provided iterator, or else the generated TLV stream will be invalid.
    ///
    /// NOTE 2: The provided iterator must return valid UTF-8 bytes, or else the generated TLV stream will be invalid.
    fn utf8i<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Utf8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Utf16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self._write_tagged_raw_data(tag, TLVValueType::Utf32l, &(len as u32).to_le_bytes())?;
        } else {
            self._write_tagged_raw_data(tag, TLVValueType::Utf64l, &(len as u64).to_le_bytes())?;
        }

        self._write_raw_data(data)
    }

    /// Write a tag and a value indicating the start of a Struct TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the Struct fields
    /// to close the Struct container or else the generated TLV stream will be invalid.
    fn start_struct(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::Struct, &[])
    }

    /// Write a tag and a value indicating the start of an Array TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the Array elements
    /// to close the Array container or else the generated TLV stream will be invalid.
    fn start_array(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::Array, &[])
    }

    /// Write a tag and a value indicating the start of a List TLV container.
    ///
    /// NOTE: The user must call `end_container` after writing all the List elements
    /// to close the List container or else the generated TLV stream will be invalid.
    fn start_list(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::List, &[])
    }

    /// Write a value indicating the end of a Struct, Array, or List TLV container.
    ///
    /// NOTE: This method must be called only when the corresponding container has been opened
    /// using `start_struct`, `start_array`, or `start_list`, or else the generated TLV stream will be invalid.
    fn end_container(&mut self) -> Result<(), Error> {
        self.write(TLVControl::from(TLVTagType::Anonymous, TLVValueType::EndCnt).into_raw())
    }

    /// Write a tag and a TLV Null value to the TLV stream.
    fn null(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self._write_tagged_raw_data(tag, TLVValueType::Null, &[])
    }

    /// Write a tag and a TLV True or False value to the TLV stream.
    fn bool(&mut self, tag: &TLVTag, val: bool) -> Result<(), Error> {
        self._write_tagged_raw_data(
            tag,
            if val {
                TLVValueType::True
            } else {
                TLVValueType::False
            },
            &[],
        )
    }

    /// Write a tag and a raw, already-encoded TLV value represented as a byte slice.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn _write_tagged_raw_data(
        &mut self,
        tag: &TLVTag,
        value_type: TLVValueType,
        value_payload: &[u8],
    ) -> Result<(), Error> {
        self.write(TLVControl::from(tag.tag_type(), value_type).into_raw())?;

        match tag {
            TLVTag::Anonymous => Ok(()),
            TLVTag::Context(v) => self._write_raw_data(v.to_le_bytes()),
            TLVTag::CommonPrf16(v) | TLVTag::ImplPrf16(v) => self._write_raw_data(v.to_le_bytes()),
            TLVTag::CommonPrf32(v) | TLVTag::ImplPrf32(v) => self._write_raw_data(v.to_le_bytes()),
            TLVTag::FullQual48(v) => self._write_raw_data(v.to_le_bytes().into_iter().take(6)),
            TLVTag::FullQual64(v) => self._write_raw_data(v.to_le_bytes()),
        }?;

        self._write_raw_data(value_payload.into_iter().copied())
    }

    /// Append multiple raw bytes to the TLV stream.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn _write_raw_data<I>(&mut self, bytes: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        for byte in bytes {
            self.write(byte)?;
        }

        Ok(())
    }

    /// Append a single raw byte to the TLV stream.
    ///
    /// Note that this is a low-level method which is not expected to be called directly by users.
    fn write(&mut self, byte: u8) -> Result<(), Error>;
}

impl<T> TLVWrite for &mut T
where
    T: TLVWrite,
{
    fn write(&mut self, byte: u8) -> Result<(), Error> {
        (*self).write(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::{TLVWrite, TagType};
    use crate::utils::writebuf::WriteBuf;

    #[test]
    fn test_write_success() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWrite::new(&mut writebuf);

        tw.start_struct(TagType::Anonymous).unwrap();
        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        tw.u16(TagType::Anonymous, 0x1212).unwrap();
        tw.u16(TagType::Context(2), 0x1313).unwrap();
        tw.start_array(TagType::Context(3)).unwrap();
        tw.bool(TagType::Anonymous, true).unwrap();
        tw.end_container().unwrap();
        tw.end_container().unwrap();
        assert_eq!(
            buf,
            [21, 4, 12, 36, 1, 13, 5, 0x12, 0x012, 37, 2, 0x13, 0x13, 54, 3, 9, 24, 24, 0, 0]
        );
    }

    #[test]
    fn test_write_overflow() {
        let mut buf = [0; 6];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWrite::new(&mut writebuf);

        tw.u8(TagType::Anonymous, 12).unwrap();
        tw.u8(TagType::Context(1), 13).unwrap();
        if tw.u16(TagType::Anonymous, 12).is_ok() {
            panic!("This should have returned error")
        }
        if tw.u16(TagType::Context(2), 13).is_ok() {
            panic!("This should have returned error")
        }
        assert_eq!(buf, [4, 12, 36, 1, 13, 4]);
    }

    #[test]
    fn test_put_str8() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWrite::new(&mut writebuf);

        tw.u8(TagType::Context(1), 13).unwrap();
        tw.str8(TagType::Anonymous, &[10, 11, 12, 13, 14]).unwrap();
        tw.u16(TagType::Context(2), 0x1313).unwrap();
        tw.str8(TagType::Context(3), &[20, 21, 22]).unwrap();
        assert_eq!(
            buf,
            [36, 1, 13, 16, 5, 10, 11, 12, 13, 14, 37, 2, 0x13, 0x13, 48, 3, 3, 20, 21, 22]
        );
    }

    #[test]
    fn test_put_str16_as() {
        let mut buf = [0; 20];
        let mut writebuf = WriteBuf::new(&mut buf);
        let mut tw = TLVWrite::new(&mut writebuf);

        tw.u8(TagType::Context(1), 13).unwrap();
        tw.str8(TagType::Context(2), &[10, 11, 12, 13, 14]).unwrap();
        tw.str16_as(TagType::Context(3), |buf| {
            buf[0] = 10;
            buf[1] = 11;
            Ok(2)
        })
        .unwrap();
        tw.u8(TagType::Context(4), 13).unwrap();

        assert_eq!(
            buf,
            [36, 1, 13, 48, 2, 5, 10, 11, 12, 13, 14, 48, 3, 2, 10, 11, 36, 4, 13, 0]
        );
    }
}
