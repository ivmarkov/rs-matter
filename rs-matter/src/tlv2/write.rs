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

use super::{BytesWrite, TLVControl, TLVTag, TLVTagType, TLVValue, TLVValueType, TLV};

pub trait TLVWrite: BytesWrite {
    fn control(&mut self, control: TLVControl) -> Result<(), Error> {
        self.write(control.into_raw())
    }

    fn tag(&mut self, tag: &TLVTag, value_type: TLVValueType) -> Result<(), Error> {
        self.write(TLVControl::from(tag.tag_type(), value_type).into_raw())?;
        self._tag_payload(tag)
    }

    fn value(&mut self, value: &TLVValue) -> Result<(), Error> {
        self._value_size(value)?;
        self._value_payload(value)
    }

    fn _tagged_data(
        &mut self,
        tag: &TLVTag,
        value_type: TLVValueType,
        data: &[u8],
    ) -> Result<(), Error> {
        self.tag(tag, value_type)?;
        self.write_all(data.into_iter().copied())
    }

    fn _tag_payload(&mut self, tag: &TLVTag) -> Result<(), Error> {
        match tag {
            TLVTag::Anonymous => Ok(()),
            TLVTag::Context(v) => self.write_all(v.to_le_bytes()),
            TLVTag::CommonPrf16(v) | TLVTag::ImplPrf16(v) => self.write_all(v.to_le_bytes()),
            TLVTag::CommonPrf32(v) | TLVTag::ImplPrf32(v) => self.write_all(v.to_le_bytes()),
            TLVTag::FullQual48(v) => self.write_all(v.to_le_bytes().into_iter().take(6)),
            TLVTag::FullQual64(v) => self.write_all(v.to_le_bytes()),
        }
    }

    fn _value_size(&mut self, value: &TLVValue) -> Result<(), Error> {
        match value {
            TLVValue::Utf8l(a) | TLVValue::Str8l(a) => {
                self.write_all((a.len() as u8).to_le_bytes())
            }
            TLVValue::Utf16l(a) | TLVValue::Str16l(a) => {
                self.write_all((a.len() as u16).to_le_bytes())
            }
            TLVValue::Utf32l(a) | TLVValue::Str32l(a) => {
                self.write_all((a.len() as u32).to_le_bytes())
            }
            TLVValue::Utf64l(a) | TLVValue::Str64l(a) => {
                self.write_all((a.len() as u64).to_le_bytes())
            }
            _ => Ok(()),
        }
    }

    fn _value_payload(&mut self, value: &TLVValue) -> Result<(), Error> {
        match value {
            TLVValue::S8(a) => self.write_all(a.to_le_bytes()),
            TLVValue::S16(a) => self.write_all(a.to_le_bytes()),
            TLVValue::S32(a) => self.write_all(a.to_le_bytes()),
            TLVValue::S64(a) => self.write_all(a.to_le_bytes()),
            TLVValue::U8(a) => self.write_all(a.to_le_bytes()),
            TLVValue::U16(a) => self.write_all(a.to_le_bytes()),
            TLVValue::U32(a) => self.write_all(a.to_le_bytes()),
            TLVValue::U64(a) => self.write_all(a.to_le_bytes()),
            TLVValue::False => Ok(()),
            TLVValue::True => Ok(()),
            TLVValue::F32(a) => self.write_all(a.to_le_bytes()),
            TLVValue::F64(a) => self.write_all(a.to_le_bytes()),
            TLVValue::Utf8l(a)
            | TLVValue::Str8l(a)
            | TLVValue::Utf16l(a)
            | TLVValue::Str16l(a)
            | TLVValue::Utf32l(a)
            | TLVValue::Str32l(a)
            | TLVValue::Utf64l(a)
            | TLVValue::Str64l(a) => self.write_all(a.into_iter().copied()),
            TLVValue::Null => Ok(()),
            TLVValue::Struct => Ok(()),
            TLVValue::Array => Ok(()),
            TLVValue::List => Ok(()),
            TLVValue::EndCnt => Ok(()),
        }
    }

    fn tlv(&mut self, tlv: &TLV) -> Result<(), Error> {
        self.tag(&tlv.tag, tlv.value.value_type())?;
        self.value(&tlv.value)
    }

    fn i8(&mut self, tag: &TLVTag, data: i8) -> Result<(), Error> {
        self._tagged_data(tag, TLVValueType::S8, &data.to_le_bytes())
    }

    fn u8(&mut self, tag: &TLVTag, data: u8) -> Result<(), Error> {
        self._tagged_data(tag, TLVValueType::U8, &data.to_le_bytes())
    }

    fn i16(&mut self, tag: &TLVTag, data: i16) -> Result<(), Error> {
        if data >= i8::MIN as i16 && data <= i8::MAX as i16 {
            self.i8(tag, data as i8)
        } else {
            self._tagged_data(tag, TLVValueType::S16, &data.to_le_bytes())
        }
    }

    fn u16(&mut self, tag: &TLVTag, data: u16) -> Result<(), Error> {
        if data <= u8::MAX as u16 {
            self.u8(tag, data as u8)
        } else {
            self._tagged_data(tag, TLVValueType::U16, &data.to_le_bytes())
        }
    }

    fn i32(&mut self, tag: &TLVTag, data: i32) -> Result<(), Error> {
        if data >= i16::MIN as i32 && data <= i16::MAX as i32 {
            self.i16(tag, data as i16)
        } else {
            self._tagged_data(tag, TLVValueType::S32, &data.to_le_bytes())
        }
    }

    fn u32(&mut self, tag: &TLVTag, data: u32) -> Result<(), Error> {
        if data <= u16::MAX as u32 {
            self.u16(tag, data as u16)
        } else {
            self._tagged_data(tag, TLVValueType::U32, &data.to_le_bytes())
        }
    }

    fn i64(&mut self, tag: &TLVTag, data: i64) -> Result<(), Error> {
        if data >= i32::MIN as i64 && data <= i32::MAX as i64 {
            self.i32(tag, data as i32)
        } else {
            self._tagged_data(tag, TLVValueType::S64, &data.to_le_bytes())
        }
    }

    fn u64(&mut self, tag: &TLVTag, data: u64) -> Result<(), Error> {
        if data <= u32::MAX as u64 {
            self.u32(tag, data as u32)
        } else {
            self._tagged_data(tag, TLVValueType::U64, &data.to_le_bytes())
        }
    }

    fn stri<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self._tagged_data(tag, TLVValueType::Str8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self._tagged_data(tag, TLVValueType::Str16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self._tagged_data(tag, TLVValueType::Str32l, &(len as u32).to_le_bytes())?;
        } else {
            self._tagged_data(tag, TLVValueType::Str64l, &(len as u64).to_le_bytes())?;
        }

        self.write_all(data)
    }

    fn str(&mut self, tag: &TLVTag, data: &[u8]) -> Result<(), Error> {
        self.stri(tag, data.len(), data.into_iter().copied())
    }

    fn utf8i<I>(&mut self, tag: &TLVTag, len: usize, data: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        if len <= u8::MAX as usize {
            self._tagged_data(tag, TLVValueType::Utf8l, &(len as u8).to_le_bytes())?;
        } else if len <= u16::MAX as usize {
            self._tagged_data(tag, TLVValueType::Utf16l, &(len as u16).to_le_bytes())?;
        } else if len <= u32::MAX as usize {
            self._tagged_data(tag, TLVValueType::Utf32l, &(len as u32).to_le_bytes())?;
        } else {
            self._tagged_data(tag, TLVValueType::Utf64l, &(len as u64).to_le_bytes())?;
        }

        self.write_all(data)
    }

    fn utf8(&mut self, tag: &TLVTag, data: &[u8]) -> Result<(), Error> {
        self.utf8i(tag, data.len(), data.into_iter().copied())
    }

    fn start_struct(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.tag(tag, TLVValueType::Struct)
    }

    fn start_array(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.tag(tag, TLVValueType::Array)
    }

    fn start_list(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.tag(tag, TLVValueType::List)
    }

    fn end_container(&mut self) -> Result<(), Error> {
        self.control(TLVControl::from(
            TLVTagType::Anonymous,
            TLVValueType::EndCnt,
        ))
    }

    fn null(&mut self, tag: &TLVTag) -> Result<(), Error> {
        self.tag(tag, TLVValueType::Null)
    }

    fn bool(&mut self, tag: &TLVTag, val: bool) -> Result<(), Error> {
        self.tag(
            tag,
            if val {
                TLVValueType::True
            } else {
                TLVValueType::False
            },
        )
    }
}

impl<T> TLVWrite for T where T: BytesWrite {}

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
