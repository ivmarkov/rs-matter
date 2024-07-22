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

//! TLV support for `bitflags!`.
//! Bitflags are serialized and deserialized as TLV enumerations.

/// Implements to/from TLV for the given enumeration that was
/// created using `bitflags!`
///
/// NOTE:
///   - bitflgs are generally unrestricted. The provided implementations
///     do NOT attempt to validate flags for validity and the entire
///     range of flags will be marshalled (including unknown flags)
#[macro_export]
macro_rules! bitflags_tlv {
    ($enum_name:ident, $type:ident) => {
        impl $crate::tlv2::FromTLVOwned for $enum_name {
            fn from_tlv_owned<I>(
                value_type: $crate::tlv2::TLVValueType,
                mut read: I,
            ) -> Result<Self, Error>
            where
                I: $crate::tlv2::BytesRead,
            {
                Ok(Self::from_bits_retain($crate::tlv2::TLVRead::$type(
                    &mut read, value_type,
                )?))
            }
        }

        impl<'a> $crate::tlv2::FromTLV<'a> for $enum_name {
            fn from_tlv<I>(
                value_type: $crate::tlv2::TLVValueType,
                mut read: I,
            ) -> Result<Self, Error>
            where
                I: $crate::tlv2::BytesSlice<'a>,
            {
                Ok(Self::from_bits_retain($crate::tlv2::TLVRead::$type(
                    &mut read, value_type,
                )?))
            }
        }

        impl $crate::tlv2::ToTLV for $enum_name {
            fn to_tlv<O>(&self, tag: &$crate::tlv2::TLVTag, mut write: O) -> Result<(), Error>
            where
                O: $crate::tlv2::BytesWrite,
            {
                $crate::tlv2::TLVWrite::$type(&mut write, tag, self.bits())
            }

            fn to_tlv_iter(&self, tag: crate::tlv2::TLVTag) -> impl Iterator<Item = u8> {
                $crate::tlv2::ToTLVIter::$type(core::iter::empty(), tag, self.bits())
            }

            fn into_tlv_iter(self, tag: crate::tlv2::TLVTag) -> impl Iterator<Item = u8> {
                $crate::tlv2::ToTLVIter::$type(core::iter::empty(), tag, self.bits())
            }
        }
    };
}
