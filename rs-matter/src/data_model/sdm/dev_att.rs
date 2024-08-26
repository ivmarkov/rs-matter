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

use crate::error::{Error, ErrorCode};

/// Device Attestation Data Type
pub enum DataType {
    /// Certificate Declaration
    CertDeclaration,
    /// Product Attestation Intermediary Certificate
    PAI,
    /// Device Attestation Certificate
    DAC,
    /// Device Attestation Certificate - Public Key
    DACPubKey,
    /// Device Attestation Certificate - Private Key
    DACPrivKey,
}

/// The Device Attestation Data Fetcher Trait
///
/// Objects that implement this trait allow the Matter subsystem to query the object
/// for the Device Attestation data that is programmed in the Matter device.
pub trait DevAttDataFetcher {
    /// Get the data in the provided buffer
    fn get_devatt_data(&self, data_type: DataType, buf: &mut [u8]) -> Result<usize, Error> {
        let mut len = 0;

        self.with_devatt_data(data_type, &mut |data| {
            if data.len() > buf.len() {
                Err(ErrorCode::NoSpace)?;
            }

            buf[..data.len()].copy_from_slice(data);

            len = data.len();

            Ok(())
        })?;

        Ok(len)
    }

    /// Get the data in the provided callback
    /// The type of data that can be queried is defined in the [DataType] enum.
    fn with_devatt_data(
        &self,
        data_type: DataType,
        f: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error>;
}

impl<T> DevAttDataFetcher for &T
where
    T: DevAttDataFetcher,
{
    fn get_devatt_data(&self, data_type: DataType, buf: &mut [u8]) -> Result<usize, Error> {
        (*self).get_devatt_data(data_type, buf)
    }

    fn with_devatt_data(
        &self,
        data_type: DataType,
        f: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        (*self).with_devatt_data(data_type, f)
    }
}
