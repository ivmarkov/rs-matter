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

use crate::{error::Error, utils::writebuf::WriteBuf};

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

pub fn write(
    wb: &mut WriteBuf,
    general_code: GeneralCode,
    proto_id: u32,
    proto_code: u16,
    proto_data: Option<&[u8]>,
) -> Result<(), Error> {
    wb.le_u16(general_code as u16)?;
    wb.le_u32(proto_id)?;
    wb.le_u16(proto_code)?;
    if let Some(s) = proto_data {
        wb.copy_from_slice(s)?;
    }

    Ok(())
}
