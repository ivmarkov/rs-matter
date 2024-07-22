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

pub trait BytesRead: Iterator<Item = Result<u8, Error>> {
    fn read(&mut self) -> Result<u8, Error> {
        let byte = self.next().ok_or(ErrorCode::InvalidData)??;

        Ok(byte)
    }

    fn read_all<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut buf = [0; N];

        for i in 0..N {
            buf[i] = self.read()?;
        }

        Ok(buf)
    }

    fn skip(&mut self, count: usize) -> Result<(), Error> {
        for _ in 0..count {
            self.read()?;
        }

        Ok(())
    }
}

impl<T> BytesRead for T where T: Iterator<Item = Result<u8, Error>> {}

pub trait BytesWrite {
    fn write(&mut self, byte: u8) -> Result<(), Error>;

    fn write_all<I>(&mut self, bytes: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = u8>,
    {
        for byte in bytes {
            self.write(byte)?;
        }

        Ok(())
    }
}

impl<T> BytesWrite for &mut T
where
    T: BytesWrite,
{
    fn write(&mut self, byte: u8) -> Result<(), Error> {
        (**self).write(byte)
    }
}

pub trait BytesSlice<'a>: BytesRead {
    fn read_slice(&mut self, len: Option<usize>) -> Result<&'a [u8], Error>;
}

impl<'a, T> BytesSlice<'a> for &mut T
where
    T: BytesSlice<'a>,
{
    fn read_slice(&mut self, len: Option<usize>) -> Result<&'a [u8], Error> {
        (**self).read_slice(len)
    }
}

pub struct SliceReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
        }
    }
}

impl<'a> Iterator for SliceReader<'a> {
    type Item = Result<u8, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset < self.data.len() {
            let byte = self.data[self.offset];
            self.offset += 1;

            Some(Ok(byte))
        } else {
            None
        }
    }
}

impl<'a> BytesSlice<'a> for SliceReader<'a> {
    fn read_slice(&mut self, len: Option<usize>) -> Result<&'a [u8], Error> {
        let len = len.unwrap_or(self.data.len() - self.offset);

        if self.offset + len > self.data.len() {
            return Err(ErrorCode::InvalidData.into());
        }

        let slice = &self.data[self.offset..self.offset + len];
        self.offset += len;

        Ok(slice)
    }
}
