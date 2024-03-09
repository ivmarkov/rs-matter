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

use core::time::Duration;

use crate::{
    error::*,
    tlv::{get_root_node_struct, FromTLV, TLVArray, TLVElement, TLVWriter, TagType, ToTLV},
    transport::exchange::ExchangeMeta,
    utils::{epoch::Epoch, writebuf::WriteBuf},
};
use log::error;
use num::{self, FromPrimitive};
use num_derive::FromPrimitive;

use super::messages::msg::{
    self, InvReq, ReadReq, StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq,
};
use super::messages::{
    ib::{AttrPath, DataVersionFilter},
    msg::ReportDataTag,
};

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use owo_colors::OwoColorize;
        info! {"{} {}", "Handling command".cyan(), $e.cyan()}
    }};
}

#[derive(FromPrimitive, Debug, Clone, Copy, PartialEq)]
pub enum IMStatusCode {
    Success = 0,
    Failure = 1,
    InvalidSubscription = 0x7D,
    UnsupportedAccess = 0x7E,
    UnsupportedEndpoint = 0x7F,
    InvalidAction = 0x80,
    UnsupportedCommand = 0x81,
    InvalidCommand = 0x85,
    UnsupportedAttribute = 0x86,
    ConstraintError = 0x87,
    UnsupportedWrite = 0x88,
    ResourceExhausted = 0x89,
    NotFound = 0x8b,
    UnreportableAttribute = 0x8c,
    InvalidDataType = 0x8d,
    UnsupportedRead = 0x8f,
    DataVersionMismatch = 0x92,
    Timeout = 0x94,
    Busy = 0x9c,
    UnsupportedCluster = 0xc3,
    NoUpstreamSubscription = 0xc5,
    NeedsTimedInteraction = 0xc6,
    UnsupportedEvent = 0xc7,
    PathsExhausted = 0xc8,
    TimedRequestMisMatch = 0xc9,
    FailSafeRequired = 0xca,
}

impl From<ErrorCode> for IMStatusCode {
    fn from(e: ErrorCode) -> Self {
        match e {
            ErrorCode::EndpointNotFound => IMStatusCode::UnsupportedEndpoint,
            ErrorCode::ClusterNotFound => IMStatusCode::UnsupportedCluster,
            ErrorCode::AttributeNotFound => IMStatusCode::UnsupportedAttribute,
            ErrorCode::CommandNotFound => IMStatusCode::UnsupportedCommand,
            ErrorCode::InvalidAction => IMStatusCode::InvalidAction,
            ErrorCode::InvalidCommand => IMStatusCode::InvalidCommand,
            ErrorCode::UnsupportedAccess => IMStatusCode::UnsupportedAccess,
            ErrorCode::Busy => IMStatusCode::Busy,
            ErrorCode::DataVersionMismatch => IMStatusCode::DataVersionMismatch,
            ErrorCode::ResourceExhausted => IMStatusCode::ResourceExhausted,
            _ => IMStatusCode::Failure,
        }
    }
}

impl From<Error> for IMStatusCode {
    fn from(value: Error) -> Self {
        Self::from(value.code())
    }
}

impl FromTLV<'_> for IMStatusCode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error> {
        FromPrimitive::from_u16(t.u16()?).ok_or_else(|| ErrorCode::Invalid.into())
    }
}

impl ToTLV for IMStatusCode {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        tw.u16(tag_type, *self as u16)
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq)]
pub enum OpCode {
    Reserved = 0,
    StatusResponse = 1,
    ReadRequest = 2,
    SubscribeRequest = 3,
    SubscribeResponse = 4,
    ReportData = 5,
    WriteRequest = 6,
    WriteResponse = 7,
    InvokeRequest = 8,
    InvokeResponse = 9,
    TimedRequest = 10,
}

impl OpCode {
    pub fn meta(&self) -> ExchangeMeta {
        ExchangeMeta {
            proto_id: PROTO_ID_INTERACTION_MODEL,
            proto_opcode: *self as u8,
            reliable: true,
        }
    }

    pub fn is_tlv(&self) -> bool {
        !matches!(self, Self::Reserved)
    }
}

impl From<OpCode> for ExchangeMeta {
    fn from(opcode: OpCode) -> Self {
        opcode.meta()
    }
}

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_INTERACTION_MODEL: u16 = 0x01;

/// A wrapper enum for `ReadReq` and `SubscribeReq` that allows downstream code to
/// treat the two in a unified manner with regards to `OpCode::ReportDataResp` type responses.
pub enum ReportDataReq<'a> {
    Read(&'a ReadReq<'a>),
    Subscribe(&'a SubscribeReq<'a>),
}

impl<'a> ReportDataReq<'a> {
    pub fn attr_requests(&self) -> &Option<TLVArray<'a, AttrPath>> {
        match self {
            ReportDataReq::Read(req) => &req.attr_requests,
            ReportDataReq::Subscribe(req) => &req.attr_requests,
        }
    }

    pub fn dataver_filters(&self) -> Option<&TLVArray<'_, DataVersionFilter>> {
        match self {
            ReportDataReq::Read(req) => req.dataver_filters.as_ref(),
            ReportDataReq::Subscribe(req) => req.dataver_filters.as_ref(),
        }
    }

    pub fn fabric_filtered(&self) -> bool {
        match self {
            ReportDataReq::Read(req) => req.fabric_filtered,
            ReportDataReq::Subscribe(req) => req.fabric_filtered,
        }
    }
}

/// A streaming equivalent of `ReportDataResp` that provides means for constructing large responses
/// in an incremental fashion, with potential `await`s which the response is being constructed.
pub struct ReportDataStreamingResp<'a, 'b>(&'a mut WriteBuf<'b>);

impl<'a, 'b> ReportDataStreamingResp<'a, 'b> {
    // This is the amount of space we reserve for other things to be attached towards
    // the end of long reads.
    const LONG_READS_TLV_RESERVE_SIZE: usize = 24;

    pub fn new(wb: &'a mut WriteBuf<'b>) -> Self {
        Self(wb)
    }

    pub fn start(
        &mut self,
        req: &ReportDataReq,
        subscription_id: Option<u32>,
    ) -> Result<(), Error> {
        self.0.reset();

        let mut tw = self.reserve_long_read_space()?;

        tw.start_struct(TagType::Anonymous)?;

        if let Some(subscription_id) = subscription_id {
            assert!(matches!(req, ReportDataReq::Subscribe(_)));
            tw.u32(
                TagType::Context(ReportDataTag::SubscriptionId as u8),
                subscription_id,
            )?;
        } else {
            assert!(matches!(req, ReportDataReq::Read(_)));
        }

        let requests = req.attr_requests().is_some();
        if requests {
            tw.start_array(TagType::Context(ReportDataTag::AttributeReports as u8))?;
        }

        Ok(())
    }

    pub fn writer(&mut self) -> TLVWriter<'_, 'b> {
        TLVWriter::new(self.0)
    }

    pub fn finish_chunk(&mut self, req: &ReportDataReq) -> Result<&[u8], Error> {
        self.complete(req, true, false)
    }

    pub fn finish(&mut self, req: &ReportDataReq, suppress_resp: bool) -> Result<&[u8], Error> {
        self.complete(req, false, suppress_resp)
    }

    fn complete(
        &mut self,
        req: &ReportDataReq,
        more_chunks: bool,
        suppress_resp: bool,
    ) -> Result<&[u8], Error> {
        let mut tw = self.restore_long_read_space()?;

        let requests = req.attr_requests().is_some();
        if requests {
            tw.end_container()?;
        }

        if more_chunks {
            tw.bool(TagType::Context(ReportDataTag::MoreChunkedMsgs as u8), true)?;
        }

        tw.bool(
            TagType::Context(ReportDataTag::SupressResponse as u8),
            suppress_resp,
        )?;

        tw.end_container()?;

        Ok(self.0.as_slice())
    }

    fn reserve_long_read_space(&mut self) -> Result<TLVWriter<'_, 'b>, Error> {
        self.0.shrink(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        Ok(TLVWriter::new(self.0))
    }

    fn restore_long_read_space(&mut self) -> Result<TLVWriter<'_, 'b>, Error> {
        self.0.expand(Self::LONG_READS_TLV_RESERVE_SIZE)?;

        Ok(TLVWriter::new(self.0))
    }
}

/// A streaming equivalent of `WriteResp` that provides means for constructing large responses
/// in an incremental fashion, with potential `await`s which the response is being constructed.
pub struct WriteStreamingResp<'a, 'b>(&'a mut WriteBuf<'b>);

impl<'a, 'b> WriteStreamingResp<'a, 'b> {
    pub fn new(wb: &'a mut WriteBuf<'b>) -> Self {
        Self(wb)
    }

    pub fn start(&mut self) -> Result<(), Error> {
        self.0.reset();

        let mut tw = self.writer();

        tw.start_struct(TagType::Anonymous)?;
        tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;

        Ok(())
    }

    pub fn writer(&mut self) -> TLVWriter<'_, 'b> {
        TLVWriter::new(self.0)
    }

    pub fn finish(&mut self) -> Result<&[u8], Error> {
        let mut tw = self.writer();

        tw.end_container()?;
        tw.end_container()?;

        Ok(self.0.as_slice())
    }
}

/// A streaming equivalent of `InvResp` that provides means for constructing large responses
/// in an incremental fashion, with potential `await`s which the response is being constructed.
pub struct InvStreamingResp<'a, 'b>(&'a mut WriteBuf<'b>);

impl<'a, 'b> InvStreamingResp<'a, 'b> {
    pub fn new(wb: &'a mut WriteBuf<'b>) -> Self {
        Self(wb)
    }

    pub fn timeout(&mut self, req: &InvReq, timeout: Option<Duration>) -> Result<bool, Error> {
        let timed_tx = timeout.map(|_| true);
        let timed_request = req.timed_request.filter(|a| *a);

        // Either both should be None, or both should be Some(true)
        if timed_tx != timed_request {
            StatusResp::write(self.0, IMStatusCode::TimedRequestMisMatch)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn start(&mut self, req: &InvReq) -> Result<(), Error> {
        self.0.reset();

        let mut tw = self.writer();

        tw.start_struct(TagType::Anonymous)?;

        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        tw.bool(
            TagType::Context(msg::InvRespTag::SupressResponse as u8),
            false,
        )?;

        if req.inv_requests.is_some() {
            tw.start_array(TagType::Context(msg::InvRespTag::InvokeResponses as u8))?;
        }

        Ok(())
    }

    pub fn writer(&mut self) -> TLVWriter<'_, 'b> {
        TLVWriter::new(self.0)
    }

    pub fn finish(&mut self, req: &InvReq) -> Result<&[u8], Error> {
        let mut tw = self.writer();

        if req.inv_requests.is_some() {
            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(self.0.as_slice())
    }
}

impl StatusResp {
    pub fn write(wb: &mut WriteBuf, status: IMStatusCode) -> Result<(), Error> {
        let mut tw = TLVWriter::new(wb);

        let status = Self { status };
        status.to_tlv(&mut tw, TagType::Anonymous)
    }
}

impl TimedReq {
    pub fn timeout_instant(&self, epoch: Epoch) -> Duration {
        epoch()
            .checked_add(Duration::from_millis(self.timeout as _))
            .unwrap()
    }
}

impl SubscribeResp {
    pub fn write<'a>(
        wb: &'a mut WriteBuf,
        subscription_id: u32,
        max_int: u16,
    ) -> Result<&'a [u8], Error> {
        let mut tw = TLVWriter::new(wb);

        let resp = Self::new(subscription_id, max_int);
        resp.to_tlv(&mut tw, TagType::Anonymous)?;

        Ok(wb.as_slice())
    }
}

/// A wrapper enum for all possible interaction model requests.
pub enum Interaction<'a> {
    Read(ReadReq<'a>),
    Write(WriteReq<'a>),
    Invoke(InvReq<'a>),
    Subscribe(SubscribeReq<'a>),
    Timed(TimedReq),
}

impl<'a> Interaction<'a> {
    #[inline(always)]
    pub fn new(opcode: OpCode, rx_data: &'a [u8]) -> Result<Self, Error> {
        match opcode {
            OpCode::ReadRequest => {
                let req = ReadReq::from_tlv(&get_root_node_struct(rx_data)?)?;

                Ok(Self::Read(req))
            }
            OpCode::WriteRequest => {
                let req = WriteReq::from_tlv(&get_root_node_struct(rx_data)?)?;

                Ok(Self::Write(req))
            }
            OpCode::InvokeRequest => {
                let req = InvReq::from_tlv(&get_root_node_struct(rx_data)?)?;

                Ok(Self::Invoke(req))
            }
            OpCode::SubscribeRequest => {
                let req = SubscribeReq::from_tlv(&get_root_node_struct(rx_data)?)?;

                Ok(Self::Subscribe(req))
            }
            OpCode::TimedRequest => {
                let req = TimedReq::from_tlv(&get_root_node_struct(rx_data)?)?;

                Ok(Self::Timed(req))
            }
            _ => {
                error!("Opcode not handled: {:?}", opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }

    pub fn timed_out(epoch: Epoch, timeout: Option<Duration>) -> bool {
        timeout.map(|timeout| epoch() > timeout).unwrap_or(false)
    }
}
