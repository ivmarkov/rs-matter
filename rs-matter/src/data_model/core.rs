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

use embassy_time::Timer;
use portable_atomic::{AtomicU32, Ordering};

use super::objects::*;
use crate::{
    error::*,
    interaction_model::{
        core::{
            IMStatusCode, Interaction, InvStreamingResp, OpCode, ReportDataReq,
            ReportDataStreamingResp, WriteStreamingResp,
        },
        messages::msg::{
            InvReq, ReadReq, StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq,
        },
    },
    tlv::{get_root_node_struct, FromTLV},
    transport::exchange::{Exchange, ExchangeBuffers},
    utils::writebuf::WriteBuf,
};

static SUBS_ID: AtomicU32 = AtomicU32::new(1);

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

pub struct DataModel<T>(T);

impl<T> DataModel<T>
where
    T: DataModelHandler,
{
    pub fn new(handler: T) -> Self {
        Self(handler)
    }

    pub async fn handle(
        &self,
        mut exchange: Exchange<'_>,
        mut buffers: ExchangeBuffers<'_>,
    ) -> Result<(), Error> {
        let mut timeout_instant = None;

        let mut rb = WriteBuf::new(buffers.rx.get().await?);
        let mut tb = WriteBuf::new(buffers.tx.get().await?);

        loop {
            let meta = exchange.recv_into(&mut rb).await?;

            let interaction = Interaction::new(meta.opcode()?, rb.as_slice())?;

            tb.reset();

            match &interaction {
                Interaction::Read(req) => self.read(&mut exchange, req, &mut tb).await?,
                Interaction::Write(req) => {
                    self.write(&mut exchange, req, &mut tb, timeout_instant)
                        .await?
                }
                Interaction::Invoke(req) => {
                    self.invoke(&mut exchange, req, &mut tb, timeout_instant)
                        .await?
                }
                Interaction::Subscribe(req) => self.subscribe(&mut exchange, req, &mut tb).await?,
                Interaction::Timed(req) => {
                    timeout_instant = Some(self.timed(&mut exchange, req, &mut tb).await?)
                }
            }

            if !matches!(interaction, Interaction::Timed(_)) {
                break;
            }
        }

        Ok(())
    }

    async fn read(
        &self,
        exchange: &mut Exchange<'_>,
        req: &ReadReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        self.report_data(exchange, &ReportDataReq::Read(req), wb)
            .await
    }

    async fn report_data(
        &self,
        exchange: &mut Exchange<'_>,
        req: &ReportDataReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let metadata = self.0.lock().await;

        let mut resp = ReportDataStreamingResp::new(wb);

        resp.start(req)?;

        let accessor = exchange.accessor()?;
        let mut complete = true;

        'outer: for item in metadata.node().read(req, None, &accessor) {
            while !AttrDataEncoder::handle_read(&item, &self.0, &mut resp.writer()).await? {
                exchange
                    .send(OpCode::ReportData, resp.finish_chunk(&req)?)
                    .await?;

                if Self::recv_status(exchange).await? != IMStatusCode::Success {
                    complete = false;
                    break 'outer;
                }

                resp.start(&req)?;
            }
        }

        if complete {
            exchange.send(OpCode::ReportData, resp.finish(req)?).await?;
        }

        Ok(())
    }

    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        req: &WriteReq<'_>,
        wb: &mut WriteBuf<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        if timeout_instant
            .map(|timeout_instant| (exchange.matter.epoch)() > timeout_instant)
            .unwrap_or(false)
        {
            StatusResp::write(wb, IMStatusCode::Timeout)?;

            return exchange.send(OpCode::StatusResponse, wb.as_slice()).await;
        }

        let metadata = self.0.lock().await;

        let mut resp = WriteStreamingResp::new(wb);

        resp.start()?;

        let accessor = exchange.accessor()?;

        // The spec expects that a single write request like DeleteList + AddItem
        // should cause all ACLs of that fabric to be deleted and the new one to be added (Case 1).
        //
        // This is in conflict with the immediate-effect expectation of ACL: an ACL
        // write should instantaneously update the ACL so that immediate next WriteAttribute
        // *in the same WriteRequest* should see that effect (Case 2).
        //
        // As with the C++ SDK, here we do all the ACLs checks first, before any write begins.
        // Thus we support the Case1 by doing this. It does come at the cost of maintaining an
        // additional list of expanded write requests as we start processing those.
        let node = metadata.node();
        let write_attrs: heapless::Vec<_, MAX_WRITE_ATTRS_IN_ONE_TRANS> =
            node.write(&req, &accessor).collect();

        for item in write_attrs {
            AttrDataEncoder::handle_write(&item, &self.0, &mut resp.writer()).await?;
        }

        exchange.send(OpCode::WriteResponse, resp.finish()?).await
    }

    async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        req: &InvReq<'_>,
        wb: &mut WriteBuf<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        if timeout_instant
            .map(|timeout_instant| (exchange.matter.epoch)() > timeout_instant)
            .unwrap_or(false)
        {
            StatusResp::write(wb, IMStatusCode::Timeout)?;

            exchange.send(OpCode::StatusResponse, wb.as_slice()).await
        } else {
            let mut resp = InvStreamingResp::new(wb);

            if resp.timeout(req, timeout_instant)? {
                exchange.send(OpCode::StatusResponse, wb.as_slice()).await
            } else {
                resp.start(req)?;

                let accessor = exchange.accessor()?;

                let metadata = self.0.lock().await;

                let node = metadata.node();

                for item in node.invoke(&req, &accessor) {
                    CmdDataEncoder::handle(&item, &self.0, &mut resp.writer(), exchange).await?;
                }

                exchange
                    .send(OpCode::InvokeResponse, resp.finish(req)?)
                    .await
            }
        }
    }

    async fn subscribe(
        &self,
        exchange: &mut Exchange<'_>,
        req: &SubscribeReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        self.report_data(exchange, &ReportDataReq::Subscribe(&req), wb)
            .await?;

        if Self::recv_status(exchange).await? == IMStatusCode::Success {
            let subscription_id = SUBS_ID.fetch_add(1, Ordering::SeqCst);

            exchange
                .send(
                    OpCode::SubscribeResponse,
                    SubscribeResp::write(wb, subscription_id)?,
                )
                .await?;

            loop {
                Timer::after(embassy_time::Duration::from_secs(100)).await; // TODO

                self.report_data(exchange, &ReportDataReq::Subscribe(&req), wb)
                    .await?;
            }
        }

        Ok(())
    }

    async fn timed(
        &self,
        exchange: &mut Exchange<'_>,
        req: &TimedReq,
        wb: &mut WriteBuf<'_>,
    ) -> Result<Duration, Error> {
        let timeout_instant = req.timeout_instant(exchange.matter.epoch);

        StatusResp::write(wb, IMStatusCode::Success)?;

        exchange.send(OpCode::StatusResponse, wb.as_slice()).await?;

        Ok(timeout_instant)
    }

    async fn recv_status(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
        let rx = exchange.recv().await;

        let opcode: OpCode = rx.meta().opcode()?;

        if opcode == OpCode::StatusResponse {
            let resp = StatusResp::from_tlv(&get_root_node_struct(rx.payload())?)?;
            Ok(resp.status)
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }
}
