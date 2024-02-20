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
    acl::Accessor,
    alloc,
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
    transport::exchange::Exchange,
    utils::writebuf::WriteBuf,
};

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

// TODO: For now...
static SUBS_ID: AtomicU32 = AtomicU32::new(1);

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
        exchange: &mut Exchange<'_>,
        rb: &mut WriteBuf<'_>,
        tb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let mut timeout = None;

        loop {
            let meta = exchange.recv_into(rb).await?;

            let interaction = Interaction::new(meta.opcode()?, rb.as_slice())?;

            match &interaction {
                Interaction::Read(req) => self.read(exchange, req, tb).await?,
                Interaction::Write(req) => self.write(exchange, req, tb).await?,
                Interaction::Invoke(req) => self.invoke(exchange, req, tb).await?,
                Interaction::Subscribe(req) => self.subscribe(exchange, req, tb).await?,
                Interaction::Timed(req) => timeout = Some(self.timed(exchange, req, tb).await?),
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
                    .send(&ReportDataStreamingResp::META, resp.finish_chunk(&req)?)
                    .await?;

                if Self::recv_status(exchange).await? != IMStatusCode::Success {
                    complete = false;
                    break 'outer;
                }

                resp.start(&req)?;
            }
        }

        if complete {
            exchange
                .send(&ReportDataStreamingResp::META, resp.finish(req)?)
                .await?;
        }

        Ok(())
    }

    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        req: &WriteReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
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

        exchange
            .send(&WriteStreamingResp::META, resp.finish()?)
            .await
    }

    async fn invoke(
        &self,
        exchange: &mut Exchange<'_>,
        req: &InvReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let resp = InvStreamingResp::new(wb);

        resp.start(timeout)?;

        let accessor = exchange.accessor()?;

        let metadata = self.0.lock().await;

        let node = metadata.node();

        for item in node.invoke(&req, &accessor) {
            CmdDataEncoder::handle(&item, &self.0, &mut resp.writer(), exchange).await?;
        }

        exchange
            .send(&InvStreamingResp::META, resp.finish(req)?)
            .await
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
                    &SubscribeResp::META,
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
        let timeout = req.timeout(exchange.matter.epoch);

        StatusResp::write(wb, IMStatusCode::Success)?;

        exchange.send(&StatusResp::META, wb).await?;

        Ok(timeout)
    }

    async fn recv_status(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
        let rx = exchange.get().await;

        let opcode: OpCode = rx.meta().opcode()?;
        rx.reset();

        if opcode == OpCode::StatusResponse {
            let resp = StatusResp::from_tlv(&get_root_node_struct(rx.payload())?)?;
            Ok(resp.status)
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }
}
