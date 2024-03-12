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

use core::cell::Cell;
use core::mem::MaybeUninit;
use core::time::Duration;

use log::{info, warn};

use crate::{error::*, Matter};

use crate::interaction_model::core::{
    IMStatusCode, Interaction, InvStreamingResp, OpCode, ReportDataReq, ReportDataStreamingResp,
    WriteStreamingResp, PROTO_ID_INTERACTION_MODEL,
};
use crate::interaction_model::messages::msg::{
    InvReq, ReadReq, StatusResp, SubscribeReq, SubscribeResp, TimedReq, WriteReq,
};
use crate::respond::ExchangeHandler;
use crate::tlv::{get_root_node_struct, FromTLV};
use crate::transport::exchange::Exchange;
use crate::transport::packet::{PacketHdr, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use crate::utils::writebuf::WriteBuf;

use super::objects::*;
use super::subscriptions::Subscriptions;

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

/// An `ExchangeHandler` implementation capable of handling responder exchanges for the Interaction Model protocol.
/// The implementation needs a `DataModelHandler` instance to interact with the underlying clusters of the data model.
pub struct DataModel<const N: usize, T> {
    handler: T,
    subscriptions: Subscriptions<N>,
}

impl<const N: usize, T> DataModel<N, T>
where
    T: DataModelHandler,
{
    /// Create the handler.
    pub const fn new(handler: T) -> Self {
        Self {
            handler,
            subscriptions: Subscriptions::new(),
        }
    }

    /// A utility for getting a reference to the subscriptions utility owned by this data model handler.
    ///
    /// Necessary so that application code can notify the data model handler of data changes.
    pub fn subscriptions(&self) -> &Subscriptions<N> {
        &self.subscriptions
    }

    /// Run the subscriptions' reporting loop for all subscriptions created by this handler when responding to exchanges.
    ///
    /// All exchanges initiated when reporting on subscriptions will be initiated on the provided `Matter` stack.
    /// Therefore, the provided `Matter` stack should be the **same** one on which the responding exchanges are being handled by this data model.
    pub async fn run_subscriptions(&self, matter: &Matter<'_>) -> Result<(), Error> {
        self.subscriptions.run(&self.handler, matter).await
    }

    /// Answer a responding exchange using the `DataModelHandler` instance wrapped by this exchange handler.
    pub async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let mut rb = Box::new(MaybeUninit::<[u8; MAX_RX_BUF_SIZE]>::uninit());
        let mut tb = Box::new(MaybeUninit::<
            [u8; MAX_TX_BUF_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE],
        >::uninit());

        let rb = unsafe { rb.assume_init_mut() };
        let tb = unsafe { tb.assume_init_mut() };

        self.handle_with(exchange, &mut WriteBuf::new(rb), &mut WriteBuf::new(tb))
            .await
    }

    pub async fn handle_with(
        &self,
        exchange: &mut Exchange<'_>,
        rb: &mut WriteBuf<'_>,
        tb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let mut timeout_instant = None;
        let mut repeat = true;

        while repeat {
            let meta = exchange.rx().await?.meta();

            if meta.proto_id != PROTO_ID_INTERACTION_MODEL {
                Err(ErrorCode::InvalidProto)?;
            }

            exchange.recv_into(rb).await?;

            let interaction = Interaction::new(meta.opcode()?, rb.as_slice())?;

            repeat = matches!(interaction, Interaction::Timed(_))
                || matches!(
                    interaction,
                    Interaction::Write(WriteReq {
                        more_chunked: Some(true),
                        ..
                    })
                );

            tb.reset();

            match &interaction {
                Interaction::Read(req) => self.read(exchange, req, tb).await?,
                Interaction::Write(req) => self.write(exchange, req, tb, timeout_instant).await?,
                Interaction::Invoke(req) => self.invoke(exchange, req, tb, timeout_instant).await?,
                Interaction::Subscribe(req) => {
                    self.subscribe(exchange, req, rb.as_slice(), tb).await?
                }
                Interaction::Timed(req) => {
                    timeout_instant = Some(self.timed(exchange, req, tb).await?)
                }
            }
        }

        exchange.acknowledge().await?;
        exchange.matter().notify_changed();

        Ok(())
    }

    async fn read(
        &self,
        exchange: &mut Exchange<'_>,
        req: &ReadReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        DataModel::<0, &T>::report_data(
            &self.handler,
            exchange,
            &ReportDataReq::Read(req),
            None,
            wb,
            true,
        )
        .await?;

        Ok(())
    }

    pub(crate) async fn report_data(
        handler: T,
        exchange: &mut Exchange<'_>,
        req: &ReportDataReq<'_>,
        subscription_id: Option<u32>,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<bool, Error> {
        let metadata = handler.lock().await;

        let mut resp = ReportDataStreamingResp::new(wb);

        resp.start(req, subscription_id)?;

        let accessor = exchange.accessor()?;

        for item in metadata.node().read(req, None, &accessor) {
            while !AttrDataEncoder::handle_read(&item, &handler, &mut resp.writer()).await? {
                exchange
                    .send(OpCode::ReportData, resp.finish_chunk(req)?)
                    .await?;

                if !Self::recv_confirm(exchange).await? {
                    return Ok(false);
                }

                resp.start(req, subscription_id)?;
            }
        }

        exchange
            .send(OpCode::ReportData, resp.finish(req, suppress_resp)?)
            .await?;

        if !suppress_resp {
            Self::recv_confirm(exchange).await
        } else {
            Ok(true)
        }
    }

    async fn write(
        &self,
        exchange: &mut Exchange<'_>,
        req: &WriteReq<'_>,
        wb: &mut WriteBuf<'_>,
        timeout_instant: Option<Duration>,
    ) -> Result<(), Error> {
        if timeout_instant
            .map(|timeout_instant| (exchange.matter().epoch)() > timeout_instant)
            .unwrap_or(false)
        {
            StatusResp::write(wb, IMStatusCode::Timeout)?;

            return exchange.send(OpCode::StatusResponse, wb.as_slice()).await;
        }

        let metadata = self.handler.lock().await;

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
            node.write(req, &accessor).collect();

        for item in write_attrs {
            AttrDataEncoder::handle_write(&item, &self.handler, &mut resp.writer()).await?;
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
            .map(|timeout_instant| (exchange.matter().epoch)() > timeout_instant)
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

                let metadata = self.handler.lock().await;

                let node = metadata.node();

                for item in node.invoke(req, &accessor) {
                    CmdDataEncoder::handle(&item, &self.handler, &mut resp.writer(), exchange)
                        .await?;
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
        rb: &[u8],
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let node_id = exchange
            .with_session(|sess| sess.get_peer_node_id().ok_or(ErrorCode::Invalid.into()))?;

        if !req.keep_subs {
            self.subscriptions.remove(node_id, None);
            info!("All subscriptions for node {node_id:x} removed");
        }

        let subscribed = Cell::new(false);

        let max_int_secs = core::cmp::max(req.max_int_ceil, 40); // Say we need at least 4 secs for potential latencies

        if let Some(id) = self.subscriptions.add(node_id, rb, max_int_secs) {
            let _guard = scopeguard::guard((), |_| {
                if !subscribed.get() {
                    self.subscriptions.remove(node_id, Some(id));
                }
            });

            info!(
                "New subscription {node_id:x}::{id}; reporting interval: {}s - {max_int_secs}s",
                req.min_int_floor
            );

            if DataModel::<0, &T>::report_data(
                &self.handler,
                exchange,
                &ReportDataReq::Subscribe(req),
                Some(id),
                wb,
                false,
            )
            .await?
            {
                exchange
                    .send_with(|_, wb| {
                        SubscribeResp::write(wb, id, max_int_secs)?;
                        Ok(Some(OpCode::SubscribeResponse.into()))
                    })
                    .await?;

                subscribed.set(true);
            } else {
                info!("Subscription {node_id:x}::{id} removed during priming");
            }
        } else {
            // No place for this subscription, return resource exhausted
            exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::ResourceExhausted)?;

                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;
        }

        Ok(())
    }

    async fn timed(
        &self,
        exchange: &mut Exchange<'_>,
        req: &TimedReq,
        wb: &mut WriteBuf<'_>,
    ) -> Result<Duration, Error> {
        let timeout_instant = req.timeout_instant(exchange.matter().epoch);

        StatusResp::write(wb, IMStatusCode::Success)?;

        exchange.send(OpCode::StatusResponse, wb.as_slice()).await?;

        Ok(timeout_instant)
    }

    async fn recv_confirm(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
        let rx = exchange.recv().await?;

        let opcode: OpCode = rx.meta().opcode()?;

        if opcode == OpCode::StatusResponse {
            let resp = StatusResp::from_tlv(&get_root_node_struct(rx.payload())?)?;

            if resp.status == IMStatusCode::Success {
                Ok(true)
            } else {
                warn!(
                    "Got status response {:?}, aborting interaction",
                    resp.status
                );

                drop(rx);
                exchange.acknowledge().await?;

                Ok(false)
            }
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }
}

impl<const N: usize, T> ExchangeHandler for DataModel<N, T>
where
    T: DataModelHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        DataModel::handle(self, exchange).await
    }
}
