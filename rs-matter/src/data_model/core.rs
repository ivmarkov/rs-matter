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

use embassy_futures::select::{select, Either};
use embassy_time::{Instant, Timer};
use log::{info, warn};
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
    transport::exchange::Exchange,
    utils::{notification2::Notification2, writebuf::WriteBuf},
};

struct Subscription {
    node_id: u64,
    id: u32,
    data_changed: bool,
}

pub struct Subscriptions {
    next_subscription_id: AtomicU32,
    notification: Notification2<heapless::Vec<Subscription, MAX_SUBSCRIPTIONS>>,
}

impl Subscriptions {
    pub const fn new() -> Self {
        Self {
            next_subscription_id: AtomicU32::new(0),
            notification: Notification2::new(heapless::Vec::new()),
        }
    }

    pub fn notify_changed(&self) {
        self.notification.modify(|subs| {
            for sub in subs {
                sub.data_changed = true;
            }
        });
    }

    pub(crate) fn next_subscription_id(&self) -> u32 {
        self.next_subscription_id.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn add(&self, node_id: u64, subscription_id: u32) -> bool {
        self.notification.modify(|subs| {
            subs.push(Subscription {
                node_id,
                id: subscription_id,
                data_changed: false,
            })
            .map(|_| true)
            .unwrap_or(false)
        })
    }

    pub(crate) fn remove_all(&self, node_id: u64) {
        self.notification.modify(|subs| {
            while let Some(index) = subs.iter().position(|sub| sub.node_id == node_id) {
                subs.swap_remove(index);
            }
        });
    }

    pub(crate) fn remove(&self, node_id: u64, subscription_id: u32) {
        self.notification.modify(|subs| {
            if let Some(index) = subs
                .iter()
                .position(|sub| sub.node_id == node_id && sub.id == subscription_id)
            {
                subs.swap_remove(index);
            }
        });
    }

    pub(crate) async fn wait_removed(&self, node_id: u64, subscription_id: u32) -> bool {
        self.notification
            .wait(|subs| {
                if let Some(sub) = subs
                    .iter_mut()
                    .find(|sub| sub.node_id == node_id && sub.id == subscription_id)
                {
                    if sub.data_changed {
                        sub.data_changed = false;
                        Some(false)
                    } else {
                        None
                    }
                } else {
                    Some(true)
                }
            })
            .await
    }
}

/// The Maximum number of expanded writer request per transaction
///
/// The write requests are first wildcard-expanded, and these many number of
/// write requests per-transaction will be supported.
const MAX_WRITE_ATTRS_IN_ONE_TRANS: usize = 7;

const MAX_SUBSCRIPTIONS: usize = 8;

pub struct DataModel<'a, T> {
    handler: T,
    subscriptions: &'a Subscriptions,
}

impl<'a, T> DataModel<'a, T>
where
    T: DataModelHandler,
{
    pub const fn new(handler: T, subscriptions: &'a Subscriptions) -> Self {
        Self {
            handler,
            subscriptions,
        }
    }

    pub async fn handle(
        &self,
        mut exchange: Exchange<'_>,
        rb: &mut WriteBuf<'_>,
        tb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let mut timeout_instant = None;

        loop {
            let meta = exchange.recv_into(rb).await?;

            let interaction = Interaction::new(meta.opcode()?, rb.as_slice())?;

            tb.reset();

            match &interaction {
                Interaction::Read(req) => self.read(&mut exchange, req, tb).await?,
                Interaction::Write(req) => {
                    self.write(&mut exchange, req, tb, timeout_instant).await?
                }
                Interaction::Invoke(req) => {
                    self.invoke(&mut exchange, req, tb, timeout_instant).await?
                }
                Interaction::Subscribe(req) => self.subscribe(&mut exchange, req, tb).await?,
                Interaction::Timed(req) => {
                    timeout_instant = Some(self.timed(&mut exchange, req, tb).await?)
                }
            }

            if !matches!(interaction, Interaction::Timed(_))
                && !matches!(
                    interaction,
                    Interaction::Write(WriteReq {
                        more_chunked: Some(true),
                        ..
                    })
                )
            {
                break;
            }
        }

        exchange.matter().notify_changed();

        exchange.close().await
    }

    async fn read(
        &self,
        exchange: &mut Exchange<'_>,
        req: &ReadReq<'_>,
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        self.report_data(exchange, &ReportDataReq::Read(req), None, wb, true)
            .await?;

        Ok(())
    }

    async fn report_data(
        &self,
        exchange: &mut Exchange<'_>,
        req: &ReportDataReq<'_>,
        subscription_id: Option<u32>,
        wb: &mut WriteBuf<'_>,
        suppress_resp: bool,
    ) -> Result<bool, Error> {
        let metadata = self.handler.lock().await;

        let mut resp = ReportDataStreamingResp::new(wb);

        resp.start(req, subscription_id)?;

        let accessor = exchange.accessor()?;

        for item in metadata.node().read(req, None, &accessor) {
            while !AttrDataEncoder::handle_read(&item, &self.handler, &mut resp.writer()).await? {
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
        wb: &mut WriteBuf<'_>,
    ) -> Result<(), Error> {
        let mut reported_at = Instant::now();

        let subscription_id = self.subscriptions.next_subscription_id();
        let node_id = exchange
            .with_session(|sess| sess.get_peer_node_id().ok_or(ErrorCode::Invalid.into()))?;

        if !req.keep_subs {
            self.subscriptions.remove_all(node_id);
            info!("All subscriptions for node {node_id:x} removed");
        }

        if self.subscriptions.add(node_id, subscription_id) {
            info!("Subscription {node_id:x}::{subscription_id} added");

            let _sub_remove_guard = scopeguard::guard((), |_| {
                self.subscriptions.remove(node_id, subscription_id);
                info!("Subscription {node_id:x}::{subscription_id} removed");
            });

            let mut subscribed = self
                .report_data(
                    exchange,
                    &ReportDataReq::Subscribe(req),
                    Some(subscription_id),
                    wb,
                    false,
                )
                .await?;

            if subscribed {
                let min_int_secs = req.min_int_floor;
                let max_int_secs = core::cmp::max(req.max_int_ceil, 20); // TODO

                info!("New subscription {node_id:x}::{subscription_id}; reporting interval: {min_int_secs}s - {max_int_secs}s");

                exchange
                    .send_with(|wb| {
                        SubscribeResp::write(wb, subscription_id, max_int_secs)?;
                        Ok(OpCode::SubscribeResponse.into())
                    })
                    .await?;

                let mut changed = false;

                while subscribed {
                    let removed = self.subscriptions.wait_removed(node_id, subscription_id);
                    let timeout = Timer::after(embassy_time::Duration::from_secs(10));

                    let result = select(removed, timeout).await;

                    if let Either::First(removed) = result {
                        if removed {
                            break;
                        } else {
                            // TODO: Examine all clusters to figure out if data reporting is due
                            changed = true;
                            info!("Subscription {node_id:x}::{subscription_id}: Change detected");
                        }
                    }

                    let now = Instant::now();

                    let changed_due = changed
                        && reported_at + embassy_time::Duration::from_secs(min_int_secs as _)
                            <= now;
                    let timeout_due =
                        reported_at + embassy_time::Duration::from_secs(max_int_secs as _) <= now; // TODO

                    if changed_due || timeout_due {
                        if changed_due {
                            info!("Subscription {node_id:x}::{subscription_id}: Reporting due to detected change");
                        } else {
                            info!("Subscription {node_id:x}::{subscription_id}: Reporting due to {max_int_secs}s interval expiry");
                        }

                        reported_at = now;
                        changed = false;

                        subscribed = self
                            .report_data(
                                exchange,
                                &ReportDataReq::Subscribe(req),
                                Some(subscription_id),
                                wb,
                                false,
                            )
                            .await?;
                    } else if changed {
                        info!("Subscription {node_id:x}::{subscription_id}: Waiting for {min_int_secs}s interval to report the change");
                    }
                }
            }
        } else {
            exchange
                .send_with(|wb| {
                    StatusResp::write(wb, IMStatusCode::ResourceExhausted)?;

                    Ok(OpCode::StatusResponse.into())
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
