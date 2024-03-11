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

use core::cell::{Cell, RefCell};

use embassy_futures::select::{select, Either};
use embassy_time::{Instant, Timer};

use portable_atomic::{AtomicU32, Ordering};

use super::{core::DataModel, objects::*};

use crate::error::*;
use crate::interaction_model::{core::ReportDataReq, messages::msg::SubscribeReq};
use crate::tlv::{self, FromTLV};
use crate::transport::exchange::Exchange;
use crate::transport::packet::MAX_RX_BUF_SIZE;
use crate::utils::{select::Notification, writebuf::WriteBuf};
use crate::Matter;

struct Subscription {
    node_id: u64,
    id: u32,
    subscribe_req: heapless::Vec<u8, MAX_RX_BUF_SIZE>,
    min_int_secs: u16,
    max_int_secs: u16,
    reported_at: Instant,
    changed: bool,
}

impl Subscription {
    pub const fn new() -> Self {
        Self {
            node_id: 0,
            id: 0,
            subscribe_req: heapless::Vec::new(),
            min_int_secs: 0,
            max_int_secs: 0,
            reported_at: Instant::MAX,
            changed: false,
        }
    }

    pub fn remove(&mut self) {
        self.id = 0;
    }

    pub fn is_free(&self) -> bool {
        self.id == 0
    }

    pub fn report_due(&self, now: Instant) -> bool {
        !self.is_free()
            && self.changed
            && self.reported_at + embassy_time::Duration::from_secs(self.min_int_secs as _) <= now
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        !self.is_free()
            && self.reported_at + embassy_time::Duration::from_secs(self.max_int_secs as _) <= now
    }
}

pub struct Subscriptions<'a, const N: usize> {
    matter: &'a Matter<'a>,
    next_subscription_id: AtomicU32,
    subscriptions: RefCell<[Subscription; N]>,
    notification: Notification,
}

impl<'a, const N: usize> Subscriptions<'a, N> {
    const INIT: Subscription = Subscription::new();

    pub const fn new(matter: &'a Matter) -> Self {
        Self {
            matter,
            next_subscription_id: AtomicU32::new(1),
            subscriptions: RefCell::new([Self::INIT; N]),
            notification: Notification::new(),
        }
    }

    pub fn matter(&'a self) -> &'a Matter<'a> {
        self.matter
    }

    pub fn notify_changed(&self) {
        for sub in self
            .subscriptions
            .borrow_mut()
            .iter_mut()
            .filter(|sub| !sub.is_free())
        {
            sub.changed = true;
        }

        self.notification.signal(());
    }

    pub async fn run<T>(&self, handler: T) -> Result<(), Error>
    where
        T: DataModelHandler,
    {
        let mut data = heapless::Vec::<_, 1480>::new(); // TODO: Will take too much space
        let mut wb = heapless::Vec::<_, 1280>::new(); // TODO: Will take too much space

        wb.resize_default(1280).unwrap(); // TODO

        loop {
            let timer = Timer::after(embassy_time::Duration::from_secs(4));

            let result = select(self.notification.wait(), timer).await;
            let _changed = matches!(result, Either::First(_));

            let now = Instant::now();

            {
                for sub in self
                    .subscriptions
                    .borrow_mut()
                    .iter_mut()
                    .filter(|sub| sub.is_expired(now))
                {
                    sub.remove();
                }
            }

            loop {
                let sub = {
                    if let Some(sub) = self
                        .subscriptions
                        .borrow()
                        .iter()
                        .find(|sub| sub.report_due(now))
                    {
                        data.clear();
                        data.extend_from_slice(&sub.subscribe_req).unwrap();

                        Some((sub.id, sub.node_id))
                    } else {
                        None
                    }
                };

                if let Some((id, node_id)) = sub {
                    let subscribed = Cell::new(false);

                    let _guard = scopeguard::guard((), |_| {
                        if !subscribed.get() {
                            self.remove(node_id, Some(id));
                        }
                    });

                    // TODO: Do a more sophisticated check whether something had actually changed w.r.t. this subscription

                    let mut req =
                        SubscribeReq::from_tlv(&tlv::get_root_node_struct(&data).unwrap()).unwrap();

                    // Only used when priming the subscription
                    req.event_filters = None;
                    req.dataver_filters = None;

                    let req = ReportDataReq::Subscribe(&req);
                    let mut wb = WriteBuf::new(&mut wb);

                    let mut exchange = Exchange::initiate(self.matter, node_id, true).await?;

                    if DataModel::<0, &T>::report_data(
                        &handler,
                        &mut exchange,
                        &req,
                        Some(id),
                        &mut wb,
                        false,
                    )
                    .await?
                    {
                        if let Some(sub) = self
                            .subscriptions
                            .borrow_mut()
                            .iter_mut()
                            .find(|sub| sub.id == id)
                        {
                            sub.changed = false;
                            sub.reported_at = Instant::now();
                            subscribed.set(true);
                        }
                    }

                    exchange.acknowledge().await?;
                } else {
                    break;
                }
            }
        }
    }

    pub(crate) fn add(&self, node_id: u64, req: &[u8], max_int_secs: u16) -> Option<u32> {
        let mut subscriptions = self.subscriptions.borrow_mut();

        if let Some(sub) = subscriptions.iter_mut().find(|sub| sub.is_free()) {
            let id = self.next_subscription_id.fetch_add(1, Ordering::SeqCst);

            sub.subscribe_req.clear();
            sub.subscribe_req.extend_from_slice(req).unwrap();

            sub.node_id = node_id;
            sub.id = id;
            sub.max_int_secs = max_int_secs;
            sub.reported_at = Instant::now();

            Some(id)
        } else {
            None
        }
    }

    pub(crate) fn remove(&self, node_id: u64, id: Option<u32>) {
        for sub in self.subscriptions.borrow_mut().iter_mut() {
            if sub.node_id == node_id && id.map(|id| id == sub.id).unwrap_or(true) {
                sub.remove();
            }
        }
    }
}
