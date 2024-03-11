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

use core::fmt::Display;

use embassy_futures::select::select_slice;

use log::{error, info};

use crate::data_model::core::DataModel;
use crate::data_model::objects::DataModelHandler;
use crate::data_model::subscriptions::Subscriptions;
use crate::error::{Error, ErrorCode};
use crate::interaction_model::busy::BusyInteractionModel;
use crate::secure_channel::busy::BusySecureChannel;
use crate::secure_channel::core::SecureChannel;
use crate::transport::exchange::Exchange;
use crate::Matter;

pub trait ExchangeHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error>;

    fn compose<T>(self, other: T) -> CompositeExchangeHandler<Self, T>
    where
        T: ExchangeHandler,
        Self: Sized,
    {
        CompositeExchangeHandler(self, other)
    }
}

impl<T> ExchangeHandler for &T
where
    T: ExchangeHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        (*self).handle(exchange).await
    }
}

pub struct CompositeExchangeHandler<F, S>(F, S);

impl<F, S> ExchangeHandler for CompositeExchangeHandler<F, S>
where
    F: ExchangeHandler,
    S: ExchangeHandler,
{
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error> {
        let result = self.0.handle(exchange).await;

        match result {
            Err(e) if e.code() == ErrorCode::InvalidProto => self.1.handle(exchange).await,
            other => other,
        }
    }
}

pub struct Responder<'a, T> {
    name: &'a str,
    handler: T,
    matter: &'a Matter<'a>,
    respond_after_ms: u32,
}

impl<'a, T> Responder<'a, T>
where
    T: ExchangeHandler,
{
    pub const fn new(
        name: &'a str,
        handler: T,
        matter: &'a Matter<'a>,
        respond_after_ms: u32,
    ) -> Self {
        Self {
            name,
            handler,
            matter,
            respond_after_ms,
        }
    }

    pub async fn run<const N: usize>(&self) -> Result<(), Error> {
        info!("{}: Creating {N} handlers", self.name);

        let mut handlers = heapless::Vec::<_, N>::new();
        info!(
            "{}: Handlers size: {}B",
            self.name,
            core::mem::size_of_val(&handlers)
        );

        for index in 0..N {
            let handler_id = (index as u8) + 2;

            handlers
                .push(self.respond(handler_id))
                .map_err(|_| ())
                .unwrap();
        }

        select_slice(&mut handlers).await.0
    }

    async fn respond(&self, handler_id: impl Display) -> Result<(), Error> {
        loop {
            let mut exchange = Exchange::accept_after(self.matter, self.respond_after_ms).await?;

            info!(
                "{}: Handler {handler_id} / exchange {}: Starting",
                self.name,
                exchange.id()
            );

            let result = self.handler.handle(&mut exchange).await;

            if let Err(err) = result {
                error!(
                    "{}: Handler {handler_id} / exchange {}: Abandoned because of error {err:?}",
                    self.name,
                    exchange.id()
                );
            } else {
                info!(
                    "{}: Handler {handler_id} / exchange {}: Completed",
                    self.name,
                    exchange.id()
                );
            }
        }
    }
}

impl<'a, const N: usize, H>
    Responder<'a, CompositeExchangeHandler<DataModel<'a, N, H>, SecureChannel>>
{
    pub fn new_default(subscriptions: &'a Subscriptions<'a, N>, dm_handler: H) -> Self
    where
        H: DataModelHandler,
    {
        Self::new(
            "Responder",
            DataModel::new(dm_handler, subscriptions).compose(SecureChannel::new()),
            subscriptions.matter(),
            0,
        )
    }
}

impl<'a> Responder<'a, CompositeExchangeHandler<BusyInteractionModel, BusySecureChannel>> {
    pub fn new_busy(matter: &'a Matter<'a>) -> Self {
        Self::new(
            "Busy Responder",
            BusyInteractionModel::new().compose(BusySecureChannel::new()),
            matter,
            200,
        )
    }
}
