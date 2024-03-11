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

use crate::error::{Error, ErrorCode};
use crate::transport::exchange::Exchange;
use crate::Matter;

pub trait ExchangeHandler {
    async fn handle(&self, exchange: &mut Exchange<'_>) -> Result<(), Error>;

    fn compose<T>(self, other: T) -> impl ExchangeHandler
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

struct CompositeExchangeHandler<F, S>(F, S);

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
            let exchange = Exchange::accept_after(self.matter, self.respond_after_ms).await?;
            let exchange_id = exchange.id();

            info!(
                "{}: Handler {handler_id} / exchange {exchange_id}: Starting",
                self.name
            );

            let result = self.handler.handle(&mut exchange).await;

            if let Err(err) = result {
                error!("{}: Handler {handler_id} / exchange {exchange_id}: Abandoned because of error {err:?}", self.name);
            } else {
                info!(
                    "{}: Handler {handler_id} / exchange {exchange_id}: Completed",
                    self.name
                );
            }
        }
    }
}
