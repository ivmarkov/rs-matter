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

use crate::{
    alloc,
    data_model::{core::DataModel, objects::DataModelHandler},
    error::Error,
    interaction_model::core::PROTO_ID_INTERACTION_MODEL,
    secure_channel::{common::PROTO_ID_SECURE_CHANNEL, core::SecureChannel},
    transport::{
        exchange::Exchange,
        packet::{PacketHdr, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE},
    },
    utils::writebuf::WriteBuf,
    Matter,
};

pub struct Responder<H>(H);

impl<'a, H> Responder<H>
where
    H: DataModelHandler,
{
    pub const fn new(handler: H) -> Self {
        Self(handler)
    }

    pub async fn run<const N: usize>(&self, matter: &Matter<'_>) -> Result<(), Error> {
        info!("Creating {N} handlers");
        let mut handlers = heapless::Vec::<_, N>::new();

        info!("Handlers size: {}", core::mem::size_of_val(&handlers));

        for index in 0..N {
            let handler_id = (index as u8) + 2;

            handlers
                .push(self.respond(matter, handler_id))
                .map_err(|_| ())
                .unwrap();
        }

        select_slice(&mut handlers).await.0
    }

    #[inline(always)]
    async fn respond(&self, matter: &Matter<'_>, handler_id: impl Display) -> Result<(), Error> {
        loop {
            let exchange = Exchange::accept(matter).await?;

            info!("Handler {}: Got exchange {:?}", handler_id, exchange.id());

            let result = self.process(exchange).await;

            if let Err(err) = result {
                error!(
                    "Handler {}: Exchange abandoned because of error: {:?}",
                    handler_id, err
                );
            } else {
                info!("Handler {}: Exchange completed", handler_id);
            }
        }
    }

    pub async fn process(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        let proto_id = exchange.rx().await?.meta().proto_id;

        match proto_id {
            PROTO_ID_SECURE_CHANNEL => SecureChannel::new().handle(exchange).await,
            PROTO_ID_INTERACTION_MODEL => {
                let mut rx = alloc!([0; MAX_RX_BUF_SIZE]);
                let mut tx =
                    alloc!([0; MAX_TX_BUF_SIZE - PacketHdr::HDR_RESERVE - PacketHdr::TAIL_RESERVE]);

                let mut rb = WriteBuf::new(&mut *rx);
                let mut tb = WriteBuf::new(&mut *tx);

                DataModel::new(&self.0)
                    .handle(exchange, &mut rb, &mut tb)
                    .await
            }
            other => {
                error!("Unknown Proto-ID: {}", other);

                Ok(())
            }
        }
    }
}
