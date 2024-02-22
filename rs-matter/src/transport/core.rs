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

use core::mem::MaybeUninit;
use core::pin::pin;

use embassy_futures::select::{select3, select_slice};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::Mutex;

use log::{error, info, warn};

use crate::{
    data_model::{core::DataModel, objects::DataModelHandler},
    error::{Error, ErrorCode},
    interaction_model::core::PROTO_ID_INTERACTION_MODEL,
    secure_channel::{
        common::{OpCode, PROTO_ID_SECURE_CHANNEL},
        core::SecureChannel,
    },
    utils::{
        notification::Notification, parsebuf::ParseBuf, select::EitherUnwrap, writebuf::WriteBuf,
    },
    CommissioningData, Matter, MATTER_PORT,
};

use super::exchange::{
    Exchange, ExchangeBuffer, ExchangeBuffers, ExchangeId, ExchangeMeta, ExchangePacket, Role,
    RxExchangePacket, TxExchangePacket, MAX_EXCHANGES,
};
use super::network::{Address, Ipv6Addr, SocketAddr, SocketAddrV6, UdpReceive, UdpSend};
use super::packet::{PacketHdr, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use super::session::CloneData;

#[derive(Debug)]
enum OpCodeDescriptor {
    SecureChannel(OpCode),
    InteractionModel(crate::interaction_model::core::OpCode),
    Unknown(u8),
}

impl From<u8> for OpCodeDescriptor {
    fn from(value: u8) -> Self {
        if let Some(opcode) = num::FromPrimitive::from_u8(value) {
            Self::SecureChannel(opcode)
        } else if let Some(opcode) = num::FromPrimitive::from_u8(value) {
            Self::InteractionModel(opcode)
        } else {
            Self::Unknown(value)
        }
    }
}

const MRP_STANDALONE_ACK: ExchangeMeta = ExchangeMeta {
    proto_id: PROTO_ID_SECURE_CHANNEL,
    proto_opcode: OpCode::MRPStandAloneAck as u8,
    reliable: false,
};

pub const MATTER_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MATTER_PORT, 0, 0));

pub struct PacketBuffers {
    tx_packet: Mutex<NoopRawMutex, TxExchangePacket>,
    rx_packet: Mutex<NoopRawMutex, RxExchangePacket>,
    ack_packet: ExchangePacket<{ PacketHdr::HDR_RESERVE }>,
    tx_bufs: MaybeUninit<[[u8; MAX_TX_BUF_SIZE]; MAX_EXCHANGES]>,
    rx_bufs: MaybeUninit<[[u8; MAX_RX_BUF_SIZE]; MAX_EXCHANGES]>,
}

impl PacketBuffers {
    const TX_INIT: MaybeUninit<[[u8; MAX_TX_BUF_SIZE]; MAX_EXCHANGES]> = MaybeUninit::uninit();
    const RX_INIT: MaybeUninit<[[u8; MAX_RX_BUF_SIZE]; MAX_EXCHANGES]> = MaybeUninit::uninit();

    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            tx_packet: Mutex::new(TxExchangePacket::new()),
            rx_packet: Mutex::new(RxExchangePacket::new()),
            ack_packet: ExchangePacket::new(),
            tx_bufs: Self::TX_INIT,
            rx_bufs: Self::RX_INIT,
        }
    }
}

impl<'a> Matter<'a> {
    #[allow(clippy::too_many_arguments)]
    pub async fn run<H, S, R>(
        &self,
        send: S,
        recv: R,
        buffers: &mut PacketBuffers,
        dev_comm: CommissioningData,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
        S: UdpSend,
        R: UdpReceive,
    {
        info!("Running Matter transport");

        let tx_bufs = unsafe { buffers.tx_bufs.assume_init_mut() };
        let rx_bufs = unsafe { buffers.rx_bufs.assume_init_mut() };

        if self.start_comissioning(dev_comm, &mut rx_bufs[0])? {
            info!("Comissioning started");
        }

        let send = Mutex::new(send);

        let notification = Notification::new();

        let mut rx_handler = pin!(self.handle_rx(
            recv,
            &buffers.rx_packet,
            &notification,
            &send,
            &mut buffers.ack_packet
        ));
        let mut tx_handler = pin!(self.handle_tx(&send, &buffers.tx_packet, &notification,));

        let mut exchange_handlers = pin!(self.handle_exchanges(
            rx_bufs,
            tx_bufs,
            &buffers.rx_packet,
            &buffers.tx_packet,
            &notification,
            handler
        ));

        select3(&mut rx_handler, &mut tx_handler, &mut exchange_handlers)
            .await
            .unwrap()
    }

    async fn handle_exchanges<H>(
        &self,
        rx_bufs: &mut [[u8; MAX_RX_BUF_SIZE]; MAX_EXCHANGES],
        tx_bufs: &mut [[u8; MAX_TX_BUF_SIZE]; MAX_EXCHANGES],
        rx_packet_ref: &Mutex<NoopRawMutex, RxExchangePacket>,
        tx_packet_ref: &Mutex<NoopRawMutex, TxExchangePacket>,
        notification: &Notification,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        info!("Creating {} handlers", MAX_EXCHANGES);
        let mut handlers = heapless::Vec::<_, MAX_EXCHANGES>::new();

        info!("Handlers size: {}", core::mem::size_of_val(&handlers));

        for index in 0..MAX_EXCHANGES {
            let handler_id = (index as u8) + 2;

            let rb = unsafe {
                core::slice::from_raw_parts_mut(rx_bufs[index].as_mut_ptr(), MAX_RX_BUF_SIZE)
            };
            let wb = unsafe {
                core::slice::from_raw_parts_mut(tx_bufs[index].as_mut_ptr(), MAX_TX_BUF_SIZE)
            };

            handlers
                .push(self.handle_exchange(
                    rb,
                    wb,
                    rx_packet_ref,
                    tx_packet_ref,
                    notification,
                    handler_id,
                    handler,
                ))
                .map_err(|_| ())
                .unwrap();
        }

        select_slice(&mut handlers).await.0
    }

    pub async fn handle_tx<S>(
        &self,
        send: &Mutex<NoopRawMutex, S>,
        packet_ref: &Mutex<NoopRawMutex, TxExchangePacket>,
        notification: &Notification,
    ) -> Result<(), Error>
    where
        S: UdpSend,
    {
        loop {
            let mut dc = notification
                .get(packet_ref, 1, |td| !td.buf.is_empty())
                .await;

            let packet = dc.data_mut();

            let mut send = send.lock().await;
            send.send_to(
                &packet.buf[packet.payload_start..],
                packet.peer.unwrap_udp(),
            )
            .await?;

            packet.buf.clear();
            dc.notify(true);
        }
    }

    pub async fn handle_rx<R, S>(
        &self,
        mut recv: R,
        packet_ref: &Mutex<NoopRawMutex, RxExchangePacket>,
        notification: &Notification,
        send: &Mutex<NoopRawMutex, S>,
        ack_packet: &mut ExchangePacket<{ PacketHdr::HDR_RESERVE }>,
    ) -> Result<(), Error>
    where
        R: UdpReceive,
        S: UdpSend,
    {
        ack_packet
            .buf
            .resize_default(PacketHdr::HDR_RESERVE)
            .unwrap();
        let mut ack_packet_wb = WriteBuf::new(&mut ack_packet.buf);

        loop {
            let mut dc = notification
                .get(packet_ref, 0, |packet| packet.buf.is_empty())
                .await;

            info!("Transport: waiting for incoming packet");

            let packet = dc.data_mut();

            packet.buf.resize_default(MAX_RX_BUF_SIZE).unwrap();
            let result = recv.recv_from(&mut packet.buf).await;

            match result {
                Err(e) => {
                    error!("Network error {e}");
                    packet.buf.clear();
                }
                Ok((len, remote)) => {
                    packet.buf.truncate(len);
                    packet.peer = Address::Udp(remote);

                    info!("Got network packet from peer {remote}:\n{:?}", packet.buf);

                    let mut pb = ParseBuf::new(&mut packet.buf);

                    let result = self.process_rx(
                        packet.peer,
                        &mut packet.header,
                        &mut pb,
                        &mut ack_packet.header,
                        &mut ack_packet_wb,
                    );
                    match result {
                        Err(e) if matches!(e.code(), ErrorCode::Duplicate) => {
                            packet.buf.clear();

                            info!("Duplicate packet: {:?}", packet.header);
                            let mut send = send.lock().await;
                            send.send_to(ack_packet_wb.as_slice(), ack_packet.peer.unwrap_udp())
                                .await?;
                        }
                        Err(e) => {
                            packet.buf.clear();

                            error!("Packet error ({e}) for packet: {:?}", packet.header.plain);
                        }
                        Ok(new_exchange) => {
                            let (start, end) = pb.slice_range();

                            packet.new_exchange = new_exchange;
                            packet.payload_start = start;
                            packet.buf.truncate(end);

                            info!(
                                "Got packet: {:?} with layload len {}",
                                packet.header,
                                packet.buf.len() - packet.payload_start
                            );

                            dc.notify(true);
                        }
                    }
                }
            }
        }
    }

    #[inline(always)]
    pub async fn handle_exchange<H>(
        &self,
        rx_buf: &mut [u8],
        tx_buf: &mut [u8],
        rx_packet_ref: &Mutex<NoopRawMutex, RxExchangePacket>,
        tx_packet_ref: &Mutex<NoopRawMutex, TxExchangePacket>,
        notification: &Notification,
        handler_index: u8,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        loop {
            let id = {
                let mut dc = notification
                    .get(rx_packet_ref, handler_index, |rd| {
                        !rd.buf.is_empty() && rd.new_exchange
                    })
                    .await;

                let packet = dc.data_mut();
                packet.new_exchange = false;

                ExchangeId::load(
                    packet.header.proto.exch_id,
                    packet.peer,
                    &packet.header.plain,
                )
            };

            info!("Handler {}: Got exchange {:?}", handler_index, id);

            let exchange = Exchange {
                id: &id,
                matter: self,
                rx_packet: rx_packet_ref,
                tx_packet: tx_packet_ref,
                notification,
                index: handler_index,
            };

            let buffers = ExchangeBuffers {
                rx: ExchangeBuffer(rx_buf),
                tx: ExchangeBuffer(tx_buf),
            };

            let result = self.dispatch_exchange(exchange, buffers, handler).await;

            let mut packet = rx_packet_ref.lock().await;
            if !packet.buf.is_empty()
                && ExchangeId::load(
                    packet.header.proto.exch_id,
                    packet.peer,
                    &packet.header.plain,
                ) == id
            {
                packet.buf.clear();
            }

            self.exchange_mgr.borrow_mut().remove(&id);

            if let Err(err) = result {
                warn!(
                    "Handler {}: Exchange closed because of error: {:?}",
                    handler_index, err
                );
            } else {
                info!("Handler {}: Exchange completed", handler_index);
            }
        }
    }

    async fn dispatch_exchange<H>(
        &self,
        mut exchange: Exchange<'_>,
        buffers: ExchangeBuffers<'_>,
        handler: &H,
    ) -> Result<(), Error>
    where
        H: DataModelHandler,
    {
        let proto_id = exchange.get().await.meta().proto_id;

        match proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                let sc = SecureChannel::new(self);

                sc.handle(exchange, buffers).await?;

                self.notify_changed();
            }
            PROTO_ID_INTERACTION_MODEL => {
                let dm = DataModel::new(handler);

                dm.handle(exchange, buffers).await?;

                self.notify_changed();
            }
            other => {
                error!("Unknown Proto-ID: {}", other);
            }
        }

        Ok(())
    }

    pub fn reset_transport(&self) {
        self.exchange_mgr.borrow_mut().reset();
        self.session_mgr.borrow_mut().reset();
    }

    fn process_rx(
        &self,
        peer: Address,
        header: &mut PacketHdr,
        pb: &mut ParseBuf,
        ack_header: &mut PacketHdr,
        ack_wb: &mut WriteBuf,
    ) -> Result<bool, Error> {
        header.reset();
        header.decode_plain_hdr(pb)?;

        let mut session_mgr = self.session_mgr.borrow_mut();

        let session = session_mgr
            .get_for(
                header.plain.sess_id,
                peer,
                header.plain.get_src_nodeid(),
                header.plain.is_encrypted(),
            )
            .ok_or(ErrorCode::NoSession)?;

        session.decode_remaining(header, pb)?;

        if session.is_duplicate(&header.plain) {
            ack_header.reset();
            ack_wb.reset();
            ack_wb.reserve(PacketHdr::HDR_RESERVE)?;

            MRP_STANDALONE_ACK.set_into(&mut ack_header.proto);

            session.pre_send(None, &mut ack_header.plain);
            session.encode(&ack_header, ack_wb)?;

            Err(ErrorCode::Duplicate)?;
        }

        let mut exchange_mgr = self.exchange_mgr.borrow_mut();
        let id = ExchangeId::load(header.proto.exch_id, peer, &header.plain);
        let exchange = exchange_mgr.get(&id);

        let new = if let Some(exchange) = exchange {
            if exchange.role != Role::Responder {
                Err(ErrorCode::NoExchange)?;
            }

            let updated = session.recv(&header.plain);
            assert_eq!(updated, true);

            exchange.recv(&header, self.epoch)?;

            false
        } else {
            if !header.proto.is_initiator() {
                Err(ErrorCode::NoExchange)?;
            }

            let exchange = exchange_mgr
                .add(id, Role::complementary(header.proto.is_initiator()))
                .ok_or(ErrorCode::NoSpaceExchanges)?;

            let updated = session.recv(&header.plain);
            assert_eq!(updated, true);

            exchange.recv(&header, self.epoch)?;

            true
        };

        Ok(new)
    }

    pub(crate) fn process_tx(
        &self,
        id: &ExchangeId,
        meta: ExchangeMeta,
        ctr: Option<u32>,
        header: &mut PacketHdr,
        wb: &mut WriteBuf,
    ) -> Result<(), Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();
        let session = session_mgr
            .get(&id.session_id)
            .ok_or(ErrorCode::NoSession)?;

        let mut exchange_mgr = self.exchange_mgr.borrow_mut();
        let exchange = exchange_mgr.get(id).ok_or(ErrorCode::NoExchange)?;

        header.reset();

        session.pre_send(ctr, &mut header.plain);
        exchange.pre_send(&header.plain, &mut header.proto)?;

        meta.set_into(&mut header.proto);

        session.encode(&header, wb)
    }

    pub(crate) async fn clone_session(&self, clone_data: &CloneData) -> Result<(), Error> {
        loop {
            let mut session_mgr = self.session_mgr.borrow_mut();

            let result = session_mgr.clone_session(clone_data);

            match result {
                Ok(_) => break,
                Err(err) if err.code() == ErrorCode::NoSpaceSessions => {
                    self.evict_session().await?
                }
                Err(other) => Err(other)?,
            }
        }

        Ok(())
    }

    pub(crate) async fn evict_session(&self) -> Result<(), Error> {
        let session = {
            let mut session_mgr = self.session_mgr.borrow_mut();

            let sess_index = session_mgr.get_session_for_eviction();
            if let Some(sess_index) = sess_index {
                Some(session_mgr.remove(sess_index))
            } else {
                None
            }
        };

        if session.is_some() {
            Ok(())

            // TODO

            // let ctx = {
            //     create_status_report(
            //         tx,
            //         GeneralCode::Success,
            //         PROTO_ID_SECURE_CHANNEL as _,
            //         SCStatusCodes::CloseSession as _,
            //         None,
            //     )?;

            //     let mut session_mgr = self.session_mgr.borrow_mut();
            //     let session_id = session_mgr.mut_by_index(sess_index).unwrap().id();
            //     warn!("Evicting session: {:?}", session_id);

            //     let ctx = ExchangeCtx::prep_ephemeral(session_id, &mut session_mgr, None, tx)?;

            //     session_mgr.remove(sess_index);

            //     ctx
            // };

            // self.send_ephemeral(ctx, tx).await
        } else {
            Err(ErrorCode::NoSpaceSessions.into())
        }
    }
}
