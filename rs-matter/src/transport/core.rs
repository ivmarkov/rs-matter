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

use core::cell::RefCell;
use core::fmt::{self, Display};
use core::ops::{Deref, DerefMut};
use core::pin::pin;

use embassy_futures::select::{select, select3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_time::Timer;

use log::{debug, error, info, warn};

use crate::error::{Error, ErrorCode};
use crate::interaction_model::{
    self,
    core::{IMStatusCode, PROTO_ID_INTERACTION_MODEL},
    messages::msg::StatusResp,
};
use crate::secure_channel::common::{sc_write, OpCode, SCStatusCodes, PROTO_ID_SECURE_CHANNEL};
use crate::tlv::TLVList;
use crate::utils::{
    epoch::Epoch,
    ifmutex::{IfMutex, IfMutexGuard},
    parsebuf::ParseBuf,
    rand::Rand,
    select::{EitherUnwrap, Notification},
    writebuf::WriteBuf,
};
use crate::{Matter, MATTER_PORT};

use super::exchange::{Exchange, ExchangeId, ExchangeMeta, OwnedState, Role};
use super::network::{
    Address, BufferAccess, Ipv6Addr, NetworkReceive, NetworkSend, SocketAddr, SocketAddrV6,
};
use super::packet::{PacketHdr, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use super::proto_hdr::ProtoHdr;
use super::session::{Session, SessionMgr};

pub const MATTER_SOCKET_BIND_ADDR: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MATTER_PORT, 0, 0));

const ACCEPT_TIMEOUT_MS: u64 = 500;

pub struct Packet<const N: usize> {
    pub(crate) peer: Address,
    pub(crate) header: PacketHdr,
    pub(crate) buf: heapless::Vec<u8, N>,
    pub(crate) payload_start: usize,
}

impl<const N: usize> Packet<N> {
    #[inline(always)]
    pub(crate) const fn new() -> Self {
        Self {
            peer: Address::new(),
            header: PacketHdr::new(),
            buf: heapless::Vec::new(),
            payload_start: 0,
        }
    }

    pub fn display<'a>(peer: &'a Address, header: &'a PacketHdr) -> impl Display + 'a {
        struct PacketInfo<'a>(&'a Address, &'a PacketHdr);

        impl<'a> Display for PacketInfo<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Packet::<0>::fmt(f, self.0, self.1)
            }
        }

        PacketInfo(peer, header)
    }

    pub fn display_payload<'a>(proto: &'a ProtoHdr, buf: &'a [u8]) -> impl Display + 'a {
        struct PacketInfo<'a>(&'a ProtoHdr, &'a [u8]);

        impl<'a> Display for PacketInfo<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                Packet::<0>::fmt_payload(f, self.0, self.1)
            }
        }

        PacketInfo(proto, buf)
    }

    fn fmt(f: &mut fmt::Formatter<'_>, peer: &Address, header: &PacketHdr) -> fmt::Result {
        let meta = ExchangeMeta::from(&header.proto);

        write!(f, "{peer} {header}\n{meta}")
    }

    fn fmt_payload(f: &mut fmt::Formatter<'_>, proto: &ProtoHdr, buf: &[u8]) -> fmt::Result {
        let meta = ExchangeMeta::from(proto);

        write!(f, "{meta}")?;

        if meta.is_tlv() {
            write!(
                f,
                "; TLV:\n----------------\n{}\n----------------\n",
                TLVList::new(buf)
            )?;
        } else {
            write!(
                f,
                "; Payload:\n----------------\n{:02x?}\n----------------\n",
                buf
            )?;
        }

        Ok(())
    }
}

impl<const N: usize> Display for Packet<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::fmt(f, &self.peer, &self.header)
    }
}

pub(crate) struct PacketAccess<'a, const N: usize>(IfMutexGuard<'a, NoopRawMutex, Packet<N>>, bool);

impl<'a, const N: usize> PacketAccess<'a, N> {
    pub fn clear_on_drop(&mut self, clear: bool) {
        self.1 = clear;
    }
}

impl<'a, const N: usize> Deref for PacketAccess<'a, N> {
    type Target = Packet<N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, const N: usize> DerefMut for PacketAccess<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, const N: usize> Drop for PacketAccess<'a, N> {
    fn drop(&mut self) {
        if self.1 {
            self.buf.clear();
        }
    }
}

impl<'a, const N: usize> Display for PacketAccess<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub(crate) struct PacketBufferAccess<'a, const N: usize>(
    pub(crate) &'a IfMutex<NoopRawMutex, Packet<N>>,
);

impl<'a, const N: usize> BufferAccess for PacketBufferAccess<'a, N> {
    type Buffer<'b> = PacketBuffer<'b, N> where Self: 'b;

    async fn get(&self) -> PacketBuffer<'_, N> {
        let mut packet = self.0.lock_if(|packet| packet.buf.is_empty()).await;

        packet.buf.resize_default(N).unwrap();

        PacketBuffer(packet)
    }
}

pub struct PacketBuffer<'a, const N: usize>(IfMutexGuard<'a, NoopRawMutex, Packet<N>>);

impl<'a, const N: usize> Deref for PacketBuffer<'a, N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.buf
    }
}

impl<'a, const N: usize> DerefMut for PacketBuffer<'a, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.buf
    }
}

impl<'a, const N: usize> Drop for PacketBuffer<'a, N> {
    fn drop(&mut self) {
        self.0.buf.clear();
    }
}

pub struct TransportMgr {
    pub(crate) rx: IfMutex<NoopRawMutex, Packet<MAX_RX_BUF_SIZE>>,
    pub(crate) tx: IfMutex<NoopRawMutex, Packet<MAX_TX_BUF_SIZE>>,
    pub(crate) orphaned: Notification,
    pub session_mgr: RefCell<SessionMgr>, // For testing
}

impl TransportMgr {
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            rx: IfMutex::new(Packet::new()),
            tx: IfMutex::new(Packet::new()),
            orphaned: Notification::new(),
            session_mgr: RefCell::new(SessionMgr::new(epoch, rand)),
        }
    }

    pub fn reset(&self) {
        self.session_mgr.borrow_mut().reset();
    }

    pub(crate) async fn initiate<'a>(
        &'a self,
        matter: &'a Matter<'a>,
        session_id: u32,
    ) -> Result<Exchange<'_>, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();

        session_mgr.get(session_id).ok_or(ErrorCode::NoSession)?;

        let exch_id = session_mgr.get_next_exch_id();

        let session = session_mgr.get(session_id).unwrap();
        let exchange_index = session
            .add_exchange(exch_id, Role::Initiator)
            .ok_or(ErrorCode::NoSpaceExchanges)?;

        let id = ExchangeId::new(session_id, exchange_index);

        info!("Exchange {id}: Initiated");

        Ok(Exchange::new(id, matter))
    }

    pub(crate) async fn accept<'a>(
        &'a self,
        matter: &'a Matter<'a>,
    ) -> Result<Exchange<'_>, Error> {
        let exchange = self
            .with_locked(&self.rx, |packet| {
                let mut session_mgr = self.session_mgr.borrow_mut();
                if let Some(session) = session_mgr.get_for(&packet.peer, &packet.header.plain) {
                    if let Some(exch_index) = session.get_exchange_index_for(&packet.header.proto) {
                        let exch = session.exchanges[exch_index].as_mut().unwrap();

                        if matches!(exch.owned_state, OwnedState::NotAccepted) {
                            exch.owned_state = OwnedState::Owned;

                            let id = ExchangeId::new(session.id, exch_index);

                            info!("Exchange {id}: Accepted");

                            let exchange =
                                Exchange::new(ExchangeId::new(session.id, exch_index), matter);

                            return Some(exchange);
                        }
                    }
                }

                None
            })
            .await;

        Ok(exchange)
    }

    pub async fn run<S, R>(&self, send: S, recv: R) -> Result<(), Error>
    where
        S: NetworkSend,
        R: NetworkReceive,
    {
        info!("Running Matter transport");

        let send = IfMutex::new(send);

        let mut rx = pin!(self.process_rx(recv, &send));
        let mut tx = pin!(self.process_tx(&send));
        let mut orphaned = pin!(self.process_orphaned());

        select3(&mut rx, &mut tx, &mut orphaned).await.unwrap()
    }

    pub(crate) async fn get_if<'a, F, const N: usize>(
        &'a self,
        packet_mutex: &'a IfMutex<NoopRawMutex, Packet<N>>,
        f: F,
    ) -> PacketAccess<'a, N>
    where
        F: Fn(&Packet<N>) -> bool,
    {
        PacketAccess(packet_mutex.lock_if(f).await, false)
    }

    async fn with_locked<'a, F, R, T>(
        &'a self,
        packet_mutex: &'a IfMutex<NoopRawMutex, T>,
        f: F,
    ) -> R
    where
        F: FnMut(&mut T) -> Option<R>,
    {
        packet_mutex.with(f).await
    }

    async fn process_tx<S>(&self, send: &IfMutex<NoopRawMutex, S>) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        loop {
            let mut tx = self.get_if(&self.tx, |packet| !packet.buf.is_empty()).await;
            tx.clear_on_drop(true);

            Self::netw_send(send, tx.peer, &tx.buf[tx.payload_start..], false).await?;
        }
    }

    async fn process_rx<R, S>(
        &self,
        mut recv: R,
        send: &IfMutex<NoopRawMutex, S>,
    ) -> Result<(), Error>
    where
        R: NetworkReceive,
        S: NetworkSend,
    {
        loop {
            info!("Waiting for incoming packet");

            recv.wait_available().await?;

            let mut rx = self.get_if(&self.rx, |packet| packet.buf.is_empty()).await;
            rx.clear_on_drop(true); // In case of error, or if the future is dropped

            rx.buf.resize_default(MAX_RX_BUF_SIZE).unwrap();
            let (len, peer) = Self::netw_recv(&mut recv, &mut rx.buf).await?;

            rx.peer = peer;
            rx.buf.truncate(len);
            rx.payload_start = 0;

            match self.handle_rx_packet(&mut rx, send).await {
                Ok(true) => {
                    // Leave the packet in place for accepting by responders
                    rx.clear_on_drop(false);
                }
                Ok(false) => {
                    // Drop the packet, as no further processing is necessary
                }
                Err(e) => {
                    // Drop the packet and report the unexpected error
                    error!("UNEXPECTED RX ERROR: {e:?}");
                }
            }
        }
    }

    async fn process_orphaned(&self) -> Result<(), Error> {
        let mut rx_accept_timeout = pin!(self.process_accept_timeout_rx());
        let mut rx_orphaned = pin!(self.process_orphaned_rx());
        let mut exch_orphaned = pin!(self.process_orphaned_exchanges());

        select3(&mut rx_accept_timeout, &mut rx_orphaned, &mut exch_orphaned)
            .await
            .unwrap()
    }

    async fn process_accept_timeout_rx(&self) -> Result<(), Error> {
        loop {
            //info!("Waiting for accept timeout");

            let accept_timeout = self.with_locked(&self.rx, |packet| {
                self.handle_accept_timeout_rx_packet(packet).then_some(())
            });

            let timer = Timer::after(embassy_time::Duration::from_millis(50));

            select(accept_timeout, timer).await;
        }
    }

    async fn process_orphaned_rx(&self) -> Result<(), Error> {
        loop {
            info!("Waiting for orphaned RX packets");

            self.with_locked(&self.rx, |packet| {
                self.handle_orphaned_rx_packet(packet).then_some(())
            })
            .await;
        }
    }

    async fn process_orphaned_exchanges(&self) -> Result<(), Error> {
        loop {
            //info!("Waiting for orphaned exchanges");

            let mut tx = self.get_if(&self.tx, |packet| packet.buf.is_empty()).await;
            tx.clear_on_drop(true); // In case of error, or if the future is dropped

            let wait = match self.handle_orphaned_exchange(&mut tx) {
                Ok(wait) => {
                    tx.clear_on_drop(false);
                    wait
                }
                Err(e) => {
                    error!("UNEXPECTED RX ERROR: {e:?}");
                    false
                }
            };

            drop(tx);

            if wait {
                select(
                    Timer::after(embassy_time::Duration::from_millis(100)),
                    self.orphaned.wait(),
                )
                .await;
            }
        }
    }

    async fn handle_rx_packet<const N: usize, S>(
        &self,
        packet: &mut Packet<N>,
        send: &IfMutex<NoopRawMutex, S>,
    ) -> Result<bool, Error>
    where
        S: NetworkSend,
    {
        let result = self.decode_packet(packet);
        match result {
            Err(e) if matches!(e.code(), ErrorCode::Duplicate) => {
                info!("\n>>>>> {packet}\n => Duplicate, sending ACK");

                {
                    let mut session_mgr = self.session_mgr.borrow_mut();
                    let epoch = session_mgr.epoch;
                    let session = session_mgr
                        .get_for(&packet.peer, &packet.header.plain)
                        .unwrap();

                    let ack = packet.header.plain.ctr;

                    packet.header.proto.unset_initiator();
                    packet.header.proto.set_ack(Some(ack));

                    self.encode_packet(packet, Some(session), None, epoch, |_| {
                        Ok(OpCode::MRPStandAloneAck.into())
                    })?;
                }

                Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                    .await?;
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceSessions) => {
                if !packet.header.plain.is_encrypted()
                    && packet.header.proto.proto_id == PROTO_ID_SECURE_CHANNEL
                    && (packet.header.proto.proto_opcode == OpCode::PBKDFParamRequest as u8
                        || packet.header.proto.proto_opcode == OpCode::CASESigma1 as u8)
                {
                    error!("\n>>>>> {packet}\n => No space for a new session, sending Busy");

                    let ack = packet.header.plain.ctr;

                    packet.header.proto.unset_initiator();
                    packet.header.proto.set_ack(Some(ack));

                    self.encode_packet(
                        packet,
                        None,
                        None,
                        self.session_mgr.borrow().epoch,
                        |wb| sc_write(wb, SCStatusCodes::Busy, Some(&[0xF4, 0x01])),
                    )?;

                    Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                        .await?;

                    if self.encode_evict_some_session(packet)? {
                        Self::netw_send(
                            send,
                            packet.peer,
                            &packet.buf[packet.payload_start..],
                            true,
                        )
                        .await?;
                    }
                } else {
                    error!("\n>>>>> {packet}\n => No space for a new session, dropping");
                }
            }
            Err(e) if matches!(e.code(), ErrorCode::NoSpaceExchanges) => {
                // TODO: Before closing the session, try to take other measures:
                // - For CASESigma1 & PBKDFParamRequest - send Busy instead
                // - For Interaction Model interactions that do need an ACK - send IM Busy,
                //   wait for ACK and retransmit without releasing the RX buffer, potentially
                //   blocking all other interactions

                error!("\n>>>>> {packet}\n => No space for a new exchange, closing session");

                {
                    let mut session_mgr = self.session_mgr.borrow_mut();
                    let session_id = session_mgr
                        .get_for(&packet.peer, &packet.header.plain)
                        .unwrap()
                        .id;

                    packet.header.proto.exch_id = session_mgr.get_next_exch_id();
                    packet.header.proto.set_initiator();

                    let mut session = session_mgr.remove(session_id).unwrap();

                    self.encode_packet(
                        packet,
                        Some(&mut session),
                        None,
                        session_mgr.epoch,
                        |wb| sc_write(wb, SCStatusCodes::CloseSession, None),
                    )?;
                }

                Self::netw_send(send, packet.peer, &packet.buf[packet.payload_start..], true)
                    .await?;
            }
            Err(e) => {
                error!("\n>>>>> {packet}\n => Error ({e:?}), dropping");
            }
            Ok(new_exchange) => {
                if packet.header.proto.proto_id == PROTO_ID_SECURE_CHANNEL
                    && packet.header.proto.proto_opcode == OpCode::MRPStandAloneAck as u8
                {
                    // No need to propagate this further
                    info!("\n>>>>> {packet}\n => Standalone Ack, dropping");
                } else {
                    info!(
                        "\n>>>>> {packet}\n => Processing{}",
                        if new_exchange { " (new exchange)" } else { "" }
                    );

                    debug!(
                        "{}",
                        Packet::<0>::display_payload(
                            &packet.header.proto,
                            &packet.buf[core::cmp::min(packet.payload_start, packet.buf.len())..]
                        )
                    );

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn handle_accept_timeout_rx_packet<const N: usize>(&self, packet: &mut Packet<N>) -> bool {
        if !packet.buf.is_empty() {
            let mut session_mgr = self.session_mgr.borrow_mut();
            let epoch = session_mgr.epoch;
            if let Some(session) = session_mgr.get_for(&packet.peer, &packet.header.plain) {
                if let Some(exchange_index) = session.get_exchange_index_for(&packet.header.proto) {
                    let exchange = session.exchanges[exchange_index].as_mut().unwrap();

                    if matches!(exchange.owned_state, OwnedState::NotAccepted)
                        && exchange
                            .mrp
                            .ack
                            .as_mut()
                            .map(|ack| ack.has_timed_out(ACCEPT_TIMEOUT_MS, epoch))
                            .unwrap_or(false)
                    {
                        warn!("\n----- {packet}\n => Accept timeout, marking as orphaned");

                        exchange.owned_state = OwnedState::Orphaned;
                        packet.buf.clear();
                        self.orphaned.signal(());

                        return true;
                    }
                }
            }
        }

        false
    }

    fn handle_orphaned_rx_packet<const N: usize>(&self, packet: &mut Packet<N>) -> bool {
        if !packet.buf.is_empty() {
            let mut session_mgr = self.session_mgr.borrow_mut();
            if let Some(session) = session_mgr.get_for(&packet.peer, &packet.header.plain) {
                if let Some(exchange_index) = session.get_exchange_index_for(&packet.header.proto) {
                    let exchange = session.exchanges[exchange_index].as_mut().unwrap();

                    if matches!(
                        exchange.owned_state,
                        OwnedState::Orphaned | OwnedState::OrphanedClosing
                    ) {
                        warn!(
                            "\n----- {packet}\n => Owned by orphaned exchange {}, dropping",
                            ExchangeId::new(session.id, exchange_index)
                        );

                        exchange.owned_state = OwnedState::Orphaned;

                        packet.buf.clear();
                        return true;
                    }
                } else {
                    warn!("\n----- {packet}\n => No exchange, dropping");

                    packet.buf.clear();
                    return true;
                }
            } else {
                warn!("\n----- {packet}\n => No session, dropping");

                packet.buf.clear();
                return true;
            }
        }

        false
    }

    fn handle_orphaned_exchange<const N: usize>(
        &self,
        packet: &mut Packet<N>,
    ) -> Result<bool, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();
        let epoch = session_mgr.epoch;

        let exch = session_mgr
            .get_exch(|_, exch| {
                matches!(exch.owned_state, OwnedState::Orphaned) && exch.is_retrans()
            })
            .map(|(sess, exch_index)| (sess.id, exch_index, true))
            .or_else(|| {
                session_mgr
                    .get_exch(|_, exch| {
                        matches!(exch.owned_state, OwnedState::Orphaned) && !exch.is_retrans()
                            || matches!(exch.owned_state, OwnedState::OrphanedClosing)
                                && exch.is_retrans_due(epoch)
                    })
                    .map(|(sess, exch_index)| (sess.id, exch_index, false))
            });

        if let Some((session_id, exch_index, close_session)) = exch {
            let exchange_id = ExchangeId::new(session_id, exch_index);

            if close_session {
                // Found an orphaned exchange that cannot be completed cleanly
                // Close the whole session

                error!(
                    "Orphaned exchange {exchange_id}: Closing session because the exchange cannot be closed cleanly"
                );

                self.encode_evict_session(packet, &mut session_mgr, session_id)?;
            } else {
                // Found an orphaned exchange that can be completed cleanly
                // Figure out the right reply and send it with re-transmission

                warn!("Orphaned exchange {exchange_id}: Closing");

                let epoch = session_mgr.epoch;
                let session = session_mgr.get(session_id).unwrap();
                let exchange = session.exchanges[exch_index].as_mut().unwrap();

                if matches!(exchange.owned_state, OwnedState::OrphanedClosing)
                    && !exchange.is_retrans()
                {
                    session.exchanges[exch_index] = None;
                    warn!("Orphaned exchange {exchange_id}: Closed");
                } else if let Some(meta) = exchange.last_received {
                    self.encode_orphaned_close_resp(packet, session, exch_index, epoch, meta)?;

                    let exchange = session.exchanges[exch_index].as_mut().unwrap();
                    if !exchange.is_retrans() {
                        session.exchanges[exch_index] = None;
                        warn!("Orphaned exchange {exchange_id}: Closed");
                    } else {
                        exchange.owned_state = OwnedState::OrphanedClosing;
                    }
                } else {
                    unreachable!("Orphaned exchange {exchange_id}: Should not happen");
                }
            }
        }

        Ok(exch.is_none())
    }

    pub(crate) async fn evict_some_session(&self) -> Result<(), Error> {
        let mut tx = self.get_if(&self.tx, |packet| packet.buf.is_empty()).await;
        tx.clear_on_drop(true); // By default, if an error occurs

        let evicted = self.encode_evict_some_session(&mut tx)?;

        if evicted {
            // Send it
            tx.clear_on_drop(false);

            Ok(())
        } else {
            Err(ErrorCode::NoSpaceSessions.into())
        }
    }

    fn decode_packet<const N: usize>(&self, packet: &mut Packet<N>) -> Result<bool, Error> {
        packet.header.reset();

        let mut pb = ParseBuf::new(&mut packet.buf[packet.payload_start..]);
        packet.header.plain.decode(&mut pb)?;

        let mut session_mgr = self.session_mgr.borrow_mut();
        let epoch = session_mgr.epoch;

        let res = if let Some(session) = session_mgr.get_for(&packet.peer, &packet.header.plain) {
            session.post_recv(&mut packet.header, &mut pb, epoch)
        } else if !packet.header.plain.is_encrypted() {
            let mut session =
                session_mgr.add(false, packet.peer, packet.header.plain.get_src_nodeid());

            if let Some(session) = session.as_mut() {
                session.post_recv(&mut packet.header, &mut pb, epoch)
            } else {
                packet.header.decode_remaining(&mut pb, 0, None)?;

                Err(ErrorCode::NoSpaceSessions.into())
            }
        } else {
            Err(ErrorCode::NoSession.into())
        };

        let range = pb.slice_range();
        packet.payload_start = range.0;
        packet.buf.truncate(range.1);

        res
    }

    fn encode_packet<const N: usize, F>(
        &self,
        packet: &mut Packet<N>,
        mut session: Option<&mut Session>,
        exchange_index: Option<usize>,
        epoch: Epoch,
        payload_writer: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&mut WriteBuf) -> Result<ExchangeMeta, Error>,
    {
        packet.buf.resize_default(N).unwrap();

        let mut wb = WriteBuf::new(&mut packet.buf);
        wb.reserve(PacketHdr::HDR_RESERVE)?;

        payload_writer(&mut wb)?.set_into(&mut packet.header.proto);

        let retransmission = if let Some(session) = &mut session {
            packet.header.plain = Default::default();

            let (peer, retransmission) =
                session.pre_send(exchange_index, &mut packet.header, epoch)?;

            packet.peer = peer;

            retransmission
        } else {
            if packet.header.plain.is_encrypted()
                || packet.header.plain.get_src_nodeid().is_none()
                || packet.header.proto.is_reliable()
            {
                // We can encode packets without a session only when they are unencrypted and do not need a retransmission
                Err(ErrorCode::NoSession)?;
            }

            let src_nodeid = packet.header.plain.get_src_nodeid();

            packet.header.plain = Default::default();

            packet.header.plain.sess_id = 0;
            packet.header.plain.ctr = 1;
            packet.header.plain.set_src_nodeid(None);
            packet.header.plain.set_dst_unicast_nodeid(src_nodeid);

            packet.header.proto.unset_initiator();

            false
        };

        info!(
            "\n<<<<< {}\n => {} (system)",
            Packet::<0>::display(&packet.peer, &packet.header),
            if retransmission {
                "Re-sending"
            } else {
                "Sending"
            }
        );

        debug!(
            "{}",
            Packet::<0>::display_payload(&packet.header.proto, wb.as_slice())
        );

        if let Some(session) = session {
            session.encode(&packet.header, &mut wb)?;
        } else {
            packet.header.encode(&mut wb, 0, None)?;
        }

        let range = (wb.get_start(), wb.get_tail());

        packet.payload_start = range.0;
        packet.buf.truncate(range.1);

        Ok(())
    }

    fn encode_orphaned_close_resp<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        session: &mut Session,
        exchange_index: usize,
        epoch: Epoch,
        meta: ExchangeMeta,
    ) -> Result<(), Error> {
        self.encode_packet(packet, Some(session), Some(exchange_index), epoch, |wb| {
            let meta = if meta.proto_id == PROTO_ID_SECURE_CHANNEL {
                match meta.opcode()? {
                    OpCode::PBKDFParamRequest | OpCode::CASESigma1 => {
                        // Send Busy, as per section 4.10.1.5 of the Matter spec
                        sc_write(wb, SCStatusCodes::Busy, Some(&[0xF4, 0x01]))?
                    }
                    _ => {
                        // Send InvalidParameter, as there seems to be no other suitable status code
                        sc_write(wb, SCStatusCodes::InvalidParameter, None)?
                    }
                }
            } else if meta.proto_id == PROTO_ID_INTERACTION_MODEL {
                // Identical behavior to https://github.com/project-chip/connectedhomeip/pull/11667
                let status = match meta.opcode()? {
                    interaction_model::core::OpCode::SubscribeRequest => IMStatusCode::Busy,
                    interaction_model::core::OpCode::ReadRequest
                    | interaction_model::core::OpCode::WriteRequest
                    | interaction_model::core::OpCode::InvokeRequest => IMStatusCode::Busy,
                    _ => IMStatusCode::Failure,
                };

                StatusResp::write(wb, status)?;

                interaction_model::core::OpCode::StatusResponse.meta()
            } else {
                Err(ErrorCode::Invalid)? // TODO
            };

            Ok(meta)
        })
    }

    fn encode_evict_some_session<const N: usize>(
        &self,
        packet: &mut Packet<N>,
    ) -> Result<bool, Error> {
        let mut session_mgr = self.session_mgr.borrow_mut();
        let id = session_mgr.get_session_for_eviction().map(|sess| sess.id);
        if let Some(id) = id {
            self.encode_evict_session(packet, &mut session_mgr, id)?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn encode_evict_session<const N: usize>(
        &self,
        packet: &mut Packet<N>,
        session_mgr: &mut SessionMgr,
        id: u32,
    ) -> Result<(), Error> {
        packet.header.proto.exch_id = session_mgr.get_next_exch_id();
        packet.header.proto.set_initiator();

        let mut session = session_mgr.remove(id).unwrap();

        self.encode_packet(packet, Some(&mut session), None, session_mgr.epoch, |wb| {
            sc_write(wb, SCStatusCodes::CloseSession, None)
        })?;

        Ok(())
    }

    async fn netw_recv<R>(mut recv: R, buf: &mut [u8]) -> Result<(usize, Address), Error>
    where
        R: NetworkReceive,
    {
        match recv.recv_from(buf).await {
            Ok((len, addr)) => {
                debug!("\n>>>>> {} {}B:\n{:02x?}", addr, len, &buf[..len]);

                Ok((len, addr))
            }
            Err(e) => {
                error!("FAILED network recv: {e:?}");

                Err(e)
            }
        }
    }

    async fn netw_send<S>(
        send: &IfMutex<NoopRawMutex, S>,
        peer: Address,
        data: &[u8],
        system: bool,
    ) -> Result<(), Error>
    where
        S: NetworkSend,
    {
        match send.lock().await.send_to(data, peer).await {
            Ok(_) => {
                debug!(
                    "\n<<<<< {} {}B{}: {:02x?}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    data
                );

                Ok(())
            }
            Err(e) => {
                error!(
                    "\n<<<<< {} {}B{} !FAILED!: {e:?}: {:02x?}",
                    peer,
                    data.len(),
                    if system { " (system)" } else { "" },
                    data
                );

                Err(e)
            }
        }
    }
}
