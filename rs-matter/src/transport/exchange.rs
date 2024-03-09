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

use core::fmt::{self, Display};

use embassy_futures::select::select;
use embassy_time::Timer;

use log::{debug, info, warn};

use crate::acl::Accessor;
use crate::error::{Error, ErrorCode};
use crate::interaction_model::{self, core::PROTO_ID_INTERACTION_MODEL};
use crate::secure_channel::{self, common::PROTO_ID_SECURE_CHANNEL};
use crate::utils::{epoch::Epoch, writebuf::WriteBuf};
use crate::Matter;

use super::core::{Packet, PacketAccess};
use super::mrp::{ReliableMessage, RetransEntry};
use super::network::Address;
use super::packet::{PacketHdr, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE};
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;
use super::session::Session;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExchangeId(u32);

impl ExchangeId {
    pub fn new(session_id: u32, exchange_index: usize) -> Self {
        if exchange_index >= 16 {
            panic!("Exchange index out of range");
        }

        Self((exchange_index as u32) << 28 | session_id)
    }

    pub fn session_id(&self) -> u32 {
        self.0 & 0x0fff_ffff
    }

    pub fn exchange_index(&self) -> usize {
        (self.0 >> 28) as _
    }
}

impl Display for ExchangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.session_id(), self.exchange_index())
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub(crate) enum Role {
    #[default]
    Initiator = 0,
    Responder = 1,
}

impl Role {
    pub fn complementary(is_initiator: bool) -> Self {
        if is_initiator {
            Self::Responder
        } else {
            Self::Initiator
        }
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub(crate) enum OwnedState {
    NotAccepted,
    Owned,
    Closed,
    Orphaned,
    OrphanedClosing,
}

#[derive(Debug)]
pub(crate) struct ExchangeState {
    pub(crate) exch_id: u16,
    pub(crate) role: Role,
    pub(crate) owned_state: OwnedState,
    pub(crate) last_received: Option<ExchangeMeta>,
    pub(crate) mrp: ReliableMessage,
}

impl ExchangeState {
    pub fn is_for(&self, proto: &ProtoHdr) -> bool {
        self.exch_id == proto.exch_id && self.role == Role::complementary(proto.is_initiator())
    }

    pub fn is_closable(&self) -> bool {
        self.mrp.ack.is_none()
            && self.mrp.retrans.is_none()
            && self
                .last_received
                .map(|meta| !meta.reliable)
                .unwrap_or(true)
    }

    pub fn is_retrans(&self) -> bool {
        self.mrp.retrans.is_some()
    }

    pub fn is_retrans_due(&self, epoch: Epoch) -> bool {
        self.mrp
            .retrans
            .as_ref()
            .map(|retrans| retrans.is_due(epoch))
            .unwrap_or(true)
    }

    pub fn post_recv(
        &mut self,
        plain: &PlainHdr,
        proto: &ProtoHdr,
        epoch: Epoch,
    ) -> Result<(), Error> {
        self.mrp.post_recv(plain, proto, epoch)?;
        self.last_received = Some(ExchangeMeta::from(proto));

        Ok(())
    }

    pub fn pre_send(
        &mut self,
        plain: &PlainHdr,
        proto: &mut ProtoHdr,
        epoch: Epoch,
    ) -> Result<(), Error> {
        if matches!(self.role, Role::Initiator) {
            proto.set_initiator();
        } else {
            proto.unset_initiator();
        }

        proto.exch_id = self.exch_id;

        self.mrp.pre_send(plain, proto, epoch)
    }

    pub fn retrans_delay_ms(&mut self) -> Option<u64> {
        self.mrp.retrans().map(RetransEntry::delay_ms)
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct ExchangeMeta {
    pub proto_id: u16,
    pub proto_opcode: u8,
    pub reliable: bool,
}

impl ExchangeMeta {
    pub const fn new(proto_id: u16, proto_opcode: u8, reliable: bool) -> Self {
        Self {
            proto_id,
            proto_opcode,
            reliable,
        }
    }

    pub fn opcode<T: num::FromPrimitive>(&self) -> Result<T, Error> {
        num::FromPrimitive::from_u8(self.proto_opcode).ok_or(ErrorCode::Invalid.into())
    }

    pub fn check_opcode<T: num::FromPrimitive + PartialEq>(&self, opcode: T) -> Result<(), Error> {
        if self.opcode::<T>()? == opcode {
            Ok(())
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub fn from(proto: &ProtoHdr) -> Self {
        Self {
            proto_id: proto.proto_id,
            proto_opcode: proto.proto_opcode,
            reliable: proto.is_reliable(),
        }
    }

    pub fn set_into(&self, proto: &mut ProtoHdr) {
        proto.proto_id = self.proto_id;
        proto.proto_opcode = self.proto_opcode;
        proto.set_vendor(None);

        if self.reliable {
            proto.set_reliable();
        } else {
            proto.unset_reliable();
        }
    }

    pub fn reliable(self, reliable: bool) -> Self {
        Self { reliable, ..self }
    }

    pub fn is_tlv(&self) -> bool {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => self
                .opcode::<secure_channel::common::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            PROTO_ID_INTERACTION_MODEL => self
                .opcode::<interaction_model::core::OpCode>()
                .ok()
                .map(|op| op.is_tlv())
                .unwrap_or(false),
            _ => false,
        }
    }
}

impl Display for ExchangeMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                if let Ok(opcode) = self.opcode::<secure_channel::common::OpCode>() {
                    write!(f, "SC::{:?}", opcode)
                } else {
                    write!(f, "SC::{:02x}", self.proto_opcode)
                }
            }
            PROTO_ID_INTERACTION_MODEL => {
                if let Ok(opcode) = self.opcode::<interaction_model::core::OpCode>() {
                    write!(f, "IM::{:?}", opcode)
                } else {
                    write!(f, "IM::{:02x}", self.proto_opcode)
                }
            }
            _ => write!(f, "{:02x}::{:02x}", self.proto_id, self.proto_opcode),
        }
    }
}

pub struct Rx<'a, 'b> {
    exchange: &'a Exchange<'a>,
    packet: PacketAccess<'b, MAX_RX_BUF_SIZE>,
    consumed: bool,
}

impl<'a, 'b> Rx<'a, 'b> {
    pub fn meta(&self) -> ExchangeMeta {
        ExchangeMeta::from(&self.packet.packet_ref().header.proto)
    }

    pub fn payload(&self) -> &[u8] {
        &self.packet.packet_ref().buf[self.packet.packet_ref().payload_start..]
    }

    pub fn consume(&mut self) -> &mut Self {
        self.consumed = true;
        self
    }

    pub fn exchange(&self) -> &Exchange<'a> {
        self.exchange
    }
}

impl<'a, 'b> Drop for Rx<'a, 'b> {
    fn drop(&mut self) {
        if self.consumed {
            self.packet.buf.clear();
        }
    }
}

pub struct Tx<'a, 'b> {
    exchange: &'a Exchange<'a>,
    packet: PacketAccess<'b, MAX_TX_BUF_SIZE>,
    completed: Option<(usize, usize)>,
}

impl<'a, 'b> Tx<'a, 'b> {
    pub fn payload(&mut self) -> Result<TxPayload<'a, '_>, Error> {
        self.completed = None;

        let packet = self.packet.packet_mut();
        packet.buf.resize_default(MAX_TX_BUF_SIZE).unwrap();

        let mut writebuf = WriteBuf::new(&mut packet.buf);
        writebuf.reserve(PacketHdr::HDR_RESERVE)?;

        Ok(TxPayload {
            exchange: self.exchange,
            header: &mut packet.header,
            peer: &mut packet.peer,
            writebuf,
            completed: &mut self.completed,
        })
    }
}

impl<'a, 'b> Drop for Tx<'a, 'b> {
    fn drop(&mut self) {
        if let Some((start, end)) = self.completed {
            self.packet.payload_start = start;
            self.packet.buf.truncate(end);
        } else {
            self.packet.buf.clear();
        }
    }
}

pub struct TxPayload<'a, 'b> {
    exchange: &'a Exchange<'a>,
    header: &'b mut PacketHdr,
    peer: &'b mut Address,
    writebuf: WriteBuf<'b>,
    completed: &'b mut Option<(usize, usize)>,
}

impl<'a, 'b> TxPayload<'a, 'b> {
    pub fn writebuf(&mut self) -> &mut WriteBuf<'b> {
        &mut self.writebuf
    }

    pub fn complete(mut self, meta: impl Into<ExchangeMeta>) -> Result<bool, Error> {
        let meta: ExchangeMeta = meta.into();

        self.header.reset();

        meta.set_into(&mut self.header.proto);

        let mut session_mgr = self.exchange.matter.transport_mgr.session_mgr.borrow_mut();

        let session = session_mgr
            .get(self.exchange.id.session_id())
            .ok_or(ErrorCode::NoSession)?;

        *self.peer = session.pre_send(
            Some(self.exchange.id.exchange_index()),
            self.header,
            self.exchange.matter.epoch,
        )?;

        if self.header.proto.is_reliable()
            || self.header.proto.proto_id != PROTO_ID_SECURE_CHANNEL
            || self.header.proto.proto_opcode
                != secure_channel::common::OpCode::MRPStandAloneAck as u8
            || self.header.proto.get_ack().is_none()
        {
            info!(
                "<<< {} => Sending",
                Packet::<0>::display(self.peer, self.header)
            );

            debug!(
                "{}",
                Packet::<0>::display_payload(&self.header.proto, self.writebuf.as_slice())
            );

            session.encode(self.header, &mut self.writebuf)?;

            *self.completed = Some((self.writebuf.get_start(), self.writebuf.get_tail()));

            Ok(true)
        } else {
            // No need to send a standalone ACK when there is nothing to acknowledge
            *self.completed = None;
            Ok(false)
        }
    }
}

pub struct Exchange<'a> {
    id: ExchangeId,
    matter: &'a Matter<'a>,
}

impl<'a> Exchange<'a> {
    pub(crate) const fn new(id: ExchangeId, matter: &'a Matter<'a>) -> Self {
        Self { id, matter }
    }

    pub fn id(&self) -> ExchangeId {
        self.id
    }

    pub fn matter(&self) -> &'a Matter<'a> {
        self.matter
    }

    /// TODO: This signature will change in future
    pub async fn initiate(matter: &'a Matter<'a>, session_id: u32) -> Result<Self, Error> {
        matter.transport_mgr.initiate(matter, session_id).await
    }

    pub async fn accept(matter: &'a Matter<'a>) -> Result<Self, Error> {
        matter.transport_mgr.accept(matter).await
    }

    pub async fn rx(&mut self) -> Result<Rx<'_, 'a>, Error> {
        self.with_ctx(|_, _| Ok(()))?;

        let transport_mgr = &self.matter.transport_mgr;

        let packet = transport_mgr
            .get_if(&transport_mgr.rx, |packet| {
                if packet.buf.is_empty() {
                    false
                } else {
                    let for_us = self.with_ctx(|sess, exch_index| {
                        if sess.is_for(&packet.peer, &packet.header.plain) {
                            let exchange = sess.exchanges[exch_index].as_ref().unwrap();

                            return Ok(exchange.is_for(&packet.header.proto));
                        }

                        Ok(false)
                    });

                    for_us.unwrap_or(true)
                }
            })
            .await;

        self.with_ctx(|_, _| Ok(()))?;

        let rx = Rx {
            exchange: self,
            packet,
            consumed: false,
        };

        Ok(rx)
    }

    pub async fn recv(&mut self) -> Result<Rx<'_, 'a>, Error> {
        let mut rx = self.rx().await?;

        rx.consume();

        Ok(rx)
    }

    pub async fn recv_into(&mut self, wb: &mut WriteBuf<'_>) -> Result<ExchangeMeta, Error> {
        let rx = self.recv().await?;

        wb.reset();
        wb.append(rx.payload())?;

        Ok(rx.meta())
    }

    pub async fn tx(&mut self) -> Result<Tx<'_, 'a>, Error> {
        self.with_ctx(|_, _| Ok(()))?;

        let transport_mgr = &self.matter.transport_mgr;

        let packet = transport_mgr
            .get_if(&transport_mgr.tx, |packet| {
                packet.buf.is_empty() || self.with_ctx(|_, _| Ok(())).is_err()
            })
            .await;

        self.with_ctx(|_, _| Ok(()))?;

        let tx = Tx {
            exchange: self,
            packet,
            completed: None,
        };

        Ok(tx)
    }

    pub async fn wait_ack(&mut self) -> Result<bool, Error> {
        if let Some(delay) = self.retrans_delay_ms()? {
            let notification = self.internal_wait_ack();
            let timer = Timer::after(embassy_time::Duration::from_millis(delay));

            select(notification, timer).await;

            Ok(self.retrans_delay_ms()?.is_none())
        } else {
            Ok(true)
        }
    }

    pub async fn acknowledge(&mut self) -> Result<(), Error> {
        self.send_with(|_| Ok(secure_channel::common::OpCode::MRPStandAloneAck.into()))
            .await
    }

    pub async fn send_with<F>(&mut self, mut f: F) -> Result<(), Error>
    where
        F: FnMut(&mut WriteBuf) -> Result<ExchangeMeta, Error>,
    {
        let mut retrans = false;

        loop {
            let reliable = {
                let mut tx = self.tx().await?;

                if !retrans || tx.exchange.retrans_delay_ms()?.is_some() {
                    let mut payload = tx.payload()?;

                    let meta = f(payload.writebuf())?;

                    if !payload.complete(meta)? {
                        break;
                    }

                    meta.reliable
                } else {
                    break;
                }
            };

            if !reliable || self.wait_ack().await? {
                break;
            }

            retrans = true;
        }

        Ok(())
    }

    pub async fn send(
        &mut self,
        meta: impl Into<ExchangeMeta>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let meta = meta.into();

        self.send_with(|wb| {
            wb.append(payload)?;

            Ok(meta)
        })
        .await
    }

    pub async fn close(mut self) -> Result<(), Error> {
        self.acknowledge().await?;

        self.with_ctx(|sess, exch_index| {
            let exchange = sess.exchanges[exch_index].as_mut().unwrap();

            if exchange.is_closable() {
                exchange.owned_state = OwnedState::Closed;

                Ok(())
            } else {
                warn!("Exchange {}: Cannot be closed yet", self.id);
                Err(ErrorCode::InvalidState.into())
            }
        })
    }

    pub(crate) fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.with_session(|sess| Ok(Accessor::for_session(sess, &self.matter.acl_mgr)))
    }

    pub(crate) fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(|sess, _| f(sess))
    }

    pub(crate) fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session, usize) -> Result<T, Error>,
    {
        let mut session_mgr = self.matter.transport_mgr.session_mgr.borrow_mut();

        if let Some(session) = session_mgr.get(self.id.session_id()) {
            f(session, self.id.exchange_index())
        } else {
            warn!("Exchange {}: No session", self.id);
            Err(ErrorCode::NoSession.into())
        }
    }

    async fn internal_wait_ack(&self) -> Result<(), Error> {
        let transport_mgr = &self.matter.transport_mgr;

        transport_mgr
            .get_if(&transport_mgr.rx, |_| {
                self.retrans_delay_ms()
                    .map(|retrans| retrans.is_none())
                    .unwrap_or(true)
            })
            .await;

        self.with_ctx(|_, _| Ok(()))
    }

    fn retrans_delay_ms(&self) -> Result<Option<u64>, Error> {
        self.with_ctx(|sess, exch_index| {
            let exchange = sess.exchanges[exch_index].as_mut().unwrap();

            Ok(exchange.retrans_delay_ms())
        })
    }
}

impl<'a> Drop for Exchange<'a> {
    fn drop(&mut self) {
        let closed = self.with_ctx(|sess, exch_index| Ok(sess.close_exchange(exch_index)));

        if !matches!(closed, Ok(true)) {
            self.matter.transport_mgr.orphaned.signal(());
        }
    }
}

impl<'a> Display for Exchange<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.id)
    }
}
