use core::num::NonZeroUsize;

use embassy_futures::select::select;
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use embassy_time::{Duration, Timer};

use log::info;

use crate::{
    acl::Accessor,
    error::{Error, ErrorCode},
    utils::{
        epoch::Epoch,
        notification::{DataCarrier, Notification},
        writebuf::WriteBuf,
    },
    Matter,
};

use super::{
    mrp::ReliableMessage,
    network::Address,
    packet::{PacketHeader, MAX_RX_BUF_SIZE, MAX_TX_BUF_SIZE},
    plain_hdr::PlainHdr,
    proto_hdr::ProtoHdr,
    session::{Session, SessionId},
};

pub const MAX_EXCHANGES: usize = 8;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ExchangeId {
    pub id: u16,
    pub session_id: SessionId,
}

impl ExchangeId {
    pub fn load(exch_id: u16, peer: Address, plain: &PlainHdr) -> Self {
        Self {
            id: exch_id,
            session_id: SessionId::load(peer, plain),
        }
    }

    pub fn matches(&self, exch_id: u16, peer: &Address, plain: &PlainHdr) -> bool {
        self.id == exch_id && self.session_id.matches(peer, plain)
    }
}

pub struct ExchangeEntry {
    id: ExchangeId,
    role: Role,
    mrp: ReliableMessage,
}

impl ExchangeEntry {
    pub fn recv(&mut self, header: &PacketHeader, epoch: Epoch) {
        self.mrp.recv(header, epoch);
    }

    pub fn pre_send(&mut self, plain: &PlainHdr, proto: &mut ProtoHdr) -> Result<(), Error> {
        self.mrp.pre_send(plain, proto)
    }
}

pub struct ExchangeMgr {
    exchanges: heapless::Vec<ExchangeEntry, MAX_EXCHANGES>,
    epoch: Epoch,
}

impl ExchangeMgr {
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            exchanges: heapless::Vec::new(),
            epoch,
        }
    }

    pub fn reset(&mut self) {
        self.exchanges.clear();
    }

    pub fn get(&mut self, id: &ExchangeId) -> Option<&mut ExchangeEntry> {
        self.exchanges
            .iter_mut()
            .find(|exchange| exchange.id == *id)
    }

    pub fn is_full(&self) -> bool {
        self.exchanges.is_full()
    }

    pub fn add(&mut self, id: ExchangeId, role: Role) -> Option<&mut ExchangeEntry> {
        info!("Creating new exchange: {:?}", id);

        self.exchanges
            .push(ExchangeEntry {
                id,
                role,
                mrp: ReliableMessage::new(),
            })
            .ok()?;

        Some(self.exchanges.last_mut().unwrap())
    }

    pub fn remove(&mut self, id: &ExchangeId) {
        info!("Removing exchange: {:?}", id);

        let index = self.exchanges.iter_mut().position(|ctx| ctx.id == *id);

        if let Some(index) = index {
            self.exchanges.swap_remove(index);
        }
    }
}

pub struct ExchangeCtx<'a> {
    pub exchange: &'a mut ExchangeEntry,
    pub session: &'a mut Session,
}

impl<'a> ExchangeCtx<'a> {
    pub fn id(&self) -> &ExchangeId {
        &self.exchange.id
    }

    pub fn peer(&self) -> Address {
        self.session.get_peer_addr()
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

    pub fn check_opcode<T: num::FromPrimitive>(&self, opcode: T) -> Result<(), Error> {
        if matches!(self.opcode::<T>()?, opcode) {
            Ok(())
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    fn from(proto: &ProtoHdr) -> Self {
        Self {
            proto_id: proto.proto_id,
            proto_opcode: proto.proto_opcode,
            reliable: proto.is_reliable(),
        }
    }

    pub(crate) fn set_into(&self, proto: &mut ProtoHdr) {
        proto.proto_id = self.proto_id;
        proto.proto_opcode = self.proto_opcode;

        if self.reliable {
            proto.set_reliable();
        } else {
            proto.unset_reliable();
        }
    }
}

pub(crate) type RxExchangePacket = ExchangePacket<MAX_RX_BUF_SIZE>;
pub(crate) type TxExchangePacket = ExchangePacket<MAX_TX_BUF_SIZE>;

pub(crate) struct ExchangePacket<const N: usize> {
    pub(crate) new_exchange: bool,
    pub(crate) peer: Address,
    pub(crate) header: PacketHeader,
    pub(crate) buf: heapless::Vec<u8, MAX_RX_BUF_SIZE>,
    pub(crate) payload_start: usize,
}

impl<const N: usize> ExchangePacket<N> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            new_exchange: false,
            peer: Address::default(),
            header: PacketHeader::new(),
            buf: heapless::Vec::new(),
            payload_start: 0,
        }
    }
}

pub struct Rx<'a, 'b> {
    id: &'a ExchangeId,
    matter: &'a Matter<'a>,
    dc: DataCarrier<'b, RxExchangePacket>,
    consumed: bool,
}

impl<'a, 'b> Rx<'a, 'b> {
    pub fn meta(&self) -> ExchangeMeta {
        ExchangeMeta::from(&self.dc.data().header.proto)
    }

    pub fn payload(&self) -> &[u8] {
        &self.dc.data().buf[self.dc.data().payload_start..]
    }

    pub fn consume(&mut self) -> &mut Self {
        self.consumed = true;
        self
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.with_session(|sess| Ok(Accessor::for_session(sess, &self.matter.acl_mgr)))
    }

    pub fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(|ctx| f(ctx.session))
    }

    pub fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(ExchangeCtx) -> Result<T, Error>,
    {
        Exchange::ctx(self.id, self.matter, f)
    }
}

impl<'a, 'b> Drop for Rx<'a, 'b> {
    fn drop(&mut self) {
        if self.consumed {
            self.dc.data().buf.clear();
        }
    }
}

pub struct Tx<'a, 'b> {
    id: &'a ExchangeId,
    matter: &'a Matter<'a>,
    dc: DataCarrier<'b, TxExchangePacket>,
    finished: bool,
}

impl<'a, 'b> Tx<'a, 'b> {
    pub fn reset(&mut self) {
        self.dc.data().buf.clear();
    }

    pub fn set_peer(&mut self, peer: Address) {
        self.dc.data().peer = peer;
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), Error> {
        self.dc
            .data()
            .buf
            .extend_from_slice(data)
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(())
    }

    pub fn truncate(&mut self, len: usize) {
        self.dc.data().buf.truncate(len);
    }

    pub fn as_buf(&mut self) -> &mut [u8] {
        self.dc.data().buf.resize_default(MAX_TX_BUF_SIZE);
        &mut self.dc.data().buf
    }

    pub fn finish(&mut self) {
        self.finished = true;
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.with_session(|sess| Ok(Accessor::for_session(sess, &self.matter.acl_mgr)))
    }

    pub fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(|ctx| f(ctx.session))
    }

    pub fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(ExchangeCtx) -> Result<T, Error>,
    {
        Exchange::ctx(self.id, self.matter, f)
    }
}

impl<'a, 'b> Drop for Tx<'a, 'b> {
    fn drop(&mut self) {
        if !self.finished {
            self.reset();
        }
    }
}

pub struct Exchange<'a> {
    pub(crate) id: &'a ExchangeId,
    pub(crate) matter: &'a Matter<'a>,
    pub(crate) rx_packet: &'a Mutex<NoopRawMutex, RxExchangePacket>,
    pub(crate) tx_packet: &'a Mutex<NoopRawMutex, TxExchangePacket>,
    pub(crate) notification: &'a Notification,
    pub(crate) index: u8,
}

impl<'a> Exchange<'a> {
    pub async fn get(&mut self) -> Rx<'_, 'a> {
        Rx {
            dc: self
                .notification
                .get(&self.rx_packet, self.index, |sd| self.for_us(sd))
                .await,
            id: self.id,
            matter: self.matter,
            consumed: false,
        }
    }

    pub async fn recv(&mut self) -> Rx<'_, 'a> {
        let mut rx = self.get().await;

        rx.consume();

        rx
    }

    pub async fn recv_into(&mut self, wb: &mut WriteBuf<'_>) -> Result<ExchangeMeta, Error> {
        let mut rc = self.get().await;

        wb.reset();
        wb.append(rc.payload())?;

        rc.consume();

        Ok(rc.meta())
    }

    pub async fn initiate_send(&mut self) -> Tx<'_, 'a> {
        let dc = self
            .notification
            .get(&self.tx_packet, self.index, |td| td.buf.is_empty())
            .await;

        Tx {
            dc,
            id: self.id,
            matter: self.matter,
            finished: false,
        }
    }

    pub async fn send_with<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: Fn(&mut WriteBuf) -> Result<ExchangeMeta, Error>,
    {
        let mut ctr = None;

        loop {
            let reliable = {
                let mut tx = self.initiate_send().await;

                let packet = tx.dc.data();
                packet.buf.resize_default(MAX_TX_BUF_SIZE);

                let mut wb = WriteBuf::new(&mut packet.buf);
                let meta = f(&mut wb)?;

                ctr = Some(self.matter.process_tx(
                    self.id,
                    &meta,
                    ctr,
                    &mut packet.header,
                    &mut wb,
                )?);

                let (start, end) = (wb.get_start(), wb.get_tail());

                packet.buf.truncate(end);
                packet.payload_start = start;

                tx.finish();

                packet.header.proto.is_reliable()
            };

            if reliable {
                let rx = self
                    .notification
                    .wait(NonZeroUsize::new(1 << self.index).unwrap());
                let timeout = Timer::after(Duration::from_secs(30)); // TODO

                select(rx, timeout).await;

                let acknowledged =
                    self.with_ctx(|ctx| Ok(ctx.exchange.mrp.is_acknowledged(ctr)))?;

                if acknowledged {
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn send(&mut self, meta: &ExchangeMeta, payload: &[u8]) -> Result<(), Error> {
        self.send_with(|wb| {
            wb.copy_from_slice(payload)?;

            Ok(*meta)
        })
        .await
    }

    pub fn accessor(&self) -> Result<Accessor<'a>, Error> {
        self.with_session(|sess| Ok(Accessor::for_session(sess, &self.matter.acl_mgr)))
    }

    pub fn with_session<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut Session) -> Result<T, Error>,
    {
        self.with_ctx(|ctx| f(ctx.session))
    }

    pub fn with_ctx<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(ExchangeCtx) -> Result<T, Error>,
    {
        Self::ctx(self.id, self.matter, f)
    }

    fn ctx<F, T>(id: &ExchangeId, matter: &Matter, f: F) -> Result<T, Error>
    where
        F: FnOnce(ExchangeCtx) -> Result<T, Error>,
    {
        let mut exchange_mgr = matter.exchange_mgr.borrow_mut();
        let mut session_mgr = matter.session_mgr.borrow_mut();

        let exchange = exchange_mgr.get(id).ok_or(ErrorCode::NoExchange)?;
        let session = session_mgr
            .get(&id.session_id)
            .ok_or(ErrorCode::NoSession)?;

        f(ExchangeCtx { exchange, session })
    }

    fn for_us(&self, packet: &RxExchangePacket) -> bool {
        !packet.buf.is_empty()
            && self.id.matches(
                packet.header.proto.exch_id,
                &packet.peer,
                &packet.header.plain,
            )
    }
}
