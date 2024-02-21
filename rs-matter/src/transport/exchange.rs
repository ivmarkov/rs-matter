use core::num::NonZeroUsize;

use embassy_futures::select::{select, Either};
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
pub enum Role {
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
    pub fn recv(&mut self, header: &PacketHeader, epoch: Epoch) -> Result<(), Error> {
        self.mrp.recv(header, epoch)
    }

    pub fn pre_send(&mut self, plain: &PlainHdr, proto: &mut ProtoHdr) -> Result<(), Error> {
        self.mrp.pre_send(plain, proto)
    }

    pub fn retrans_ctr(&self) -> Option<u32> {
        self.mrp.retrans_ctr()
    }

    pub fn retrans_delay_ms(&mut self, ctr: u32) -> Result<Option<u64>, Error> {
        let delay = self
            .mrp
            .retrans_delay_ms(ctr)
            .map_err(|_| ErrorCode::Invalid)?; // TODO

        Ok(delay)
    }

    pub fn is_acknowledged(&self, ctr: u32) -> bool {
        self.mrp.is_acknowledged(ctr)
    }
}

pub struct ExchangeMgr {
    exchanges: heapless::Vec<ExchangeEntry, MAX_EXCHANGES>,
    _epoch: Epoch,
}

impl ExchangeMgr {
    pub const fn new(epoch: Epoch) -> Self {
        Self {
            exchanges: heapless::Vec::new(),
            _epoch: epoch,
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

    pub fn check_opcode<T: num::FromPrimitive + PartialEq>(&self, opcode: T) -> Result<(), Error> {
        if self.opcode::<T>()? == opcode {
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

pub type RxExchangePacket = ExchangePacket<MAX_RX_BUF_SIZE>;
pub type TxExchangePacket = ExchangePacket<MAX_TX_BUF_SIZE>;

pub struct ExchangePacket<const N: usize> {
    pub(crate) new_exchange: bool,
    pub(crate) peer: Address,
    pub(crate) header: PacketHeader,
    pub(crate) buf: heapless::Vec<u8, MAX_RX_BUF_SIZE>,
    pub(crate) payload_start: usize,
}

impl<const N: usize> ExchangePacket<N> {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            new_exchange: false,
            peer: Address::new(),
            header: PacketHeader::new(),
            buf: heapless::Vec::new(),
            payload_start: 0,
        }
    }
}

pub struct Rx<'a, 'b> {
    pub(crate) id: &'a ExchangeId,
    pub(crate) matter: &'a Matter<'a>,
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
            self.dc.data_mut().buf.clear();
        }
    }
}

pub struct Tx<'a, 'b> {
    pub(crate) id: &'a ExchangeId,
    pub(crate) matter: &'a Matter<'a>,
    dc: DataCarrier<'b, TxExchangePacket>,
    completed: bool,
}

pub struct TxPayload<'a, 'b> {
    pub(crate) id: &'a ExchangeId,
    pub(crate) matter: &'a Matter<'a>,
    header: &'b mut PacketHeader,
    writebuf: WriteBuf<'b>,
    completed: &'b mut bool,
}

impl<'a, 'b> TxPayload<'a, 'b> {
    pub fn writebuf(&mut self) -> &mut WriteBuf<'b> {
        &mut self.writebuf
    }

    pub fn complete(
        mut self,
        meta: impl Into<ExchangeMeta>,
        retrans_ctr: Option<u32>,
    ) -> Result<Option<u32>, Error> {
        let meta = meta.into();

        if self
            .matter
            .process_tx(self.id, meta, retrans_ctr, self.header, &mut self.writebuf)?
        {
            *self.completed = true;
            Ok(meta.reliable.then_some(self.header.plain.ctr))
        } else {
            Ok(None)
        }
    }
}

impl<'a, 'b> Tx<'a, 'b> {
    pub fn payload(&mut self) -> Result<TxPayload<'a, '_>, Error> {
        self.completed = false;

        let packet = self.dc.data_mut();
        packet.buf.resize_default(MAX_TX_BUF_SIZE).unwrap();

        let mut writebuf = WriteBuf::new(&mut packet.buf);
        writebuf.reserve(PacketHeader::HDR_RESERVE)?;

        Ok(TxPayload {
            id: self.id,
            matter: self.matter,
            header: &mut packet.header,
            writebuf,
            completed: &mut self.completed,
        })
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
        if !self.completed {
            self.dc.data_mut().buf.clear();
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
            completed: false,
        }
    }

    pub async fn wait_if_ack(&mut self, ctr: Option<u32>) -> Result<bool, Error> {
        if let Some(ctr) = ctr {
            self.wait_ack(ctr).await
        } else {
            Ok(true)
        }
    }

    pub async fn wait_ack(&mut self, ctr: u32) -> Result<bool, Error> {
        let delay = {
            let mut exchange_mgr = self.matter.exchange_mgr.borrow_mut();
            let exchange = exchange_mgr.get(self.id).ok_or(ErrorCode::NoExchange)?;

            exchange.retrans_delay_ms(ctr)?
        };

        if let Some(delay) = delay {
            let notification = self
                .notification
                .wait(NonZeroUsize::new(1 << self.index).unwrap());
            let timer = Timer::after(Duration::from_millis(delay));

            if matches!(select(notification, timer).await, Either::First(_)) {
                let mut exchange_mgr = self.matter.exchange_mgr.borrow_mut();
                let exchange = exchange_mgr.get(self.id).ok_or(ErrorCode::NoExchange)?;

                Ok(exchange.is_acknowledged(ctr))
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    pub async fn send_with<F>(&mut self, f: F) -> Result<(), Error>
    where
        F: Fn(&mut WriteBuf) -> Result<ExchangeMeta, Error>,
    {
        let mut retrans_ctr = None;

        loop {
            {
                let mut tx = self.initiate_send().await;

                let mut payload = tx.payload()?;

                let meta = f(payload.writebuf())?;

                retrans_ctr = payload.complete(meta, retrans_ctr)?;
            }

            if self.wait_if_ack(retrans_ctr).await? {
                break;
            }
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

pub struct ExchangeBuffer<'a>(pub(crate) &'a mut [u8]);

impl<'a> ExchangeBuffer<'a> {
    pub async fn get(&mut self) -> Result<&mut [u8], Error> {
        Ok(self.0)
    }
}

pub struct ExchangeBuffers<'a> {
    pub rx: ExchangeBuffer<'a>,
    pub tx: ExchangeBuffer<'a>,
}
