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

use core::fmt;
use core::num::NonZeroU8;
use core::time::Duration;

use crate::error::*;
use crate::transport::exchange::ExchangeId;
use crate::transport::mrp::ReliableMessage;
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, zeroed, Init, IntoFallibleInit};
use crate::utils::rand::Rand;
use crate::utils::storage::{ParseBuf, WriteBuf};
use crate::Matter;

use super::dedup::RxCtrState;
use super::exchange::{ExchangeState, MessageMeta, Role};
use super::mrp::RetransEntry;
use super::network::Address;
use super::packet::PacketHdr;
use super::plain_hdr::PlainHdr;
use super::proto_hdr::ProtoHdr;

pub const MAX_CAT_IDS_PER_NOC: usize = 3;
pub type NocCatIds = [u32; MAX_CAT_IDS_PER_NOC];

const MATTER_AES128_KEY_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SessionMode {
    // The Case session will capture the local fabric index
    // and the local fabric index
    Case {
        fab_idx: NonZeroU8,
        cat_ids: NocCatIds,
    },
    // The Pase session always starts with a fabric index of 0
    // (i.e. no fabric) but will be upgraded to the actual fabric index
    // once AddNOC or UpdateNOC is received
    Pase {
        fab_idx: u8,
    },
    #[default]
    PlainText,
}

impl SessionMode {
    pub fn fab_idx(&self) -> u8 {
        match self {
            SessionMode::Case { fab_idx, .. } => fab_idx.get(),
            SessionMode::Pase { fab_idx, .. } => *fab_idx,
            SessionMode::PlainText => 0,
        }
    }
}

pub struct Session {
    // Internal ID which is guaranteeed to be unique accross all sessions and not change when sessions are added/removed
    pub(crate) id: u32,
    peer_addr: Address,
    local_nodeid: u64,
    peer_nodeid: Option<u64>,
    // I find the session initiator/responder role getting confused with exchange initiator/responder
    // So, we might keep this as enc_key and dec_key for now
    dec_key: [u8; MATTER_AES128_KEY_SIZE],
    enc_key: [u8; MATTER_AES128_KEY_SIZE],
    att_challenge: [u8; MATTER_AES128_KEY_SIZE],
    local_sess_id: u16,
    peer_sess_id: u16,
    msg_ctr: u32,
    rx_ctr_state: RxCtrState,
    mode: SessionMode,
    pub(crate) exchanges: crate::utils::storage::Vec<Option<ExchangeState>, MAX_EXCHANGES>,
    last_use: Duration,
    /// If `true` then the session is considered "expired". Session expiration happens
    /// for the session on behalf of which a fabric is removed.
    ///
    /// Expired sessions can still process their ongoing exchanges, but do not accept any new ones.
    /// Furthermore, expired sessions are the prime candidates for eviction.
    expired: bool,
    reserved: bool,
}

impl Session {
    pub fn new(
        id: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        epoch: Epoch,
        rand: Rand,
    ) -> Self {
        Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key: [0; MATTER_AES128_KEY_SIZE],
            enc_key: [0; MATTER_AES128_KEY_SIZE],
            att_challenge: [0; MATTER_AES128_KEY_SIZE],
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: Self::rand_msg_ctr(rand),
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges: crate::utils::storage::Vec::new(),
            last_use: epoch(),
            expired: false,
        }
    }

    pub fn init(
        id: u32,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
        epoch: Epoch,
        rand: Rand,
    ) -> impl Init<Self> {
        init!(Self {
            id,
            reserved,
            peer_addr,
            local_nodeid: 0,
            peer_nodeid,
            dec_key <- zeroed(),
            enc_key <- zeroed(),
            att_challenge <- zeroed(),
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: Self::rand_msg_ctr(rand),
            rx_ctr_state: RxCtrState::new(0),
            mode: SessionMode::PlainText,
            exchanges: crate::utils::storage::Vec::new(),
            last_use: epoch(),
            expired: false,
        })
    }

    /// Get the internal ID of the session
    /// This ID is guaranteed to be unique across all sessions
    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn get_local_sess_id(&self) -> u16 {
        self.local_sess_id
    }

    #[cfg(test)]
    pub fn set_local_sess_id(&mut self, sess_id: u16) {
        self.local_sess_id = sess_id;
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
    }

    pub fn get_peer_addr(&self) -> Address {
        self.peer_addr
    }

    pub fn is_encrypted(&self) -> bool {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } => true,
            SessionMode::PlainText => false,
        }
    }

    pub fn get_peer_node_id(&self) -> Option<u64> {
        self.peer_nodeid
    }

    pub fn get_local_fabric_idx(&self) -> u8 {
        self.mode.fab_idx()
    }

    pub fn get_session_mode(&self) -> &SessionMode {
        &self.mode
    }

    fn get_msg_ctr(&mut self) -> u32 {
        let ctr = self.msg_ctr;
        self.msg_ctr += 1;
        ctr
    }

    pub fn get_dec_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } => Some(&self.dec_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn get_enc_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Case { .. } | SessionMode::Pase { .. } => Some(&self.enc_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn get_att_challenge(&self) -> &[u8] {
        &self.att_challenge
    }

    pub(crate) fn is_for_node(&self, fabric_idx: u8, peer_node_id: u64, secure: bool) -> bool {
        self.get_local_fabric_idx() == fabric_idx
            && self.peer_nodeid == Some(peer_node_id)
            && self.is_encrypted() == secure
            && !self.reserved
    }

    pub(crate) fn is_for_rx(&self, rx_peer: &Address, rx_plain: &PlainHdr) -> bool {
        let nodeid_matches = self.peer_nodeid.is_none()
            || rx_plain.get_src_nodeid().is_none()
            || self.peer_nodeid == rx_plain.get_src_nodeid();

        nodeid_matches
            && self.local_sess_id == rx_plain.sess_id
            && self.peer_addr == *rx_peer
            && self.is_encrypted() == rx_plain.is_encrypted()
            && !self.reserved
    }

    /// Return `true` if the session is expired.
    pub(crate) fn is_expired(&self) -> bool {
        self.expired
    }

    pub fn upgrade_fabric_idx(&mut self, fabric_idx: NonZeroU8) -> Result<(), Error> {
        if let SessionMode::Pase { fab_idx } = &mut self.mode {
            if *fab_idx == 0 {
                *fab_idx = fabric_idx.get();
            } else {
                // Upgrading a PASE session can happen only once
                Err(ErrorCode::Invalid)?;
            }
        } else {
            // CASE sessions are not upgradeable, as per spec
            // And for plain text sessions - we shoudn't even get here in the first place
            Err(ErrorCode::Invalid)?;
        }

        Ok(())
    }

    /// Update the session state with the data in the received packet headers.
    ///
    /// Return `true` if a new exchange was created, and `false` otherwise.
    pub(crate) fn post_recv(&mut self, rx_header: &PacketHdr, epoch: Epoch) -> Result<bool, Error> {
        if !self
            .rx_ctr_state
            .post_recv(rx_header.plain.ctr, self.is_encrypted())
        {
            Err(ErrorCode::Duplicate)?;
        }

        let exch_index = self.get_exch_for_rx(&rx_header.proto);
        if let Some(exch_index) = exch_index {
            let exch = unwrap!(self.exchanges[exch_index].as_mut());

            exch.post_recv(&rx_header.plain, &rx_header.proto, epoch)?;

            Ok(false)
        } else {
            if !rx_header.proto.is_initiator()
                || !MessageMeta::from(&rx_header.proto).is_new_exchange()
            {
                // Do not create a new exchange if the peer is not an initiator, or if
                // the packet is NOT a candidate for a new exchange
                // (i.e. it is a standalone ACK or a SC status response)
                Err(ErrorCode::NoExchange)?;
            }

            if let Some(exch_index) =
                self.add_exch(rx_header.proto.exch_id, Role::Responder(Default::default()))
            {
                // unwrap is safe as we just created the exchange
                let exch = unwrap!(self.exchanges[exch_index].as_mut());

                exch.post_recv(&rx_header.plain, &rx_header.proto, epoch)?;

                Ok(true)
            } else {
                Err(ErrorCode::NoSpaceExchanges)?
            }
        }
    }

    pub(crate) fn pre_send(
        &mut self,
        exch_index: Option<usize>,
        tx_header: &mut PacketHdr,
        session_active_interval_ms: Option<u16>,
        session_idle_interval_ms: Option<u16>,
    ) -> Result<(Address, bool), Error> {
        let ctr = if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());
            exchange.mrp.retrans.as_ref().map(RetransEntry::get_msg_ctr)
        } else {
            None
        };

        let retransmission = ctr.is_some();

        tx_header.plain.sess_id = self.get_peer_sess_id();
        tx_header.plain.ctr = ctr.unwrap_or_else(|| self.get_msg_ctr());
        tx_header.plain.set_src_nodeid(None);
        tx_header.plain.set_dst_unicast_nodeid(
            (self.mode == SessionMode::PlainText)
                .then_some(self.peer_nodeid)
                .flatten(),
        );

        tx_header.proto.adjust_reliability(false, &self.peer_addr);

        if let Some(exchange_index) = exch_index {
            let exchange = unwrap!(self.exchanges[exchange_index].as_mut());

            exchange.pre_send(
                &tx_header.plain,
                &mut tx_header.proto,
                session_active_interval_ms,
                session_idle_interval_ms,
            )?;
        }

        Ok((self.peer_addr, retransmission))
    }

    /// Decode the remaining part of the packet after the plain header and then consume the `ParseBuf`
    /// instance as it no longer would be necessary.
    ///
    /// Returns the range of the decoded packet payload
    pub(crate) fn decode_remaining(
        &self,
        rx_header: &mut PacketHdr,
        mut pb: ParseBuf,
    ) -> Result<(usize, usize), Error> {
        rx_header.decode_remaining(
            &mut pb,
            self.peer_nodeid.unwrap_or_default(),
            self.get_dec_key(),
        )?;

        rx_header.proto.adjust_reliability(true, &self.peer_addr);

        Ok(pb.slice_range())
    }

    pub(crate) fn encode(&self, tx: &PacketHdr, wb: &mut WriteBuf) -> Result<(), Error> {
        tx.encode(wb, self.local_nodeid, self.get_enc_key())
    }

    fn update_last_used(&mut self, epoch: Epoch) {
        self.last_use = epoch();
    }

    fn rand_msg_ctr(rand: Rand) -> u32 {
        let mut buf = [0; 4];
        rand(&mut buf);
        u32::from_be_bytes(buf) & MATTER_MSG_CTR_RANGE
    }

    pub(crate) fn get_exch_for_rx(&self, rx_proto: &ProtoHdr) -> Option<usize> {
        self.exchanges
            .iter()
            .enumerate()
            .filter(|(_, exch)| {
                exch.as_ref()
                    .map(|exch| exch.is_for_rx(rx_proto))
                    .unwrap_or(false)
            })
            .map(|(index, _)| index)
            .next()
    }

    pub(crate) fn add_exch(&mut self, exch_id: u16, role: Role) -> Option<usize> {
        let exch_state = Some(ExchangeState {
            exch_id,
            role,
            mrp: ReliableMessage::new(),
        });

        let exch_index = if self.exchanges.len() < MAX_EXCHANGES {
            let _ = self.exchanges.push(exch_state);

            self.exchanges.len() - 1
        } else {
            let index = self.exchanges.iter().position(Option::is_none);

            if let Some(index) = index {
                self.exchanges[index] = exch_state;

                index
            } else {
                error!(
                    "Too many exchanges for session {} [SID:{:x},RSID:{:x}]; exchange creation failed",
                    self.id,
                    self.get_local_sess_id(),
                    self.get_peer_sess_id()
                );

                return None;
            }
        };

        let exch_id = ExchangeId::new(self.id, exch_index);

        debug!("New exchange: {} :: {:?}", exch_id.display(self), role);

        Some(exch_index)
    }

    pub(crate) fn remove_exch(&mut self, index: usize) -> bool {
        let exchange = unwrap!(self.exchanges[index].as_mut());
        let exchange_id = ExchangeId::new(self.id, index);

        if exchange.mrp.is_retrans_pending() {
            exchange.role.set_dropped_state();
            error!("Exchange {}: A packet is still (re)transmitted! Marking as dropped, but session will be closed", exchange_id.display(self));

            false
        } else if exchange.mrp.is_ack_pending() {
            exchange.role.set_dropped_state();
            warn!(
                "Exchange {}: Pending ACK. Marking as dropped",
                exchange_id.display(self)
            );

            false
        } else {
            trace!("Exchange {}: Dropped cleanly", exchange_id.display(self));
            self.exchanges[index] = None;

            true
        }
    }
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "peer: {:?}, peer_nodeid: {:?}, local: {}, remote: {}, msg_ctr: {}, mode: {:?}, ts: {:?}, expired: {}",
            self.peer_addr,
            self.peer_nodeid,
            self.local_sess_id,
            self.peer_sess_id,
            self.msg_ctr,
            self.mode,
            self.last_use,
            self.expired,
        )
    }
}

pub struct ReservedSession<'a> {
    id: u32,
    session_mgr: &'a RefCell<SessionMgr>,
    complete: bool,
}

impl<'a> ReservedSession<'a> {
    pub fn reserve_now(matter: &'a Matter<'a>) -> Result<Self, Error> {
        let mut mgr = matter.transport_mgr.session_mgr.borrow_mut();

        let id = mgr.add(true, Address::new(), None)?.id;

        Ok(Self {
            id,
            session_mgr: &matter.transport_mgr.session_mgr,
            complete: false,
        })
    }

    pub async fn reserve(matter: &'a Matter<'a>) -> Result<ReservedSession<'a>, Error> {
        let session = Self::reserve_now(matter);

        if let Ok(session) = session {
            Ok(session)
        } else {
            matter.transport_mgr.evict_some_session().await?;

            Self::reserve_now(matter)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        local_nodeid: u64,
        peer_nodeid: u64,
        peer_sessid: u16,
        local_sessid: u16,
        peer_addr: Address,
        mode: SessionMode,
        dec_key: Option<&[u8]>,
        enc_key: Option<&[u8]>,
        att_challenge: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut mgr = self.session_mgr.borrow_mut();
        let session = mgr.get(self.id).ok_or(ErrorCode::NoSession)?;

        session.local_nodeid = local_nodeid;
        session.peer_nodeid = Some(peer_nodeid);
        session.peer_sess_id = peer_sessid;
        session.local_sess_id = local_sessid;
        session.peer_addr = peer_addr;
        session.mode = mode;

        if let Some(dec_key) = dec_key {
            session.dec_key.copy_from_slice(dec_key);
        }

        if let Some(enc_key) = enc_key {
            session.enc_key.copy_from_slice(enc_key);
        }

        if let Some(att_challenge) = att_challenge {
            session.att_challenge.copy_from_slice(att_challenge);
        }

        Ok(())
    }

    pub fn complete(mut self) {
        self.complete = true;
    }
}

impl Drop for ReservedSession<'_> {
    fn drop(&mut self) {
        if self.complete {
            let mut session_mgr = self.session_mgr.borrow_mut();
            let session = unwrap!(session_mgr.get(self.id));
            session.reserved = false;
        } else {
            self.session_mgr.borrow_mut().remove(self.id);
        }
    }
}

const MAX_SESSIONS: usize = 16;
const MAX_EXCHANGES: usize = 5;

const MATTER_MSG_CTR_RANGE: u32 = 0x0fffffff;

pub struct SessionMgr {
    next_sess_unique_id: u32,
    next_sess_id: u16,
    next_exch_id: u16,
    sessions: crate::utils::storage::Vec<Session, MAX_SESSIONS>,
    pub(crate) epoch: Epoch,
    pub(crate) rand: Rand,
}

impl SessionMgr {
    /// Create a new session manager.
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            sessions: crate::utils::storage::Vec::new(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 1,
            epoch,
            rand,
        }
    }

    /// Create an in-place initializer for a new session manager.
    pub fn init(epoch: Epoch, rand: Rand) -> impl Init<Self> {
        init!(Self {
            sessions <- crate::utils::storage::Vec::init(),
            next_sess_unique_id: 0,
            next_sess_id: 1,
            next_exch_id: 1,
            epoch,
            rand,
        })
    }

    pub fn reset(&mut self) {
        self.sessions.clear();
        self.next_sess_id = 1;
        self.next_exch_id = 1;
    }

    pub fn get_next_sess_id(&mut self) -> u16 {
        let mut next_sess_id: u16;
        loop {
            next_sess_id = self.next_sess_id;

            // Increment next sess id
            self.next_sess_id = self.next_sess_id.overflowing_add(1).0;
            if self.next_sess_id == 0 {
                self.next_sess_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing session
            if self
                .sessions
                .iter()
                .all(|sess| sess.get_local_sess_id() != next_sess_id)
            {
                break;
            }
        }
        next_sess_id
    }

    pub fn get_next_exch_id(&mut self) -> u16 {
        let mut next_exch_id: u16;
        loop {
            next_exch_id = self.next_exch_id;

            // Increment next exch id
            self.next_exch_id = self.next_exch_id.overflowing_add(1).0;
            if self.next_exch_id == 0 {
                self.next_exch_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing exchange
            if self
                .sessions
                .iter()
                .flat_map(|sess| sess.exchanges.iter())
                .filter_map(|exch| exch.as_ref())
                .all(|exch| {
                    !matches!(exch.role, Role::Responder(_)) || exch.exch_id != next_exch_id
                })
            {
                break;
            }
        }
        next_exch_id
    }

    pub fn get_session_for_eviction(&mut self) -> Option<&mut Session> {
        let mut lru_index = None;
        let mut lru_ts = (self.epoch)();
        for (i, s) in self.sessions.iter().enumerate() {
            if (s.expired || s.last_use < lru_ts)
                && !s.reserved
                && s.exchanges.iter().all(Option::is_none)
            {
                lru_ts = s.last_use;
                lru_index = Some(i);

                if s.expired {
                    // Expired sessons are the prime candidates for eviction,
                    // so we can break early
                    break;
                }
            }
        }

        lru_index.map(|index| &mut self.sessions[index])
    }

    pub fn add(
        &mut self,
        reserved: bool,
        peer_addr: Address,
        peer_nodeid: Option<u64>,
    ) -> Result<&mut Session, Error> {
        let session_id = self.next_sess_unique_id;

        self.next_sess_unique_id += 1;
        if self.next_sess_unique_id > 0x0fff_ffff {
            // Reserve the upper 4 bits for the exchange index
            self.next_sess_unique_id = 0;
        }

        let session = Session::init(
            session_id,
            reserved,
            peer_addr,
            peer_nodeid,
            self.epoch,
            self.rand,
        );

        self.sessions
            .push_init(session.into_fallible::<Error>(), || {
                ErrorCode::NoSpaceSessions.into()
            })?;

        Ok(unwrap!(self.sessions.last_mut()))
    }

    /// This assumes that the higher layer has taken care of doing anything required
    /// as per the spec before the session is removed
    pub fn remove(&mut self, id: u32) -> Option<Session> {
        if let Some(index) = self.sessions.iter().position(|sess| sess.id == id) {
            Some(self.sessions.swap_remove(index))
        } else {
            None
        }
    }

    /// This assumes that the higher layer has taken care of doing anything required
    /// as per the spec before the sessions are removed or expired
    pub fn remove_for_fabric(&mut self, fabric_idx: NonZeroU8, expire_sess_id: Option<u32>) {
        loop {
            let Some(index) = self.sessions.iter().position(|sess| {
                sess.get_local_fabric_idx() == fabric_idx.get() && Some(sess.id) != expire_sess_id
            }) else {
                break;
            };

            info!(
                "Dropping session with ID {} for fabric index {} immediately",
                self.sessions[index].id, fabric_idx
            );
            self.sessions.swap_remove(index);
        }

        if let Some(expire_sess_id) = expire_sess_id {
            let expire_sess = self
                .sessions
                .iter_mut()
                .find(|sess| sess.id == expire_sess_id);
            if let Some(expire_sess) = expire_sess {
                expire_sess.expired = true;
                info!(
                    "Marking session with ID {} as expired for fabric index {}",
                    expire_sess_id,
                    fabric_idx.get()
                );
            } else {
                warn!(
                    "No session with ID {} found for fabric index {} to mark as expired",
                    expire_sess_id,
                    fabric_idx.get()
                );
            }
        }
    }

    pub fn get(&mut self, id: u32) -> Option<&mut Session> {
        let mut session = self.sessions.iter_mut().find(|sess| sess.id == id);

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_for_node(
        &mut self,
        fabric_idx: u8,
        peer_node_id: u64,
        secure: bool,
    ) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            // Expired sessions are not allowed to initiate new exchanges
            .find(|sess| !sess.expired && sess.is_for_node(fabric_idx, peer_node_id, secure));

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_for_rx(
        &mut self,
        rx_peer: &Address,
        rx_plain: &PlainHdr,
    ) -> Option<&mut Session> {
        let mut session = self
            .sessions
            .iter_mut()
            .find(|sess| sess.is_for_rx(rx_peer, rx_plain));

        if let Some(session) = session.as_mut() {
            session.update_last_used(self.epoch);
        }

        session
    }

    pub(crate) fn get_exch<F>(&mut self, f: F) -> Option<(&mut Session, usize)>
    where
        F: Fn(&Session, &ExchangeState) -> bool,
    {
        let exch = self
            .sessions
            .iter()
            .flat_map(|sess| {
                sess.exchanges
                    .iter()
                    .enumerate()
                    .filter_map(move |(exch_index, exch)| {
                        exch.as_ref().map(|exch| (sess, exch, exch_index))
                    })
            })
            .filter(|(sess, exch, _)| f(sess, exch))
            .map(|(sess, _, exch_index)| (sess.id, exch_index))
            .next();

        if let Some((id, exch_index)) = exch {
            let epoch = self.epoch;
            let session = unwrap!(self.get(id));
            session.update_last_used(epoch);

            Some((session, exch_index))
        } else {
            None
        }
    }

    /// Iterate over the sessions
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.iter()
    }
}

impl fmt::Display for SessionMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{[")?;
        for s in &self.sessions {
            writeln!(f, "{{ {}, }},", s)?;
        }
        write!(f, "], next_sess_id: {}", self.next_sess_id)?;
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        transport::network::Address,
        utils::{epoch::dummy_epoch, rand::dummy_rand},
    };

    use super::SessionMgr;

    #[test]
    fn test_next_sess_id_doesnt_reuse() {
        let mut sm = SessionMgr::new(dummy_epoch, dummy_rand);
        let sess = unwrap!(sm.add(false, Address::default(), None));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        let sess = unwrap!(sm.add(false, Address::default(), None));
        sess.set_local_sess_id(4);
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let mut sm = SessionMgr::new(dummy_epoch, dummy_rand);
        let sess = unwrap!(sm.add(false, Address::default(), None));
        sess.set_local_sess_id(1);
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }
}
