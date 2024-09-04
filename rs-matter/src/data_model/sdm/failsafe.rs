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

use core::num::NonZeroU8;
use core::time::Duration;

use bitflags::bitflags;

use log::error;

use crate::cert::MAX_CERT_TLV_LEN;
use crate::crypto::KeyPair;
use crate::error::{Error, ErrorCode};
use crate::fabric::FabricMgr;
use crate::interaction_model::core::IMStatusCode;
use crate::mdns::Mdns;
use crate::transport::session::SessionMode;
use crate::utils::cell::RefCell;
use crate::utils::epoch::Epoch;
use crate::utils::init::{init, Init};
use crate::utils::rand::Rand;
use crate::utils::storage::Vec;

bitflags! {
    #[repr(transparent)]
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NocFlags: u8 {
        const ADD_CSR_REQ_RECVD = 0x01;
        const UPDATE_CSR_REQ_RECVD = 0x02;
        const ADD_ROOT_CERT_RECVD = 0x04;
        const ADD_NOC_RECVD = 0x08;
        const UPDATE_NOC_RECVD = 0x10;
    }
}

#[derive(PartialEq)]
pub struct ArmedCtx {
    armed_at: Duration,
    timeout_secs: u16,
    fab_idx: u8,
    flags: NocFlags,
}

#[derive(PartialEq)]
pub enum State {
    Idle,
    Armed(ArmedCtx),
}

pub enum IMError {
    Error(Error),
    Status(IMStatusCode),
}

impl From<Error> for IMError {
    fn from(e: Error) -> Self {
        IMError::Error(e)
    }
}

impl From<IMStatusCode> for IMError {
    fn from(e: IMStatusCode) -> Self {
        IMError::Status(e)
    }
}

pub struct FailSafe {
    state: State,
    key_pair: Option<KeyPair>,
    root_ca: Vec<u8, { MAX_CERT_TLV_LEN }>,
    epoch: Epoch,
    rand: Rand,
}

impl FailSafe {
    #[inline(always)]
    pub const fn new(epoch: Epoch, rand: Rand) -> Self {
        Self {
            state: State::Idle,
            key_pair: None,
            root_ca: Vec::new(),
            epoch,
            rand,
        }
    }

    pub fn init(epoch: Epoch, rand: Rand) -> impl Init<Self> {
        init!(Self {
            state: State::Idle,
            key_pair: None,
            root_ca <- Vec::init(),
            epoch,
            rand,
        })
    }

    pub fn arm(&mut self, timeout_secs: u16, session_mode: &SessionMode) -> Result<(), Error> {
        self.update_state_timeout();

        if matches!(self.state, State::Idle) {
            if matches!(session_mode, SessionMode::PlainText) {
                // Only PASE and CASE sessions supported
                return Err(ErrorCode::FailSafeInvalidAuthentication)?;
            }

            self.state = State::Armed(ArmedCtx {
                armed_at: (self.epoch)(),
                timeout_secs,
                fab_idx: session_mode.fab_idx(),
                flags: NocFlags::empty(),
            });

            return Ok(());
        }

        // Re-arm

        self.check_state(session_mode, NocFlags::empty(), NocFlags::empty())?;

        let State::Armed(ctx) = &mut self.state else {
            // Impossible, as we checked for Idle above
            unreachable!();
        };

        ctx.armed_at = (self.epoch)();
        ctx.timeout_secs = timeout_secs;

        Ok(())
    }

    pub fn disarm(&mut self, session_mode: &SessionMode) -> Result<(), Error> {
        self.update_state_timeout();

        if matches!(self.state, State::Idle) {
            error!("Received Fail-Safe Disarm without it being armed");
            return Err(ErrorCode::FailSafeConstraintError)?;
        }

        // Has to be a CASE session
        Self::get_case_fab_idx(session_mode)?;

        self.check_state(session_mode, NocFlags::empty(), NocFlags::empty())?;
        self.state = State::Idle;

        Ok(())
    }

    pub fn add_trusted_root_cert(
        &mut self,
        session_mode: &SessionMode,
        root_ca: &[u8],
    ) -> Result<(), Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_ROOT_CERT_RECVD,
        )?;
        self.check_cert(Some(root_ca))?;

        self.root_ca.clear();
        self.root_ca
            .extend_from_slice(root_ca)
            .map_err(|_| ErrorCode::InvalidCommand)?;

        self.add_flags(NocFlags::ADD_ROOT_CERT_RECVD);

        Ok(())
    }

    pub fn add_csr_req(&mut self, session_mode: &SessionMode) -> Result<&KeyPair, Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
        )?;

        self.key_pair = Some(KeyPair::new(self.rand)?);

        self.add_flags(NocFlags::ADD_CSR_REQ_RECVD);

        Ok(self.key_pair.as_ref().unwrap())
    }

    pub fn update_csr_req(&mut self, session_mode: &SessionMode) -> Result<&KeyPair, Error> {
        self.update_state_timeout();

        // Must be a CASE session
        Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::empty(),
            NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
        )?;

        self.key_pair = Some(KeyPair::new(self.rand)?);

        self.add_flags(NocFlags::UPDATE_CSR_REQ_RECVD);

        Ok(self.key_pair.as_ref().unwrap())
    }

    pub fn update_noc(
        &mut self,
        session_mode: &SessionMode,
        fabric_mgr: &RefCell<FabricMgr>,
        vendor_id: u16,
        icac: Option<&[u8]>,
        noc: &[u8],
        ipk: &[u8],
        mdns: &dyn Mdns,
    ) -> Result<(), Error> {
        self.update_state_timeout();

        let fab_idx = Self::get_case_fab_idx(session_mode)?;

        self.check_state(
            session_mode,
            NocFlags::ADD_ROOT_CERT_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD,
            NocFlags::ADD_NOC_RECVD | NocFlags::ADD_CSR_REQ_RECVD | NocFlags::UPDATE_NOC_RECVD,
        )?;

        fabric_mgr.borrow_mut().update(
            fab_idx,
            self.key_pair.take().unwrap(),
            &self.root_ca,
            noc,
            icac.unwrap_or(&[]),
            ipk,
            vendor_id,
            mdns,
        )?;

        self.add_flags(NocFlags::ADD_NOC_RECVD);

        Ok(())
    }

    pub fn add_noc(
        &mut self,
        fabric_mgr: &RefCell<FabricMgr>,
        session_mode: &SessionMode,
        vendor_id: u16,
        icac: Option<&[u8]>,
        noc: &[u8],
        ipk: &[u8],
        case_admin_subject: u64,
        mdns: &dyn Mdns,
    ) -> Result<NonZeroU8, Error> {
        self.update_state_timeout();

        self.check_state(
            session_mode,
            NocFlags::ADD_ROOT_CERT_RECVD | NocFlags::ADD_CSR_REQ_RECVD,
            NocFlags::ADD_NOC_RECVD | NocFlags::UPDATE_CSR_REQ_RECVD | NocFlags::UPDATE_NOC_RECVD,
        )?;
        self.check_cert(icac)?;
        self.check_cert(Some(noc))?;

        let fab_idx = fabric_mgr
            .borrow_mut()
            .add(
                self.key_pair.take().unwrap(),
                &self.root_ca,
                noc,
                icac.unwrap_or(&[]),
                ipk,
                vendor_id,
                case_admin_subject,
                mdns,
            )?
            .fab_idx();

        self.add_flags(NocFlags::ADD_NOC_RECVD);

        Ok(fab_idx)
    }

    fn get_case_fab_idx(session_mode: &SessionMode) -> Result<NonZeroU8, Error> {
        if let SessionMode::Case { fab_idx, .. } = session_mode {
            Ok(*fab_idx)
        } else {
            // Only CASE session supported
            Err(ErrorCode::FailSafeInvalidAuthentication.into())
        }
    }

    fn check_state(
        &self,
        session_mode: &SessionMode,
        present: NocFlags,
        absent: NocFlags,
    ) -> Result<(), Error> {
        if let State::Armed(ctx) = &self.state {
            if matches!(session_mode, SessionMode::PlainText) {
                // Session is plain text
                Err(ErrorCode::FailSafeInvalidAuthentication)?;
            }

            if ctx.fab_idx != session_mode.fab_idx() {
                // Fabric index does not match
                Err(ErrorCode::FailSafeInvalidFabricIndex)?;
            }

            if !ctx.flags.contains(present) || !ctx.flags.intersection(absent).is_empty() {
                // State is not what is expected for that concrete command
                Err(ErrorCode::FailSafeConstraintError)?;
            }
        } else {
            // Fail-safe is not armed
            Err(ErrorCode::FailSafeRequired)?;
        }

        Ok(())
    }

    fn check_cert(&self, _cert: Option<&[u8]>) -> Result<(), Error> {
        Ok(()) // TODO
    }

    fn add_flags(&mut self, flags: NocFlags) {
        match &mut self.state {
            State::Armed(ctx) => ctx.flags |= flags,
            _ => panic!("Not armed"),
        }
    }

    fn update_state_timeout(&mut self) {
        if let State::Armed(ctx) = &mut self.state {
            let now = (self.epoch)();
            if now >= ctx.armed_at + Duration::from_secs(ctx.timeout_secs as u64) {
                self.state = State::Idle;
            }
        }
    }
}
