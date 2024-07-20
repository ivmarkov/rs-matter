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

use crate::{
    crypto::KeyPair,
    error::{Error, ErrorCode},
    fabric::Fabric,
    transport::session::SessionMode,
};
use log::{error, warn};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NocCommand {
    CsrRequest { for_update_noc: bool },
    AddTrustedRoot,
    AddNoc,
    UpdateNoc,
    CommComplete,
}

impl NocCommand {
    pub fn is_for_existing_fabric(&self) -> bool {
        match self {
            Self::CsrRequest { for_update_noc } => *for_update_noc,
            Self::AddTrustedRoot | NocCommand::AddNoc => false,
            Self::UpdateNoc => true,
            Self::CommComplete => false,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub struct NocState {
    csr_req_for_add_noc_received: bool,
    csr_req_for_update_noc_received: bool,
    add_trusted_root_received: bool,
    add_noc_received: bool,
    update_noc_received: bool,
    comm_complete_received: bool,
    fab_idx: u8,
    key_pair: Option<KeyPair>,
}

impl NocState {
    pub const fn new() -> Self {
        Self {
            csr_req_for_add_noc_received: false,
            csr_req_for_update_noc_received: false,
            add_trusted_root_received: false,
            add_noc_received: false,
            update_noc_received: false,
            comm_complete_received: false,
            fab_idx: 0,
            key_pair: None,
        }
    }

    pub fn is_for_existing_fabric(&self) -> Option<bool> {
        if self.csr_req_for_add_noc_received || self.add_trusted_root_received {
            Some(false)
        } else if self.csr_req_for_update_noc_received {
            Some(true)
        } else {
            None
        }
    }

    pub fn fab_idx(&self) -> u8 {
        self.fab_idx
    }

    pub fn set_fab_idx(&mut self, fab_idx: NonZeroU8) {
        assert_eq!(self.fab_idx, 0);

        self.fab_idx = fab_idx.get();
    }

    pub fn key_pair(&self) -> Option<&KeyPair> {
        self.key_pair.as_ref()
    }

    pub fn generate_key_pair(&mut self) -> &KeyPair {
        assert!(self.key_pair.is_none());

        self.key_pair = Some(KeyPair::generate());

        self.key_pair.as_ref().unwrap()
    }

    pub fn is_fabric_active(&self) -> bool {
        self.add_noc_received || self.is_final()
    }

    pub fn is_final(&self) -> bool {
        self.comm_complete_received || self.update_noc_received
    }

    pub fn check_valid(&self, cmd: NocCommand, sess_mode: &SessionMode) -> Result<(), Error> {
        match cmd {
            NocCommand::CsrRequest { for_update_noc } => {
                if self.csr_req_for_add_noc_received || self.csr_req_for_update_noc_received {
                    warn!("Invalid CsrRequest: CsrRequest already received");
                    Err(ErrorCode::Invalid)?;
                }

                if self.add_noc_received || self.update_noc_received {
                    warn!("Invalid CsrRequest: AddNOC or UpdateNOC already received");
                    Err(ErrorCode::Invalid)?;
                }

                if for_update_noc {
                    if !matches!(sess_mode, SessionMode::Case { .. }) {
                        warn!("Invalid CsrRequest for UpdateNOC: Session mode is {sess_mode:?} but should be CASE");
                        Err(ErrorCode::Invalid)?;
                    }
                } else {
                    if !matches!(
                        sess_mode,
                        SessionMode::Pase { .. } | SessionMode::Case { .. }
                    ) {
                        warn!("Invalid CsrRequest for AddNOC: Session mode is {sess_mode:?} but should be CASE or PASE");
                        Err(ErrorCode::Invalid)?;
                    }
                }
            }
            NocCommand::AddTrustedRoot => {
                if self.add_trusted_root_received {
                    warn!("Invalid AddTrustedRoot: AddTrustedRoot already received");
                    Err(ErrorCode::Invalid)?;
                }

                if self.add_noc_received || self.update_noc_received {
                    warn!("Invalid AddTrustedRoot: AddNOC or UpdateNOC already received");
                    Err(ErrorCode::Invalid)?;
                }
            }
            NocCommand::AddNoc => {
                if self.add_noc_received || self.update_noc_received {
                    warn!("Invalid AddNOC: AddNOC or UpdateNOC already received");
                    Err(ErrorCode::Invalid)?;
                }

                if self.csr_req_for_update_noc_received {
                    warn!("Invalid AddNOC: CsrRequest for UpdateNOC had been previously received");
                    Err(ErrorCode::Invalid)?;
                }

                if !self.csr_req_for_add_noc_received {
                    warn!("Invalid AddNOC: CsrRequest for AddNOC not received yet");
                    Err(ErrorCode::Invalid)?;
                }

                if !self.add_trusted_root_received {
                    warn!("Invalid AddNOC: AddTrustedRoot not received yet");
                    Err(ErrorCode::Invalid)?;
                }
            }
            NocCommand::UpdateNoc => {
                if self.add_noc_received || self.update_noc_received {
                    warn!("Invalid UpdateNOC: AddNOC or UpdateNOC already received");
                    Err(ErrorCode::Invalid)?;
                }

                if self.csr_req_for_add_noc_received {
                    warn!("Invalid UpdateNOC: CsrRequest for AddNOC had been previously received");
                    Err(ErrorCode::Invalid)?;
                }

                if !self.csr_req_for_update_noc_received {
                    warn!("Invalid UpdateNOC: CsrRequest for UpdateNOC not received yet");
                    Err(ErrorCode::Invalid)?;
                }

                if self.add_trusted_root_received {
                    warn!("Invalid UpdateNOC: AddTrustedRoot had been previously received");
                    Err(ErrorCode::Invalid)?;
                }
            }
            NocCommand::CommComplete => {
                if self.comm_complete_received {
                    warn!("Invalid CommComplete: CommComplete already received");
                    Err(ErrorCode::Invalid)?;
                }

                if !self.add_noc_received {
                    warn!("Invalid CommComplete: AddNOC not received yet");
                    Err(ErrorCode::Invalid)?;
                }

                if self.update_noc_received {
                    warn!("Invalid CommComplete: UpdateNOC had been previously received");
                    Err(ErrorCode::Invalid)?;
                }
            }
        }

        Ok(())
    }

    pub fn update(&mut self, cmd: NocCommand, sess_mode: &SessionMode) -> Result<(), Error> {
        self.check_valid(cmd, sess_mode)?;

        match cmd {
            NocCommand::CsrRequest { for_update_noc } => {
                if for_update_noc {
                    self.csr_req_for_update_noc_received = true;
                } else {
                    self.csr_req_for_add_noc_received = true;
                }
            }
            NocCommand::AddTrustedRoot => {
                self.add_trusted_root_received = true;
            }
            NocCommand::AddNoc => {
                self.add_noc_received = true;
                self.fab_idx = sess_mode.fab_idx();
            }
            NocCommand::UpdateNoc => {
                self.update_noc_received = true;
                self.fab_idx = sess_mode.fab_idx();
            }
            NocCommand::CommComplete => {
                self.comm_complete_received = true;
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ArmedCtx {
    timeout: u16,
    noc_state: NocState,
}

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Idle,
    Armed(ArmedCtx),
}

pub struct FailSafe {
    state: State,
}

impl FailSafe {
    #[inline(always)]
    pub const fn new() -> Self {
        Self { state: State::Idle }
    }

    pub fn arm(&mut self, timeout: u16, session_mode: SessionMode) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => {
                self.state = State::Armed(ArmedCtx {
                    timeout,
                    noc_state: NocState::new(),
                })
            }
            State::Armed(c) => {
                match c.noc_state {
                    NocState::AddNocRecvd(fab_idx) | NocState::UpdateNocRecvd(fab_idx) => {
                        if let Some(sess_fab_idx) = NonZeroU8::new(session_mode.fab_idx()) {
                            if sess_fab_idx != fab_idx {
                                error!("Received Fail-Safe Re-arm with a different fabric index from a previous Add/Update NOC");
                                Err(ErrorCode::Invalid)?;
                            }
                        } else {
                            error!("Received Fail-Safe Re-arm from a session that does not have a fabric index");
                            Err(ErrorCode::Invalid)?;
                        }
                    }
                    _ => (),
                }

                // re-arm
                c.timeout = timeout;
            }
        }
        Ok(())
    }

    pub fn disarm(&mut self, session_mode: SessionMode) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => {
                error!("Received Fail-Safe Disarm without it being armed");
                Err(ErrorCode::Invalid)?;
            }
            State::Armed(c) => {
                match c.noc_state {
                    NocState::CommComleteRecvd(fab_idx) | NocState::UpdateNocRecvd(fab_idx) => {
                        if let Some(sess_fab_idx) = NonZeroU8::new(session_mode.fab_idx()) {
                            if sess_fab_idx != fab_idx {
                                error!("Received disarm with different fabric index from a previous Add/Update NOC");
                                Err(ErrorCode::Invalid)?;
                            }
                        } else {
                            error!(
                                "Received disarm from a session that does not have a fabric index"
                            );
                            Err(ErrorCode::Invalid)?;
                        }
                    }
                    _ => {
                        error!("Received Fail-Safe Disarm, yet the failsafe has not completed commissioning yet");
                        Err(ErrorCode::Invalid)?;
                    }
                }
                self.state = State::Idle;
            }
        }
        Ok(())
    }

    pub fn is_armed(&self) -> bool {
        self.state != State::Idle
    }

    pub fn record_next_state(&mut self, next: NocState) -> Result<(), Error> {
        match &mut self.state {
            State::Idle => Err(ErrorCode::Invalid.into()),
            State::Armed(c) if !c.noc_state.is_next(next) => Err(ErrorCode::Invalid.into()),
            State::Armed(c) => {
                c.noc_state = next;
                if c.noc_state.is_final() {
                    // TODO

                    self.state = State::Idle;
                }
                Ok(())
            }
        }
    }
}

impl Default for FailSafe {
    fn default() -> Self {
        Self::new()
    }
}
