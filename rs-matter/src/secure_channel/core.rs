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

use log::error;

use crate::{
    alloc,
    error::*,
    secure_channel::{common::*, pake::Pake},
    transport::exchange::Exchange,
};

use super::{
    case::{Case, CaseSession},
    spake2p::Spake2P,
};

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel(());

impl SecureChannel {
    #[inline(always)]
    pub const fn new() -> Self {
        Self(())
    }

    pub async fn handle(&self, mut exchange: Exchange<'_>) -> Result<(), Error> {
        let opcode = exchange.rx().await?.meta().opcode()?;

        match opcode {
            OpCode::PBKDFParamRequest => {
                let mut spake2p = alloc!(Spake2P::new());
                Pake::new().handle(exchange, &mut spake2p).await
            }
            OpCode::CASESigma1 => {
                let mut case_session = alloc!(CaseSession::new());
                Case::new().handle(exchange, &mut case_session).await
            }
            proto_opcode => {
                error!("OpCode not handled: {:?}", proto_opcode);
                Err(ErrorCode::InvalidOpcode.into())
            }
        }
    }
}

impl Default for SecureChannel {
    fn default() -> Self {
        Self::new()
    }
}
