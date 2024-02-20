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

use log::{info, trace};
use owo_colors::OwoColorize;

use crate::{
    error::Error,
    interaction_model::core::PROTO_ID_INTERACTION_MODEL,
    secure_channel::common::PROTO_ID_SECURE_CHANNEL,
    tlv,
    utils::{parsebuf::ParseBuf, writebuf::WriteBuf},
};

use super::{
    plain_hdr::{self, PlainHdr},
    proto_hdr::{self, ProtoHdr},
};

pub const MAX_RX_BUF_SIZE: usize = 1583;
pub const MAX_RX_STATUS_BUF_SIZE: usize = 100;
pub const MAX_TX_BUF_SIZE: usize = 1280 - 40/*IPV6 header size*/ - 8/*UDP header size*/;

#[derive(Debug, Default, Clone)]
pub struct PacketHeader {
    pub plain: PlainHdr,
    pub proto: ProtoHdr,
}

impl PacketHeader {
    const HDR_RESERVE: usize = plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len();

    pub fn new() -> Self {
        Default::default()
    }

    pub fn reset(&mut self) {
        self.plain = Default::default();
        self.proto = Default::default();
        self.proto.set_reliable();
    }

    pub fn load(&mut self, packet: &PacketHeader) {
        self.plain = packet.plain.clone();
        self.proto = packet.proto.clone();
    }

    pub fn decode_plain_hdr(&mut self, pb: &mut ParseBuf) -> Result<(), Error> {
        self.plain.decode(pb)
    }

    pub fn decode_remaining(
        &mut self,
        pb: &mut ParseBuf,
        peer_nodeid: u64,
        dec_key: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.proto
            .decrypt_and_decode(&self.plain, pb, peer_nodeid, dec_key)
    }

    pub fn encode(
        &self,
        wb: &mut WriteBuf,
        peer_nodeid: Option<u64>,
        local_nodeid: u64,
        plain_text: bool,
        enc_key: Option<&[u8]>,
    ) -> Result<(), Error> {
        // Generate encrypted header
        let mut tmp_buf = [0_u8; proto_hdr::max_proto_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.proto.encode(&mut write_buf)?;
        wb.prepend(write_buf.as_slice())?;

        // Generate plain-text header
        if plain_text {
            if let Some(d) = peer_nodeid {
                self.plain.set_dest_u64(d);
            }
        }

        let mut tmp_buf = [0_u8; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf);
        self.plain.encode(&mut write_buf)?;
        let plain_hdr_bytes = write_buf.as_slice();

        trace!("unencrypted packet: {:x?}", wb.as_slice());
        let ctr = self.plain.ctr;
        if let Some(e) = enc_key {
            proto_hdr::encrypt_in_place(ctr, local_nodeid, plain_hdr_bytes, wb, e)?;
        }

        wb.prepend(plain_hdr_bytes)?;
        trace!("Full encrypted packet: {:x?}", wb.as_slice());

        Ok(())
    }

    pub fn log(&self, operation: &str, payload: &[u8]) {
        match self.proto.proto_id {
            PROTO_ID_SECURE_CHANNEL => {
                if let Ok(opcode) = self.proto.opcode::<crate::secure_channel::common::OpCode>() {
                    info!("{} SC:{:?}: ", operation.cyan(), opcode);
                } else {
                    info!("{} SC:{}??: ", operation.cyan(), self.proto.proto_opcode);
                }

                tlv::print_tlv_list(payload);
            }
            PROTO_ID_INTERACTION_MODEL => {
                if let Ok(opcode) = self
                    .proto
                    .opcode::<crate::interaction_model::core::OpCode>()
                {
                    info!("{} IM:{:?}: ", operation.cyan(), opcode);
                } else {
                    info!("{} IM:{}??: ", operation.cyan(), self.proto.proto_opcode);
                }

                tlv::print_tlv_list(payload);
            }
            other => info!(
                "{} {}??:{}??: ",
                operation.cyan(),
                other,
                self.proto.proto_opcode
            ),
        }
    }
}
