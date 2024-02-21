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

use crate::utils::epoch::Epoch;
use core::time::Duration;

use crate::{error::*, transport::packet::PacketHeader};
use log::error;

use super::{plain_hdr::PlainHdr, proto_hdr::ProtoHdr};

const MRP_STANDALONE_ACK_TIMEOUT_MS: u64 = 200;
const MRP_BASE_RETRY_INTERVAL_MS: u64 = 200; // TODO: Un-hardcode for Sleepy vs Active devices
const MRP_MAX_TRANSMISSIONS: usize = 10;
const MRP_BACKOFF_THRESHOLD: usize = 3;
const MRP_BACKOFF_BASE: (u64, u64) = (16, 10); // 1.6
                                               //const MRP_BACKOFF_JITTER: (u64, u64) = (25, 100); // 0.25
                                               //const MRP_BACKOFF_MARGIN: (u64, u64) = (11, 10);  // 1.1

#[derive(Debug)]
pub struct RetransEntry {
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    counter: usize,
}

impl RetransEntry {
    pub fn new(msg_ctr: u32) -> Self {
        Self {
            msg_ctr,
            counter: 0,
        }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }

    pub fn retrans_delay_ms(&mut self) -> Option<u64> {
        if self.counter < MRP_MAX_TRANSMISSIONS {
            let mut backoff = MRP_BASE_RETRY_INTERVAL_MS;

            if self.counter >= MRP_BACKOFF_THRESHOLD {
                for _ in 0..self.counter - MRP_BACKOFF_THRESHOLD {
                    backoff = backoff * MRP_BACKOFF_BASE.0 / MRP_BACKOFF_BASE.1;
                }
            }

            self.counter += 1;
            Some(backoff)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct AckEntry {
    // The msg counter that we should acknowledge
    msg_ctr: u32,
    // The max time after which this entry must be ACK
    ack_timeout: Duration,
}

impl AckEntry {
    pub fn new(msg_ctr: u32, epoch: Epoch) -> Result<Self, Error> {
        if let Some(ack_timeout) =
            epoch().checked_add(Duration::from_millis(MRP_STANDALONE_ACK_TIMEOUT_MS))
        {
            Ok(Self {
                msg_ctr,
                ack_timeout,
            })
        } else {
            Err(ErrorCode::Invalid.into())
        }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }

    pub fn has_timed_out(&self, epoch: Epoch) -> bool {
        self.ack_timeout > epoch()
    }
}

#[derive(Default, Debug)]
pub struct ReliableMessage {
    retrans: Option<RetransEntry>,
    ack: Option<AckEntry>,
}

impl ReliableMessage {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn retrans(&mut self) -> Option<&mut RetransEntry> {
        self.retrans.as_mut()
    }

    pub fn is_acknowledged(&self, ctr: u32) -> bool {
        self.retrans
            .map(|retrans| retrans.get_msg_ctr() > ctr)
            .unwrap_or(true)
    }

    pub fn retrans_delay_ms(&self, ctr: u32) -> Result<Option<u64>, ()> {
        if let Some(retrans) = self.retrans.as_ref() {
            if ctr >= retrans.get_msg_ctr() {
                let delay = retrans.retrans_delay_ms().ok_or(())?;

                Ok(Some(delay))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.retrans.is_none() && self.ack.is_none()
    }

    // Check any pending acknowledgements / retransmissions and take action
    pub fn is_ack_ready(&self, epoch: Epoch) -> bool {
        // Acknowledgements
        if let Some(ack_entry) = &self.ack {
            ack_entry.has_timed_out(epoch)
        } else {
            false
        }
    }

    pub fn retrans_ctr(&self) -> Option<u32> {
        self.retrans.as_ref().map(|re| re.msg_ctr)
    }

    pub fn pre_send(&mut self, plain: &PlainHdr, proto: &mut ProtoHdr) -> Result<(), Error> {
        // Check if any acknowledgements are pending for this exchange,

        // if so, piggy back in the encoded header here
        if let Some(ack_entry) = &self.ack {
            // Ack Entry exists, set ACK bit and remove from table
            proto.set_ack(ack_entry.get_msg_ctr());
            self.ack = None;
        }

        if !proto.is_reliable() {
            return Ok(());
        }

        if let Some(retrans) = &self.retrans {
            if retrans.get_msg_ctr() != plain.ctr {
                // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                error!("Previous retrans entry for this exchange already exists");
                Err(ErrorCode::Invalid)?;
            }
        }

        self.retrans = Some(RetransEntry::new(plain.ctr));
        Ok(())
    }

    /* A note about Message ACKs, it is a bit asymmetric in the sense that:
     * -  there can be only one pending ACK per exchange (so this is per-exchange)
     * -  there can be only one pending retransmission per exchange (so this is per-exchange)
     * -  duplicate detection should happen per session (obviously), so that part is per-session
     */
    pub fn recv(&mut self, proto_rx: &PacketHeader, epoch: Epoch) -> Result<(), Error> {
        if proto_rx.proto.is_ack() {
            // Handle received Acks
            let ack_msg_ctr = proto_rx.proto.get_ack_msg_ctr().ok_or(ErrorCode::Invalid)?;
            if let Some(entry) = &self.retrans {
                if entry.get_msg_ctr() != ack_msg_ctr {
                    // TODO: XXX Fix this
                    error!("Mismatch in retrans-table's msg counter and received msg counter: received {}, expected {}. This is expected for the timebeing", ack_msg_ctr, entry.get_msg_ctr());
                }
                self.retrans = None;
            }
        }

        if proto_rx.proto.is_reliable() {
            if self.ack.is_some() {
                // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                // TODO: As per the spec if this happens, we need to send out the previous ACK and note this new ACK
                error!("Previous ACK entry for this exchange already exists");
                Err(ErrorCode::Invalid)?;
            }

            self.ack = Some(AckEntry::new(proto_rx.plain.ctr, epoch)?);
        }
        Ok(())
    }
}
