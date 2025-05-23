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

use crate::error::*;
use crate::utils::epoch::Epoch;

use super::{plain_hdr::PlainHdr, proto_hdr::ProtoHdr};

//const MRP_STANDALONE_ACK_TIMEOUT_MS: u64 = 200;   // TODO: Use to pro-actively send ACKs
const MRP_BASE_RETRY_INTERVAL_MS: u16 = 300;
const MRP_MAX_TRANSMISSIONS: u16 = 10;
const MRP_BACKOFF_THRESHOLD: u16 = 1;
const MRP_BACKOFF_BASE: (u64, u64) = (16, 10); // 1.6
const MRP_BACKOFF_JITTER: (u64, u64) = (25, 100); // 0.25
const MRP_BACKOFF_MARGIN: (u64, u64) = (11, 10); // 1.1
const MRP_JITTER_RAND_MAX: u8 = u8::MAX;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RetransEntry {
    /// The retransmission delay interval in milliseconds
    base_delay_interval_ms: u16,
    // The msg counter that we are waiting to be acknowledged
    msg_ctr: u32,
    // The retransmission counter
    counter: u16,
}

impl RetransEntry {
    pub fn new(base_delay_interval_ms: Option<u16>, msg_ctr: u32) -> Self {
        Self {
            base_delay_interval_ms: base_delay_interval_ms.unwrap_or(MRP_BASE_RETRY_INTERVAL_MS),
            msg_ctr,
            counter: 0,
        }
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }

    /// Return how much to delay before (re)transmitting the message
    /// based on the number of re-transmissions so far
    pub fn delay_ms(&self, jitter_rand: u8) -> u64 {
        self.delay_ms_counter(self.counter, jitter_rand)
    }

    /// Maximum delay before giving up on retransmitting the message
    pub fn max_delay_ms(&self) -> u64 {
        self.delay_ms_counter(MRP_MAX_TRANSMISSIONS, MRP_JITTER_RAND_MAX)
    }

    /// Return how much to delay before (re)transmitting the message
    /// based on the provided number of re-transmissions so far
    pub fn delay_ms_counter(&self, counter: u16, jitter_rand: u8) -> u64 {
        let mut delay =
            self.base_delay_interval_ms as u64 * MRP_BACKOFF_MARGIN.0 / MRP_BACKOFF_MARGIN.1;

        if counter > MRP_BACKOFF_THRESHOLD {
            for _ in 0..counter - MRP_BACKOFF_THRESHOLD {
                delay = delay * MRP_BACKOFF_BASE.0 / MRP_BACKOFF_BASE.1;
            }
        }

        delay + (delay * jitter_rand as u64 * MRP_BACKOFF_JITTER.0) / (255 * MRP_BACKOFF_JITTER.1)
    }

    pub fn pre_send(&mut self, ctr: u32) -> Result<(), Error> {
        if self.msg_ctr == ctr {
            if self.counter < MRP_MAX_TRANSMISSIONS {
                self.counter += 1;
                Ok(())
            } else {
                Err(ErrorCode::TxTimeout.into())
            }
        } else {
            // This indicates there was some existing entry for same sess-id/exch-id, which shouldn't happen
            panic!("Previous retrans entry for this exchange already exists");
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AckEntry {
    // The msg counter that we should acknowledge
    pub(crate) msg_ctr: u32,
    // Whether the message was acknowledged at least once
    pub(crate) acknowledged: bool,
}

impl AckEntry {
    pub fn new(msg_ctr: u32) -> Result<Self, Error> {
        Ok(Self {
            msg_ctr,
            acknowledged: false,
        })
    }

    pub fn get_msg_ctr(&self) -> u32 {
        self.msg_ctr
    }
}

#[derive(Default, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ReliableMessage {
    pub(crate) retrans: Option<RetransEntry>,
    pub(crate) ack: Option<AckEntry>,
    pub(crate) received_at_ms: Option<u64>,
}

impl ReliableMessage {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn is_retrans_pending(&self) -> bool {
        self.retrans.is_some()
    }

    pub fn is_ack_pending(&self) -> bool {
        self.ack
            .as_ref()
            .map(|ack| !ack.acknowledged)
            .unwrap_or(false)
    }

    pub fn has_rx_timed_out(&self, timeout_ms: u64, epoch: Epoch) -> bool {
        self.received_at_ms
            .and_then(|received_at_ms| {
                received_at_ms
                    .checked_add(timeout_ms)
                    .map(|d| d <= epoch().as_millis() as u64)
            })
            .unwrap_or(false)
    }

    pub fn pre_send(
        &mut self,
        tx_plain: &PlainHdr,
        tx_proto: &mut ProtoHdr,
        session_active_interval_ms: Option<u16>,
        // TODO: Need to make use of it in future,
        // once we detect idle vs active devices
        _session_idle_interval_ms: Option<u16>,
    ) -> Result<(), Error> {
        // Check if any acknowledgements are pending for this exchange,
        if let Some(ack) = &mut self.ack {
            // if so, piggy back in the encoded header here
            tx_proto.set_ack(Some(ack.get_msg_ctr()));
            ack.acknowledged = true;
        }

        if tx_proto.is_reliable() {
            if let Some(retrans) = &mut self.retrans {
                if retrans.pre_send(tx_plain.ctr).is_err() {
                    // Too many retransmissions, give up
                    error!(
                        "Packet {}{}: Too many retransmissions. Giving up",
                        tx_plain, tx_proto
                    );

                    self.retrans = None;
                    self.ack = None;
                }
            } else {
                self.retrans = Some(RetransEntry::new(session_active_interval_ms, tx_plain.ctr));
            }
        }

        self.received_at_ms = None;

        Ok(())
    }

    /// This method will update the state of the rentransmission and ACK tables
    /// with the data from the incoming packet.
    ///
    /// The method will return `Ok` if the message needs to be processed by the
    /// exchange layer, and an error if it needs to be dropped.
    ///
    /// A note about Message ACKs, it is a bit asymmetric in the sense that:
    /// - there can be only one pending ACK per exchange (so this is per-exchange)
    /// - there can be only one pending retransmission per exchange (so this is per-exchange)
    /// - duplicate detection should happen per session (obviously), so that part is per-session
    pub fn post_recv(
        &mut self,
        rx_plain: &PlainHdr,
        rx_proto: &ProtoHdr,
        epoch: Epoch,
    ) -> Result<(), Error> {
        if let Some(ack_msg_ctr) = rx_proto.get_ack() {
            // Handle received Acks
            if let Some(entry) = &self.retrans {
                if entry.get_msg_ctr() != ack_msg_ctr {
                    warn!("Mismatch in retrans-table's msg counter and received msg counter: received {:x}, expected {:x}.", ack_msg_ctr, entry.msg_ctr);

                    // This can actually happen on a noisy channel, where we've just sent a reply to a message
                    // - yet - the other side is still retransmitting the original message and thus acknowledging
                    // an earlier counter we've sent.

                    // In this case, we should ignore the ACK and not process this message any further, as it is
                    // a duplicate.
                    Err(ErrorCode::Duplicate)?;
                }

                self.retrans = None;
                self.ack = None;
            }
        }

        if rx_proto.is_reliable() {
            if let Some(ack) = &self.ack {
                // This indicates there was some existing entry for same sess-id/exch-id, which shouldnt happen
                // TODO: As per the spec if this happens, we need to send out the previous ACK and note this new ACK
                error!(
                    "Previous ACK entry {:x} for this exchange already exists",
                    ack.get_msg_ctr()
                );
            }

            self.ack = Some(AckEntry::new(rx_plain.ctr)?);
        }

        self.received_at_ms = Some(epoch().as_millis() as u64);

        Ok(())
    }
}
