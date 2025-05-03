//! The network state store for the wireless module.

use core::fmt::{Debug, Display};

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, OctetsOwned, ToTLV};
use crate::utils::init::{init, Init, IntoFallibleInit};
use crate::utils::storage::Vec;

use crate::data_model::sdm::net_comm::WirelessCreds;

use super::{WirelessNetwork, WirelessNetworks};

pub type ThreadNetworks<const N: usize, M> = WirelessNetworks<N, M, Thread>;

/// A struct implementing the `Network` trait for Wifi networks.
#[derive(Debug, Clone, Eq, PartialEq, Hash, ToTLV, FromTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Thread {
    pub dataset: OctetsOwned<256>,
}

impl Default for Thread {
    fn default() -> Self {
        Self::new()
    }
}

impl Thread {
    /// Create a new, empty instance of `Thread`.
    pub const fn new() -> Self {
        Self {
            dataset: OctetsOwned { vec: Vec::new() },
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            dataset <- OctetsOwned::init(),
        })
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn dataset_ext_pan_id(dataset_tlv: &[u8]) -> Result<&[u8], Error> {
        ThreadTLV::new(dataset_tlv).ext_pan_id()
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn ext_pan_id(&self) -> &[u8] {
        unwrap!(Self::dataset_ext_pan_id(&self.dataset.vec))
    }
}

impl WirelessNetwork for Thread {
    fn id(&self) -> &[u8] {
        self.ext_pan_id()
    }

    #[cfg(not(feature = "defmt"))]
    fn display_id(id: &[u8]) -> impl Display {
        use super::DisplayId;

        DisplayId::Thread(id)
    }

    #[cfg(feature = "defmt")]
    fn display_id(id: &[u8]) -> impl Display + defmt::Format {
        use super::DisplayId;

        DisplayId::Thread(id)
    }

    fn init_from<'a>(creds: &'a WirelessCreds<'a>) -> impl Init<Self, Error> + 'a {
        Self::init().into_fallible().chain(move |network| {
            let WirelessCreds::Thread { dataset_tlv } = creds else {
                return Err(ErrorCode::InvalidData.into());
            };

            network
                .dataset
                .vec
                .extend_from_slice(dataset_tlv)
                .map_err(|_| ErrorCode::InvalidData)?;

            Ok(())
        })
    }

    fn update(&mut self, creds: &WirelessCreds<'_>) -> Result<(), Error> {
        let WirelessCreds::Thread { dataset_tlv } = creds else {
            return Err(ErrorCode::InvalidData.into());
        };

        if dataset_tlv.len() > self.dataset.vec.capacity() {
            return Err(ErrorCode::InvalidData.into());
        }

        self.dataset.vec.clear();

        unwrap!(self.dataset.vec.extend_from_slice(dataset_tlv));

        Ok(())
    }

    fn creds(&self) -> WirelessCreds<'_> {
        WirelessCreds::Thread {
            dataset_tlv: &self.dataset.vec,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
/// A simple Thread TLV reader
pub struct ThreadTLV<'a>(&'a [u8]);

impl<'a> ThreadTLV<'a> {
    /// Create a new `ThreadTlvRead` instance with the given TLV data
    pub const fn new(tlv: &'a [u8]) -> Self {
        Self(tlv)
    }

    /// Get the Extended PAN ID from the operational dataset
    pub fn ext_pan_id(&mut self) -> Result<&'a [u8], Error> {
        const EXT_PAN_ID: u8 = 2;

        let ext_pan_id =
            self.find_map(|(tlv_type, tlv_value)| (tlv_type == EXT_PAN_ID).then_some(tlv_value));

        let Some(ext_pan_id) = ext_pan_id else {
            return Err(ErrorCode::InvalidData.into());
        };

        Ok(ext_pan_id)
    }

    /// Get the next TLV from the data
    ///
    /// Returns `Some` with the TLV type and value if there is a TLV available,
    /// otherwise returns `None`.
    pub fn next_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        const LONG_VALUE_ID: u8 = 255;

        // Adopted from here:
        // https://github.com/openthread/openthread/blob/main/tools/tcat_ble_client/tlv/tlv.py

        let mut slice = self.0;

        (slice.len() >= 2).then_some(())?;

        let tlv_type = slice[0];
        slice = &slice[1..];

        let tlv_len_size = if slice[0] == LONG_VALUE_ID {
            slice = &slice[1..];
            3
        } else {
            1
        };

        (slice.len() >= tlv_len_size).then_some(())?;

        let tlv_len = if tlv_len_size == 1 {
            slice[0] as usize
        } else {
            u32::from_be_bytes([0, slice[0], slice[1], slice[2]]) as usize
        };

        slice = &slice[tlv_len_size..];
        (slice.len() >= tlv_len).then_some(())?;

        let tlv_value = &slice[..tlv_len];

        slice = &slice[tlv_len..];

        self.0 = slice;

        Some((tlv_type, tlv_value))
    }
}

impl<'a> Iterator for ThreadTLV<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_tlv()
    }
}
