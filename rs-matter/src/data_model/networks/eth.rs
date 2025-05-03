//! This module contains the `Networks` trait implementation for Ethernet.

use crate::data_model::sdm::net_comm::{
    self, NetCtl, NetworkCommissioningStatusEnum, NetworkError, NetworkScanInfo, NetworkType,
};
use crate::error::{Error, ErrorCode};

use crate::data_model::sdm::net_comm::WirelessCreds;

/// A fixed `Networks` trait implementation for Ethernet.
///
/// Ethernet does not need to manage networks, so it always reports 1 network
/// and returns an error when trying to add or update networks.
pub struct EthNetwork<'a> {
    network_id: &'a str,
}

impl<'a> EthNetwork<'a> {
    /// Creates a new `EthNetwork` instance.
    pub const fn new(network_id: &'a str) -> Self {
        Self { network_id }
    }
}

impl net_comm::Networks for EthNetwork<'_> {
    fn max_networks(&self) -> Result<u8, Error> {
        Ok(1)
    }

    fn networks(
        &self,
        f: &mut dyn FnMut(&net_comm::NetworkInfo) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(&net_comm::NetworkInfo {
            network_id: self.network_id.as_bytes(),
            connected: false, // TODO
        })
    }

    fn creds(
        &self,
        _network_id: &[u8],
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworkError> {
        Err(net_comm::NetworkError::Other(
            ErrorCode::InvalidAction.into(),
        ))
    }

    fn next_creds(
        &self,
        _last_network_id: Option<&[u8]>,
        _f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        Err(ErrorCode::InvalidAction.into())
    }

    fn enabled(&self) -> Result<bool, Error> {
        Ok(true)
    }

    fn set_enabled(&self, _enabled: bool) -> Result<(), Error> {
        Ok(())
    }

    fn add_or_update(&self, _creds: &WirelessCreds<'_>) -> Result<u8, NetworkError> {
        Err(net_comm::NetworkError::Other(
            ErrorCode::InvalidAction.into(),
        ))
    }

    fn reorder(&self, _index: u8, _network_id: &[u8]) -> Result<u8, NetworkError> {
        Err(net_comm::NetworkError::Other(
            ErrorCode::InvalidAction.into(),
        ))
    }

    fn remove(&self, _network_id: &[u8]) -> Result<u8, NetworkError> {
        Err(net_comm::NetworkError::Other(
            ErrorCode::InvalidAction.into(),
        ))
    }
}

/// A `net_comm::NetCtl` implementation for Ethernet that errors out on all methods.
pub struct EthNetCtl;

impl NetCtl for EthNetCtl {
    fn net_type(&self) -> NetworkType {
        NetworkType::Ethernet
    }

    async fn scan<F>(&self, _network: Option<&[u8]>, _f: F) -> Result<(), NetworkError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        Err(NetworkError::Other(ErrorCode::InvalidAction.into()))
    }

    async fn connect(&self, _creds: &WirelessCreds<'_>) -> Result<(), NetworkError> {
        Err(NetworkError::Other(ErrorCode::InvalidAction.into()))
    }

    async fn last_networking_status(
        &self,
    ) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        Ok(None)
    }

    async fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        f(None)
    }

    async fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        Ok(None)
    }
}
