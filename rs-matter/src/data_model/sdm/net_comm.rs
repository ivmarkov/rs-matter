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

use crate::data_model::networks::wireless::{Thread, ThreadTLV, MAX_NETWORK_ID_LEN};
use crate::data_model::objects::{
    ArrayAttributeRead, Cluster, Dataver, InvokeContext, ReadContext, WriteContext,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::{
    Nullable, NullableBuilder, Octets, OctetsBuilder, TLVBuilder, TLVBuilderParent, TLVWrite,
};
use crate::{clusters, with};

pub use crate::data_model::clusters::network_commissioning::*;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkType {
    Ethernet,
    Wifi,
    Thread,
}

impl NetworkType {
    pub const fn cluster(&self) -> Cluster<'static> {
        match self {
            Self::Ethernet => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::ETHERNET_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required))
                .with_cmds(with!()),
            Self::Wifi => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::WI_FI_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required; AttributeId::ScanMaxTimeSeconds | AttributeId::ConnectMaxTimeSeconds | AttributeId::SupportedWiFiBands))
                .with_cmds(with!(CommandId::AddOrUpdateWiFiNetwork | CommandId::ScanNetworks | CommandId::RemoveNetwork | CommandId::ConnectNetwork | CommandId::ReorderNetwork)),
            Self::Thread => FULL_CLUSTER
                .with_revision(1)
                .with_features(Feature::THREAD_NETWORK_INTERFACE.bits())
                .with_attrs(with!(required; AttributeId::ScanMaxTimeSeconds | AttributeId::ConnectMaxTimeSeconds | AttributeId::ThreadVersion | AttributeId::SupportedThreadFeatures))
                .with_cmds(with!(CommandId::AddOrUpdateThreadNetwork | CommandId::ScanNetworks | CommandId::RemoveNetwork | CommandId::ConnectNetwork | CommandId::ReorderNetwork)),
        }
    }

    pub const fn root_clusters(&self) -> &'static [Cluster<'static>] {
        static ETH: &[Cluster<'static>] = clusters!(eth;);
        static WIFI: &[Cluster<'static>] = clusters!(wifi;);
        static THREAD: &[Cluster<'static>] = clusters!(thread;);

        match self {
            Self::Ethernet => ETH,
            Self::Wifi => WIFI,
            Self::Thread => THREAD,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInfo<'a> {
    pub network_id: &'a [u8],
    pub connected: bool,
}

impl NetworkInfo<'_> {
    fn read_into<P: TLVBuilderParent>(
        &self,
        builder: NetworkInfoStructBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .network_id(Octets::new(self.network_id))?
            .connected(self.connected)?
            .network_identifier(None)?
            .client_identifier(None)?
            .end()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkScanInfo<'a> {
    Wifi {
        security: WiFiSecurityBitmap,
        ssid: &'a [u8],
        bssid: &'a [u8],
        channel: u16,
        band: WiFiBandEnum,
        rssi: i8,
    },
    Thread {
        pan_id: u16,
        ext_pan_id: u64,
        network_name: &'a str,
        channel: u16,
        version: u8,
        ext_addr: &'a [u8],
        rssi: i8,
        lqi: u8,
    },
}

impl NetworkScanInfo<'_> {
    pub fn wifi_read_into<P: TLVBuilderParent>(
        &self,
        builder: WiFiInterfaceScanResultStructBuilder<P>,
    ) -> Result<P, Error> {
        let NetworkScanInfo::Wifi {
            security,
            ssid,
            bssid,
            channel,
            band,
            rssi,
        } = self
        else {
            panic!("Wifi scan info expected");
        };

        builder
            .security(*security)?
            .ssid(Octets::new(ssid))?
            .bssid(Octets::new(bssid))?
            .channel(*channel)?
            .wi_fi_band(*band)?
            .rssi(*rssi)?
            .end()
    }

    pub fn thread_read_into<P: TLVBuilderParent>(
        &self,
        builder: ThreadInterfaceScanResultStructBuilder<P>,
    ) -> Result<P, Error> {
        let NetworkScanInfo::Thread {
            pan_id,
            ext_pan_id: extended_pan_id,
            network_name,
            channel,
            version,
            ext_addr,
            rssi,
            lqi,
        } = self
        else {
            panic!("Thread scan info expected");
        };

        builder
            .pan_id(*pan_id)?
            .extended_pan_id(*extended_pan_id)?
            .network_name(network_name)?
            .channel(*channel)?
            .version(*version)?
            .extended_address(Octets::new(ext_addr))?
            .rssi(*rssi)?
            .lqi(*lqi)?
            .end()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum WirelessCreds<'a> {
    Wifi { ssid: &'a [u8], pass: &'a [u8] },
    Thread { dataset_tlv: &'a [u8] },
}

impl WirelessCreds<'_> {
    pub fn id(&self) -> Result<&[u8], Error> {
        match self {
            WirelessCreds::Wifi { ssid, .. } => Ok(ssid),
            WirelessCreds::Thread { dataset_tlv } => Thread::dataset_ext_pan_id(dataset_tlv),
        }
    }

    pub fn check_match(&self, net_type: NetworkType) -> Result<(), Error> {
        match self {
            WirelessCreds::Wifi { .. } if matches!(net_type, NetworkType::Wifi) => Ok(()),
            WirelessCreds::Thread { .. } if matches!(net_type, NetworkType::Thread) => Ok(()),
            _ => Err(ErrorCode::InvalidAction.into()),
        }
    }
}

impl fmt::Display for WirelessCreds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WirelessCreds::Wifi { ssid, .. } => write!(
                f,
                "SSID({})",
                core::str::from_utf8(ssid).ok().unwrap_or("???")
            ),
            WirelessCreds::Thread { dataset_tlv } => write!(
                f,
                "ExtEpanId({:?})",
                ThreadTLV::new(dataset_tlv).ext_pan_id().ok().unwrap_or(&[])
            ),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for WirelessCreds<'_> {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            WirelessCreds::Wifi { ssid, .. } => defmt::write!(
                fmt,
                "SSID({})",
                core::str::from_utf8(ssid).ok().unwrap_or("???")
            ),
            WirelessCreds::Thread { dataset_tlv } => defmt::write!(
                fmt,
                "ExtEpanId({:?})",
                ThreadTLV::new(dataset_tlv).ext_pan_id().ok().unwrap_or(&[])
            ),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkError {
    NotFound,
    Duplicate,
    OutOfRange,
    BoundsExceeded,
    Other(Error),
}

impl From<Error> for NetworkError {
    fn from(err: Error) -> Self {
        NetworkError::Other(err)
    }
}

impl NetworkCommissioningStatusEnum {
    pub fn map(
        result: Result<u8, NetworkError>,
    ) -> Result<(NetworkCommissioningStatusEnum, Option<u8>), Error> {
        match result {
            Ok(index) => Ok((NetworkCommissioningStatusEnum::Success, Some(index))),
            Err(NetworkError::NotFound) => {
                Ok((NetworkCommissioningStatusEnum::NetworkNotFound, None))
            }
            Err(NetworkError::Duplicate) => {
                Ok((NetworkCommissioningStatusEnum::DuplicateNetworkID, None))
            }
            Err(NetworkError::OutOfRange) => Ok((NetworkCommissioningStatusEnum::OutOfRange, None)),
            Err(NetworkError::BoundsExceeded) => {
                Ok((NetworkCommissioningStatusEnum::BoundsExceeded, None))
            }
            Err(NetworkError::Other(err)) => Err(err),
        }
    }

    pub fn read_into<P: TLVBuilderParent>(
        &self,
        index: Option<u8>,
        builder: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        builder
            .networking_status(*self)?
            .debug_text(None)?
            .network_index(index)?
            .client_identity(None)?
            .possession_signature(None)?
            .end()
    }
}

pub trait Networks {
    fn max_networks(&self) -> Result<u8, Error>;

    fn networks(&self, f: &mut dyn FnMut(&NetworkInfo) -> Result<(), Error>) -> Result<(), Error>;

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworkError>;

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error>;

    fn enabled(&self) -> Result<bool, Error>;

    fn set_enabled(&self, enabled: bool) -> Result<(), Error>;

    fn add_or_update(&self, creds: &WirelessCreds<'_>) -> Result<u8, NetworkError>;

    fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworkError>;

    fn remove(&self, network_id: &[u8]) -> Result<u8, NetworkError>;
}

impl<T> Networks for &T
where
    T: Networks,
{
    fn max_networks(&self) -> Result<u8, Error> {
        (*self).max_networks()
    }

    fn networks(&self, f: &mut dyn FnMut(&NetworkInfo) -> Result<(), Error>) -> Result<(), Error> {
        (*self).networks(f)
    }

    fn creds(
        &self,
        network_id: &[u8],
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<u8, NetworkError> {
        (*self).creds(network_id, f)
    }

    fn next_creds(
        &self,
        last_network_id: Option<&[u8]>,
        f: &mut dyn FnMut(&WirelessCreds) -> Result<(), Error>,
    ) -> Result<bool, Error> {
        (*self).next_creds(last_network_id, f)
    }

    fn enabled(&self) -> Result<bool, Error> {
        (*self).enabled()
    }

    fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        (*self).set_enabled(enabled)
    }

    fn add_or_update(&self, creds: &WirelessCreds<'_>) -> Result<u8, NetworkError> {
        (*self).add_or_update(creds)
    }

    fn reorder(&self, index: u8, network_id: &[u8]) -> Result<u8, NetworkError> {
        (*self).reorder(index, network_id)
    }

    fn remove(&self, network_id: &[u8]) -> Result<u8, NetworkError> {
        (*self).remove(network_id)
    }
}

pub trait NetCtl {
    fn net_type(&self) -> NetworkType;

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetworkError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>;

    async fn connect(&self, creds: &WirelessCreds) -> Result<(), NetworkError>;

    async fn last_networking_status(&self)
        -> Result<Option<NetworkCommissioningStatusEnum>, Error>;

    async fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>;

    async fn last_connect_error_value(&self) -> Result<Option<i32>, Error>;
}

impl<T> NetCtl for &T
where
    T: NetCtl,
{
    fn net_type(&self) -> NetworkType {
        (*self).net_type()
    }

    async fn scan<F>(&self, network: Option<&[u8]>, f: F) -> Result<(), NetworkError>
    where
        F: FnMut(&NetworkScanInfo) -> Result<(), Error>,
    {
        (*self).scan(network, f).await
    }

    async fn connect(&self, creds: &WirelessCreds<'_>) -> Result<(), NetworkError> {
        (*self).connect(creds).await
    }

    async fn last_networking_status(
        &self,
    ) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        (*self).last_networking_status().await
    }

    async fn last_network_id<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(Option<&[u8]>) -> Result<R, Error>,
    {
        (*self).last_network_id(f).await
    }

    async fn last_connect_error_value(&self) -> Result<Option<i32>, Error> {
        (*self).last_connect_error_value().await
    }
}

pub struct NetCommHandler<'a, T> {
    dataver: Dataver,
    networks: &'a dyn Networks,
    net_ctl: T,
}

impl<'a, T> NetCommHandler<'a, T> {
    pub const fn new(dataver: Dataver, networks: &'a dyn Networks, net_ctl: T) -> Self {
        Self {
            dataver,
            networks,
            net_ctl,
        }
    }

    /// Adapt the handler instance to the generic `rs-matter` `AsyncHandler` trait
    pub const fn adapt(self) -> HandlerAsyncAdaptor<Self> {
        HandlerAsyncAdaptor(self)
    }
}

impl<T> ClusterAsyncHandler for NetCommHandler<'_, T>
where
    T: NetCtl,
{
    const CLUSTER: Cluster<'static> = NetworkType::Ethernet.cluster(); // TODO

    fn dataver(&self) -> u32 {
        self.dataver.get()
    }

    fn dataver_changed(&self) {
        self.dataver.changed();
    }

    async fn max_networks(&self, _ctx: &ReadContext<'_>) -> Result<u8, Error> {
        self.networks.max_networks()
    }

    async fn networks<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: ArrayAttributeRead<NetworkInfoStructArrayBuilder<P>, NetworkInfoStructBuilder<P>>,
    ) -> Result<P, Error> {
        match builder {
            ArrayAttributeRead::ReadAll(builder) => builder.with(|builder| {
                let mut builder = Some(builder);

                self.networks.networks(&mut |ni| {
                    builder = Some(ni.read_into(unwrap!(builder.take()).push()?)?);

                    Ok(())
                })?;

                unwrap!(builder.take()).end()
            }),
            ArrayAttributeRead::ReadOne(index, builder) => {
                let mut current = 0;
                let mut builder = Some(builder);
                let mut parent = None;

                self.networks.networks(&mut |ni| {
                    if current == index {
                        parent = Some(ni.read_into(unwrap!(builder.take()))?);
                    }

                    current += 1;

                    Ok(())
                })?;

                if let Some(parent) = parent {
                    Ok(parent)
                } else {
                    Err(ErrorCode::ConstraintError.into())
                }
            }
        }
    }

    async fn interface_enabled(&self, _ctx: &ReadContext<'_>) -> Result<bool, Error> {
        self.networks.enabled()
    }

    async fn last_networking_status(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<NetworkCommissioningStatusEnum>, Error> {
        Ok(Nullable::new(self.net_ctl.last_networking_status().await?))
    }

    async fn last_network_id<P: TLVBuilderParent>(
        &self,
        _ctx: &ReadContext<'_>,
        builder: NullableBuilder<P, OctetsBuilder<P>>,
    ) -> Result<P, Error> {
        self.net_ctl
            .last_network_id(|network_id| {
                if let Some(network_id) = network_id {
                    builder.non_null()?.set(Octets::new(network_id))
                } else {
                    builder.null()
                }
            })
            .await
    }

    async fn last_connect_error_value(
        &self,
        _ctx: &ReadContext<'_>,
    ) -> Result<Nullable<i32>, Error> {
        Ok(Nullable::new(
            self.net_ctl.last_connect_error_value().await?,
        ))
    }

    async fn set_interface_enabled(
        &self,
        _ctx: &WriteContext<'_>,
        value: bool,
    ) -> Result<(), Error> {
        self.networks.set_enabled(value)
    }

    async fn handle_scan_networks<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ScanNetworksRequest<'_>,
        response: ScanNetworksResponseBuilder<P>,
    ) -> Result<P, Error> {
        match self.net_ctl.net_type() {
            NetworkType::Thread => {
                let mut builder = Some(response);
                let mut array_builder = None;

                let (status, _) = NetworkCommissioningStatusEnum::map(
                    self.net_ctl
                        .scan(
                            request
                                .ssid()?
                                .as_ref()
                                .and_then(|ssid| ssid.as_opt_ref())
                                .map(|ssid| ssid.0),
                            |network| {
                                let abuilder = if let Some(builder) = builder.take() {
                                    builder
                                        .networking_status(NetworkCommissioningStatusEnum::Success)?
                                        .debug_text(None)?
                                        .wi_fi_scan_results()?
                                        .none()
                                        .thread_scan_results()?
                                        .some()?
                                } else {
                                    unwrap!(array_builder.take())
                                };

                                array_builder = Some(network.thread_read_into(abuilder.push()?)?);

                                Ok(())
                            },
                        )
                        .await
                        .map(|_| 0),
                )?;

                if let Some(builder) = builder {
                    builder
                        .networking_status(status)?
                        .debug_text(None)?
                        .wi_fi_scan_results()?
                        .none()
                        .thread_scan_results()?
                        .none()
                        .end()
                } else {
                    unwrap!(array_builder.take()).end()?.end()
                }
            }
            NetworkType::Wifi => {
                let mut builder = Some(response);
                let mut array_builder = None;

                let (status, _) = NetworkCommissioningStatusEnum::map(
                    self.net_ctl
                        .scan(
                            request
                                .ssid()?
                                .as_ref()
                                .and_then(|ssid| ssid.as_opt_ref())
                                .map(|ssid| ssid.0),
                            |network| {
                                let abuilder = if let Some(builder) = builder.take() {
                                    builder
                                        .networking_status(NetworkCommissioningStatusEnum::Success)?
                                        .debug_text(None)?
                                        .wi_fi_scan_results()?
                                        .some()?
                                } else {
                                    unwrap!(array_builder.take())
                                };

                                array_builder = Some(network.wifi_read_into(abuilder.push()?)?);

                                Ok(())
                            },
                        )
                        .await
                        .map(|_| 0),
                )?;

                if let Some(builder) = builder {
                    builder
                        .networking_status(status)?
                        .debug_text(None)?
                        .wi_fi_scan_results()?
                        .none()
                        .thread_scan_results()?
                        .none()
                        .end()
                } else {
                    unwrap!(array_builder.take())
                        .end()?
                        .thread_scan_results()?
                        .none()
                        .end()
                }
            }
            NetworkType::Ethernet => Err(ErrorCode::InvalidAction.into()), // TODO
        }
    }

    async fn handle_add_or_update_wi_fi_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: AddOrUpdateWiFiNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, index) = NetworkCommissioningStatusEnum::map(self.networks.add_or_update(
            &WirelessCreds::Wifi {
                ssid: request.ssid()?.0,
                pass: request.credentials()?.0,
            },
        ))?;

        status.read_into(index, response)
    }

    async fn handle_add_or_update_thread_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: AddOrUpdateThreadNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, index) = NetworkCommissioningStatusEnum::map(self.networks.add_or_update(
            &WirelessCreds::Thread {
                dataset_tlv: request.operational_dataset()?.0,
            },
        ))?;

        status.read_into(index, response)
    }

    async fn handle_remove_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: RemoveNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, index) =
            NetworkCommissioningStatusEnum::map(self.networks.remove(request.network_id()?.0))?;

        status.read_into(index, response)
    }

    async fn handle_connect_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ConnectNetworkRequest<'_>,
        mut response: ConnectNetworkResponseBuilder<P>,
    ) -> Result<P, Error> {
        if request.network_id()?.0.len() > MAX_NETWORK_ID_LEN {
            return Err(ErrorCode::InvalidAction.into());
        }

        let status = match self.net_ctl.net_type() {
            NetworkType::Thread => {
                let dataset_buf = response.writer().available_space();
                let mut dataset_len = 0;

                let (mut status, index) = NetworkCommissioningStatusEnum::map(
                    self.networks.creds(request.network_id()?.0, &mut |creds| {
                        let WirelessCreds::Thread { dataset_tlv } = creds else {
                            panic!("Thread creds expected");
                        };

                        // TODO: Check for out of boundary
                        dataset_buf[..dataset_tlv.len()].copy_from_slice(dataset_tlv);
                        dataset_len = dataset_tlv.len();

                        Ok(())
                    }),
                )?;

                if matches!(status, NetworkCommissioningStatusEnum::Success) {
                    (status, _) = NetworkCommissioningStatusEnum::map(
                        self.net_ctl
                            .connect(&WirelessCreds::Thread {
                                dataset_tlv: &dataset_buf[..dataset_len],
                            })
                            .await
                            .map(|_| unwrap!(index) as _),
                    )?;
                }

                status
            }
            NetworkType::Wifi => {
                let buf = response.writer().available_space();
                let (ssid_buf, pass_buf) = buf.split_at_mut(buf.len() / 2);
                let mut ssid_len = 0;
                let mut pass_len = 0;

                let (mut status, index) = NetworkCommissioningStatusEnum::map(
                    self.networks.creds(request.network_id()?.0, &mut |creds| {
                        let WirelessCreds::Wifi { ssid, pass } = creds else {
                            panic!("Wifi creds expected");
                        };

                        // TODO: Check for out of boundary
                        ssid_buf[..ssid.len()].copy_from_slice(ssid);
                        ssid_len = ssid.len();
                        pass_buf[..pass.len()].copy_from_slice(pass);
                        pass_len = pass.len();

                        Ok(())
                    }),
                )?;

                if matches!(status, NetworkCommissioningStatusEnum::Success) {
                    (status, _) = NetworkCommissioningStatusEnum::map(
                        self.net_ctl
                            .connect(&WirelessCreds::Wifi {
                                ssid: &ssid_buf[..ssid_len],
                                pass: &pass_buf[..pass_len],
                            })
                            .await
                            .map(|_| unwrap!(index) as _),
                    )?;
                }

                status
            }
            NetworkType::Ethernet => {
                return Err(ErrorCode::InvalidAction.into());
            }
        };

        let err = if matches!(status, NetworkCommissioningStatusEnum::Success) {
            None
        } else {
            Some(-1)
        };

        response
            .networking_status(status)?
            .debug_text(None)?
            .error_value(Nullable::new(err))?
            .end()
    }

    async fn handle_reorder_network<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        request: ReorderNetworkRequest<'_>,
        response: NetworkConfigResponseBuilder<P>,
    ) -> Result<P, Error> {
        let (status, index) = NetworkCommissioningStatusEnum::map(
            self.networks
                .reorder(request.network_index()? as _, request.network_id()?.0),
        )?;

        status.read_into(index, response)
    }

    async fn handle_query_identity<P: TLVBuilderParent>(
        &self,
        _ctx: &InvokeContext<'_>,
        _request: QueryIdentityRequest<'_>,
        _response: QueryIdentityResponseBuilder<P>,
    ) -> Result<P, Error> {
        Err(ErrorCode::InvalidAction.into())
    }
}
