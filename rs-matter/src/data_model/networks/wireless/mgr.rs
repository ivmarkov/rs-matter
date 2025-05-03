//! The network state store for the wireless module.

use embassy_time::{Duration, Timer};

use crate::data_model::sdm::net_comm::{self, NetworkError};
use crate::error::{Error, ErrorCode};

use crate::data_model::sdm::net_comm::WirelessCreds;
use crate::data_model::sdm::wifi_diag;
use crate::data_model::sdm::wifi_diag::WirelessDiag;

use super::thread::Thread;
use super::{NetChangeNotif, OwnedWirelessNetworkId};

pub struct WirelessMgr<'a, W, T> {
    networks: W,
    net_ctl: T,
    buf: &'a mut [u8],
}

impl<'a, W, T> WirelessMgr<'a, W, T>
where
    W: net_comm::Networks + NetChangeNotif,
    T: net_comm::NetCtl + wifi_diag::WirelessDiag + NetChangeNotif,
{
    pub const fn new(networks: W, net_ctl: T, buf: &'a mut [u8]) -> Self {
        Self {
            networks,
            net_ctl,
            buf,
        }
    }

    /// Runs the wireless manager.
    ///
    /// This function will try to connect to the networks in a round-robin fashion
    /// and will retry the connection in case of a failure.
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            Self::run_connect(&self.networks, &self.net_ctl, self.buf).await?;
        }
    }

    async fn run_connect(networks: &W, net_ctl: &T, buf: &mut [u8]) -> Result<(), Error> {
        loop {
            Self::wait_connect_while(&net_ctl, false).await?;

            let mut network_id = OwnedWirelessNetworkId::new();

            let mut c = None;

            networks.next_creds(
                (!network_id.is_empty()).then_some(&network_id),
                &mut |creds| {
                    match creds {
                        WirelessCreds::Wifi { ssid, pass } => {
                            buf[..ssid.len()].copy_from_slice(ssid);
                            buf[ssid.len()..][..pass.len()].copy_from_slice(pass);

                            c = Some((ssid.len(), Some(pass.len())))
                        }
                        WirelessCreds::Thread { dataset_tlv } => {
                            buf[..dataset_tlv.len()].copy_from_slice(dataset_tlv);

                            c = Some((dataset_tlv.len(), None))
                        }
                    }

                    Ok(())
                },
            )?;

            if let Some((len1, len2)) = c {
                let creds = if let Some(len2) = len2 {
                    WirelessCreds::Wifi {
                        ssid: &buf[..len1],
                        pass: &buf[len1..][..len2],
                    }
                } else {
                    WirelessCreds::Thread {
                        dataset_tlv: &buf[..len1],
                    }
                };

                network_id.clear();
                match creds {
                    WirelessCreds::Wifi { ssid, .. } => {
                        network_id
                            .extend_from_slice(ssid)
                            .map_err(|_| ErrorCode::InvalidData)?;
                    }
                    WirelessCreds::Thread { dataset_tlv } => {
                        network_id
                            .extend_from_slice(Thread::dataset_ext_pan_id(dataset_tlv)?)
                            .map_err(|_| ErrorCode::InvalidData)?;
                    }
                }

                Self::connect_with_retries(net_ctl, &creds).await?;
            } else {
                networks.wait_changed().await;
            }
        }
    }

    async fn connect_with_retries(net_ctl: &T, creds: &WirelessCreds<'_>) -> Result<(), Error> {
        loop {
            let mut result = Ok(());

            for delay in [2, 5, 10].iter().copied() {
                info!("Connecting to network with ID {}", creds);

                result = net_ctl.connect(creds).await;

                if result.is_ok() {
                    break;
                } else {
                    warn!(
                        "Connection to network with ID {} failed: {:?}, retrying in {}s",
                        creds, result, delay
                    );
                }

                Timer::after(Duration::from_secs(delay)).await;
            }

            // TODO
            // context.state.lock(|state| {
            //     let mut state = state.borrow_mut();

            //     if result.is_ok() {
            //         state.connected_once = true;
            //     }

            //     state.status = Some(NetworkStatus {
            //         network_id: creds.network_id().clone(),
            //         status: if result.is_ok() {
            //             NetworkCommissioningStatus::Success
            //         } else {
            //             NetworkCommissioningStatus::OtherConnectionFailure
            //         },
            //         value: 0,
            //     });
            // });

            if let Err(e) = result {
                error!("Failed to connect to network with ID {}: {:?}", creds, e);

                break match e {
                    NetworkError::Other(e) => Err(e),
                    _ => Err(ErrorCode::Invalid.into()),
                };
            } else {
                info!("Connected to network with ID {}", creds);

                Self::wait_connect_while(&net_ctl, true).await?;
            }
        }
    }

    async fn wait_connect_while<N>(net_ctl: N, connected: bool) -> Result<(), Error>
    where
        N: WirelessDiag + NetChangeNotif,
    {
        loop {
            if net_ctl.connected()? == connected {
                break;
            }

            net_ctl.wait_changed().await;
        }

        Ok(())
    }
}
