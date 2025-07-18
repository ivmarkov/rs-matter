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

//! An mDNS implementation based on the `zeroconf` crate.
//! (On Linux requires the Avahi daemon to be installed and running; does not work with `systemd-resolved`.)

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

use zeroconf::{prelude::TEventLoop, service::TMdnsService, txt_record::TTxtRecord, ServiceType};

use crate::error::{Error, ErrorCode};
use crate::transport::network::mdns::Service;
use crate::{Matter, MatterMdnsService};

/// An mDNS responder for Matter utilizing the `zeroconf` crate.
/// In theory, it should work on all of Linux, MacOS and Windows, however seems to have issues on MacOSX and Windows.
pub struct ZeroconfMdnsResponder<'a> {
    matter: &'a Matter<'a>,
    services: HashMap<MatterMdnsService, MdnsEntry>,
}

impl<'a> ZeroconfMdnsResponder<'a> {
    /// Create a new `ZeroconfMdnsResponder` for the given `Matter` instance.
    pub fn new(matter: &'a Matter<'a>) -> Self {
        Self {
            matter,
            services: HashMap::new(),
        }
    }

    /// Run the mDNS responder.
    pub async fn run(&mut self) -> Result<(), Error> {
        loop {
            self.matter.wait_mdns().await;

            let mut services = HashSet::new();
            self.matter.mdns_services(|service| {
                services.insert(service);

                Ok(())
            })?;

            info!("mDNS services changed, updating...");

            self.update_services(&services)?;

            info!("mDNS services updated");
        }
    }

    fn update_services(&mut self, services: &HashSet<MatterMdnsService>) -> Result<(), Error> {
        for service in services {
            if !self.services.contains_key(service) {
                info!("Registering mDNS service: {:?}", service);

                let zeroconf_service = SendableZeroconfMdnsService::new(self.matter, service)?;
                let (sender, receiver) = sync_channel(1);

                // Spawning a thread for each service is not ideal, but unavoidable with the current API of `zeroconf`
                //
                // TODO: What is worse is that if the thread exits with an error, we wouldn't know and we would currently
                // be left with a dangling `MdnsEntry` in the hashmap table

                let _ = std::thread::spawn(move || zeroconf_service.run(receiver));

                self.services.insert(service.clone(), MdnsEntry(sender));
            }
        }

        loop {
            let removed = self
                .services
                .iter()
                .find(|(service, _)| !services.contains(service));

            if let Some((service, _)) = removed {
                info!("Deregistering mDNS service: {:?}", service);
                self.services.remove(&service.clone());
            } else {
                break;
            }
        }

        Ok(())
    }
}

/// This type is necessary because of a number of weird design decisions in the `zeroconf` crate:
/// - `MdnsService` is not `Send` (contains `Rc`s which are not really used?),
///   so we cannot create it in our own thread context and then send it to the worker thread
/// - The need for a worker thread in the first place is also problematic but unavoidable unless
///   the whole `poll` / event loop thing in `zeroconf` is reworked
struct SendableZeroconfMdnsService {
    name: String,
    service_type: ServiceType,
    port: u16,
    txt_kvs: Vec<(String, String)>,
}

impl SendableZeroconfMdnsService {
    /// Create a new `SendableZeroconfMdnsService` from a `MatterMdnsService`.
    fn new(matter: &Matter<'_>, mdns_service: &MatterMdnsService) -> Result<Self, Error> {
        Service::call_with(mdns_service, matter.dev_det(), matter.port(), |service| {
            let service_name = service.service.strip_prefix('_').unwrap_or(service.service);

            let protocol = service
                .protocol
                .strip_prefix('_')
                .unwrap_or(service.protocol);

            let service_type = if !service.service_subtypes.is_empty() {
                let subtypes = service
                    .service_subtypes
                    .iter()
                    .map(|subtype| subtype.strip_prefix('_').unwrap_or(*subtype))
                    .collect();

                ServiceType::with_sub_types(service_name, protocol, subtypes)?
            } else {
                ServiceType::new(service_name, protocol)?
            };

            let txt_kvs = service
                .txt_kvs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>();

            Ok(Self {
                name: service.name.to_string(),
                service_type,
                port: service.port,
                txt_kvs,
            })
        })
    }

    /// Run the service by polling it
    /// Due to the current design of `zeroconf`, this must be run in a separate thread.
    fn run(self, receiver: Receiver<()>) -> Result<(), Error> {
        let mut mdns_service = zeroconf::MdnsService::new(self.service_type, self.port);

        let mut txt_record = zeroconf::TxtRecord::new();
        for (k, v) in &self.txt_kvs {
            trace!("mDNS TXT key {} val {}", k, v);
            txt_record.insert(k, v)?;
        }

        mdns_service.set_name(&self.name);
        mdns_service.set_txt_record(txt_record);
        mdns_service.set_registered_callback(Box::new(|_, _| {}));

        let event_loop = mdns_service.register()?;

        while receiver.try_recv().is_err() {
            event_loop.poll(std::time::Duration::from_secs(1))?;
        }

        Ok(())
    }
}

/// A way to notify the daemon thread for a running mDNS service registration
/// that it should quit.
struct MdnsEntry(SyncSender<()>);

impl Drop for MdnsEntry {
    fn drop(&mut self) {
        if let Err(e) = self.0.send(()) {
            error!("Deregistering mDNS entry failed: {}", debug2format!(e));
        }
    }
}

impl From<zeroconf::error::Error> for Error {
    fn from(e: zeroconf::error::Error) -> Self {
        Self::new_with_details(ErrorCode::MdnsError, Box::new(e))
    }
}
