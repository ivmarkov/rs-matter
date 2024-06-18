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

use core::cell::RefCell;
use core::fmt::Write;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::utils::notification::Notification;

#[cfg(all(feature = "std", target_os = "macos"))]
#[path = "mdns/astro.rs"]
mod builtin;
#[cfg(not(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
)))]
mod builtin;
#[cfg(all(feature = "std", feature = "zeroconf", target_os = "linux"))]
#[path = "mdns/zeroconf.rs"]
mod builtin;

#[cfg(not(all(
    feature = "std",
    any(target_os = "macos", all(feature = "zeroconf", target_os = "linux"))
)))]
pub use builtin::{
    Host, MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR, MDNS_PORT, MDNS_SOCKET_BIND_ADDR,
};

/// A trait representing an mDNS implementation capable of registering and de-registering Matter-specific services
pub trait Mdns {
    /// Remove all Matter-specific services registered in the responder
    fn reset(&self);

    /// Register a new service; if it is already registered, it will be updated
    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error>;

    /// Remove a service; if service with that name is not registered, it will be ignored
    fn remove(&self, service: &str) -> Result<(), Error>;
}

impl<T> Mdns for &mut T
where
    T: Mdns,
{
    fn reset(&self) {
        (**self).reset();
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        (**self).add(service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        (**self).remove(service)
    }
}

impl<T> Mdns for &T
where
    T: Mdns,
{
    fn reset(&self) {
        (**self).reset();
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        (**self).add(service, mode)
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        (**self).remove(service)
    }
}

/// Models the mDNS implementation to be used by the Matter stack
pub enum MdnsService<'a> {
    /// Use the built-in mDNS registry, but don't start an mDNS responder
    /// It is up to the user to listen to changes in the registry and manage
    /// their own mDNS responder.
    /// Also useful for unit and integration tests.
    Registry,
    /// Use the built-in mDNS implementation, which is based on:
    /// - Bonjour on macOS;
    /// - Avahi on Linux (if feature `zeroconf` is enabled);
    /// - Our own pure-Rust implementation in all other cases, where
    ///   the built-in implementation is implemented as a decoration of the
    ///   built-registry.
    Builtin,
    /// Use an mDNS implementation provided by the user.
    Provided(&'a dyn Mdns),
}

impl<'a> MdnsService<'a> {
    pub(crate) const fn new_impl(
        &self,
        dev_det: &'a BasicInfoConfig<'a>,
        port: u16,
    ) -> MdnsImpl<'a> {
        match self {
            Self::Registry => MdnsImpl::Registry(MdnsRegistry::new(dev_det, port)),
            Self::Builtin => MdnsImpl::Builtin(MdnsRegistry::new(dev_det, port)),
            Self::Provided(mdns) => MdnsImpl::Provided(*mdns),
        }
    }
}

pub(crate) enum MdnsImpl<'a> {
    Registry(MdnsRegistry<'a>),
    Builtin(MdnsRegistry<'a>),
    Provided(&'a dyn Mdns),
}

impl<'a> Mdns for MdnsImpl<'a> {
    fn reset(&self) {
        match self {
            Self::Registry(mdns) => mdns.reset(),
            Self::Builtin(mdns) => mdns.reset(),
            Self::Provided(mdns) => mdns.reset(),
        }
    }

    fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        match self {
            Self::Registry(mdns) => mdns.add(service, mode),
            Self::Builtin(mdns) => mdns.add(service, mode),
            Self::Provided(mdns) => mdns.add(service, mode),
        }
    }

    fn remove(&self, service: &str) -> Result<(), Error> {
        match self {
            Self::Registry(mdns) => mdns.remove(service),
            Self::Builtin(mdns) => mdns.remove(service),
            Self::Provided(mdns) => mdns.remove(service),
        }
    }
}

/// Status of a service registered in the mDNS responder
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ServiceMode {
    /// The commissioned state
    Commissioned,
    /// The commissionable state with the discriminator that should be used
    Commissionable(u16),
}

const MAX_MATTER_SERVICES: usize = 4;
const MAX_MATTER_SERVICE_NAME_LEN: usize = 40;

/// A registry of Matter-specific services to be reported by the mDNS responder.
pub struct MdnsRegistry<'a> {
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<
        heapless::Vec<
            (heapless::String<MAX_MATTER_SERVICE_NAME_LEN>, ServiceMode),
            MAX_MATTER_SERVICES,
        >,
    >,
    notification: Notification<NoopRawMutex>,
}

impl<'a> MdnsRegistry<'a> {
    /// Create a new mDNS registry
    #[inline(always)]
    pub const fn new(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> Self {
        Self {
            dev_det,
            matter_port,
            services: RefCell::new(heapless::Vec::new()),
            notification: Notification::new(),
        }
    }

    /// Get the device details
    pub const fn dev_det(&self) -> &BasicInfoConfig {
        self.dev_det
    }

    /// Get the port number
    pub const fn matter_port(&self) -> u16 {
        self.matter_port
    }

    /// Get the notification object which is notified when the registry changes
    pub fn notification(&self) -> &Notification<NoopRawMutex> {
        &self.notification
    }

    /// Reset the registry by removing all reigstered services
    pub fn reset(&self) {
        self.services.borrow_mut().clear();
        self.notification.notify();
    }

    /// Add a new service to the registry
    /// Will remove any existing service with the same name before
    /// registering the new one.
    pub fn add(&self, service: &str, mode: ServiceMode) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);
        services
            .push((service.try_into().unwrap(), mode))
            .map_err(|_| ErrorCode::NoSpace)?;

        self.notification.notify();

        Ok(())
    }

    /// Remove a service from the registry
    pub fn remove(&self, service: &str) -> Result<(), Error> {
        let mut services = self.services.borrow_mut();

        services.retain(|(name, _)| name != service);

        self.notification.notify();

        Ok(())
    }

    /// Visit all services in the registry
    pub fn visit<F>(&self, mut visitor: F) -> Result<(), Error>
    where
        F: FnMut(&str, ServiceMode) -> Result<(), Error>,
    {
        let services = self.services.borrow();

        for (service, mode) in &*services {
            visitor(service, *mode)?;
        }

        Ok(())
    }
}

/// A convenience struct converting the (name, service-mode) pairs to
/// `Service` instances which are easier to report by a generic mDNS responder.
pub struct Service<'a> {
    pub name: &'a str,
    pub service: &'a str,
    pub protocol: &'a str,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub service_subtypes: &'a [&'a str],
    pub txt_kvs: &'a [(&'a str, &'a str)],
}

impl<'a> Service<'a> {
    /// Converts a (name, service-mode) pair to a `Service` instance
    /// and calls the supplied visitor with it.
    ///
    /// The visitor pattern is chosen deliberately, as it allows allocating
    /// any temporary buffers necessary during the conversion on the stack.
    pub fn visit<R, F: FnOnce(&Service) -> Result<R, Error>>(
        name: &str,
        mode: ServiceMode,
        dev_det: &BasicInfoConfig,
        port: u16,
        f: F,
    ) -> Result<R, Error> {
        match mode {
            ServiceMode::Commissioned => f(&Service {
                name,
                service: "_matter",
                protocol: "_tcp",
                priority: 0,
                weight: 0,
                port,
                service_subtypes: &[],
                txt_kvs: &[("", "")],
            }),
            ServiceMode::Commissionable(discriminator) => {
                let discriminator_str = Self::get_discriminator_str(discriminator);
                let vp = Self::get_vp(dev_det.vid, dev_det.pid);

                let txt_kvs = &[
                    ("D", discriminator_str.as_str()),
                    ("CM", "1"),
                    ("DN", dev_det.device_name),
                    ("VP", &vp),
                    ("SII", "5000"), /* Sleepy Idle Interval */
                    ("SAI", "300"),  /* Sleepy Active Interval */
                    ("PH", "33"),    /* Pairing Hint */
                    ("PI", ""),      /* Pairing Instruction */
                ];

                f(&Service {
                    name,
                    service: "_matterc",
                    protocol: "_udp",
                    priority: 0,
                    weight: 0,
                    port,
                    service_subtypes: &[
                        &Self::get_long_service_subtype(discriminator),
                        &Self::get_short_service_type(discriminator),
                    ],
                    txt_kvs,
                })
            }
        }
    }

    fn get_long_service_subtype(discriminator: u16) -> heapless::String<32> {
        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_L{}", discriminator).unwrap();

        serv_type
    }

    fn get_short_service_type(discriminator: u16) -> heapless::String<32> {
        let short = Self::compute_short_discriminator(discriminator);

        let mut serv_type = heapless::String::new();
        write!(&mut serv_type, "_S{}", short).unwrap();

        serv_type
    }

    fn get_discriminator_str(discriminator: u16) -> heapless::String<5> {
        discriminator.try_into().unwrap()
    }

    fn get_vp(vid: u16, pid: u16) -> heapless::String<11> {
        let mut vp = heapless::String::new();

        write!(&mut vp, "{}+{}", vid, pid).unwrap();

        vp
    }

    fn compute_short_discriminator(discriminator: u16) -> u16 {
        const SHORT_DISCRIMINATOR_MASK: u16 = 0xF00;
        const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

        (discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_compute_short_discriminator() {
        let discriminator: u16 = 0b0000_1111_0000_0000;
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 0b1111);

        let discriminator: u16 = 840;
        let short = Service::compute_short_discriminator(discriminator);
        assert_eq!(short, 3);
    }
}
