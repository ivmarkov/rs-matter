use core::cell::RefCell;
use std::collections::HashMap;

use crate::{
    data_model::cluster_basic_information::BasicInfoConfig,
    error::{Error, ErrorCode},
};
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
use log::info;

use super::ServiceMode;

pub struct MdnsService<'a> {
    dev_det: &'a BasicInfoConfig<'a>,
    matter_port: u16,
    services: RefCell<Option<HashMap<String, RegisteredDnsService>>>,
}

impl<'a> MdnsService<'a> {
    pub const fn new(dev_det: &'a BasicInfoConfig<'a>, matter_port: u16) -> Self {
        Self {
            dev_det,
            matter_port,
            services: RefCell::new(None),
        }
    }

    pub fn reset(&self) {
        self.services.replace(None);
    }

    pub fn enable(&self, enable: bool) {
        if enable {
            if self.services.borrow().is_none() {
                self.services.replace(Some(HashMap::new()));
            }
        } else {
            self.services.replace(None);
        }
    }

    pub fn add(&self, name: &str, mode: ServiceMode) -> Result<(), Error> {
        let _ = self.remove(name);

        if let Some(services) = self.services.borrow().as_mut() {
            info!("Registering mDNS service {}/{:?}", name, mode);

            mode.service(self.dev_det, self.matter_port, name, |service| {
                let composite_service_type = if !service.service_subtypes.is_empty() {
                    format!(
                        "{}.{},{}",
                        service.service,
                        service.protocol,
                        service.service_subtypes.join(",")
                    )
                } else {
                    format!("{}.{}", service.service, service.protocol)
                };

                let mut builder = DNSServiceBuilder::new(&composite_service_type, service.port)
                    .with_name(service.name);

                for kvs in service.txt_kvs {
                    info!("mDNS TXT key {} val {}", kvs.0, kvs.1);
                    builder = builder.with_key_value(kvs.0.to_string(), kvs.1.to_string());
                }

                let svc = builder.register().map_err(|_| ErrorCode::MdnsError)?;

                services.insert(service.name.into(), svc);

                Ok(())
            })
        }
    }

    pub fn remove(&self, name: &str) -> Result<(), Error> {
        if let Some(services) = self.services.borrow().as_mut() {
            if services.remove(name).is_some() {
                info!("Deregistering mDNS service {}", name);
            }
        }

        Ok(())
    }
}
