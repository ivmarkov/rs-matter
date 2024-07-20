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

use core::fmt::Write;
use core::num::{NonZeroU8, Wrapping};

use heapless::String;

use log::{error, info};

use crate::acl::{AccessReq, AclEntry};
use crate::cert::{Cert, MAX_CERT_TLV_LEN};
use crate::crypto::{self, hkdf_sha256, HmacSha256, KeyPair};
use crate::error::{Error, ErrorCode};
use crate::group_keys::KeySet;
use crate::mdns::{Mdns, ServiceMode};
use crate::tlv::{
    self, FromTLV, OctetStr, OctetStrOwned, TLVList, TLVWriter, TagType, ToTLV, UtfStr,
};
use crate::utils::init::{init, ApplyInit, AsFallibleInit, Init};
use crate::utils::vec::Vec;
use crate::utils::writebuf::WriteBuf;

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

#[derive(Debug, ToTLV)]
#[tlvargs(lifetime = "'a", start = 1)]
pub struct FabricDescriptor<'a> {
    root_public_key: OctetStr<'a>,
    vendor_id: u16,
    fabric_id: u64,
    node_id: u64,
    label: UtfStr<'a>,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    #[tagval(0xFE)]
    pub fab_idx: NonZeroU8,
}

// pub enum FabricState {
//     New,
//     Active,
//     Committed,
//     Updated,
// }

// impl FabricState {
//     pub const fn is_active(&self) -> bool {

//     }
// }

#[derive(Debug, ToTLV, FromTLV)]
pub struct Fabric {
    updating: bool,
    node_id: u64,
    fabric_id: u64,
    fabric_idx: NonZeroU8,
    vendor_id: u16,
    key_pair: Option<KeyPair>,
    pub root_ca: OctetStrOwned<MAX_CERT_TLV_LEN>,
    pub icac: OctetStrOwned<MAX_CERT_TLV_LEN>,
    pub noc: OctetStrOwned<MAX_CERT_TLV_LEN>,
    pub ipk: KeySet,
    label: String<32>,
    mdns_service_name: String<33>,
    acls: Vec<AclEntry, 3>,
}

impl Fabric {
    pub const fn new0(fabric_idx: NonZeroU8) -> Self {
        Self {
            updating: true,
            node_id: 0,
            fabric_id: 0,
            fabric_idx,
            vendor_id: 0,
            key_pair: None,
            root_ca: OctetStrOwned::new(),
            icac: OctetStrOwned::new(),
            noc: OctetStrOwned::new(),
            ipk: KeySet::new0(),
            label: String::new(),
            mdns_service_name: String::new(),
            acls: Vec::new(),
        }
    }

    pub fn init(fabric_idx: NonZeroU8) -> impl Init<Self> {
        init!(Self {
            updating: true,
            node_id: 0,
            fabric_id: 0,
            fabric_idx,
            vendor_id: 0,
            key_pair: None,
            root_ca <- OctetStrOwned::init(),
            icac <- OctetStrOwned::init(),
            noc <- OctetStrOwned::init(),
            ipk <- KeySet::init(),
            label: String::new(),
            mdns_service_name: String::new(),
            acls <- Vec::init(),
        })
    }

    pub fn update_root_ca(&mut self, root_ca: &[u8]) {
        self.root_ca.array.clear();
        self.root_ca.array.extend_from_slice(root_ca);
    }

    pub fn update_noc(
        &mut self,
        noc: &[u8],
        icac: &[u8],
        ipk: &[u8],
        vendor_id: u16,
        label: &str,
    ) -> Result<(), Error> {
        self.noc.array.clear();
        self.noc.array.extend_from_slice(noc);

        self.icac.array.clear();
        self.icac.array.extend_from_slice(icac);

        let mut compressed_id = [0_u8; COMPRESSED_FABRIC_ID_LEN];

        self.ipk = {
            self.compressed_id(&mut compressed_id)?;

            KeySet::new(ipk, &compressed_id)?
        };

        self.vendor_id = vendor_id;

        self.label.clear();
        self.label.push_str(label).unwrap();

        self.update_mdns_service_name()?;

        Ok(())
    }

    fn update_mdns_service_name(&mut self) -> Result<(), Error> {
        let mut compressed_id = [0_u8; COMPRESSED_FABRIC_ID_LEN];

        self.compressed_id(&mut compressed_id)?;

        self.mdns_service_name.clear();

        for c in compressed_id {
            let mut hex = heapless::String::<4>::new();
            write!(&mut hex, "{:02X}", c).unwrap();
            self.mdns_service_name.push_str(&hex).unwrap();
        }

        self.mdns_service_name.push('-').unwrap();

        for c in self.node_id.to_be_bytes() {
            let mut hex = heapless::String::<4>::new();
            write!(&mut hex, "{:02X}", c).unwrap();
            self.mdns_service_name.push_str(&hex).unwrap();
        }

        info!("MDNS Service Name: {}", self.mdns_service_name);

        Ok(())
    }

    fn compressed_id(&self, out: &mut [u8]) -> Result<(), Error> {
        const COMPRESSED_FABRIC_ID_INFO: [u8; 16] = [
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];

        let cert = Cert::new(&self.root_ca.array)?;

        hkdf_sha256(
            &self.fabric_id.to_be_bytes(),
            &cert.get_pubkey()[1..],
            &COMPRESSED_FABRIC_ID_INFO,
            out,
        )
        .map_err(|_| Error::from(ErrorCode::NoSpace))
    }

    pub fn matches_dest_id(&self, random: &[u8], target: &[u8]) -> Result<bool, Error> {
        let mut mac = HmacSha256::new(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(self.root_ca()?.get_pubkey())?;
        mac.update(&self.fabric_id.to_le_bytes())?;
        mac.update(&self.node_id.to_le_bytes())?;

        let mut id = [0_u8; crypto::SHA256_HASH_LEN_BYTES];
        mac.finish(&mut id)?;

        Ok(id.as_slice() == target)
    }

    pub fn key_pair(&self) -> &KeyPair {
        self.key_pair.as_ref().unwrap()
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    pub fn fabric_idx(&self) -> NonZeroU8 {
        self.fabric_idx
    }

    pub fn root_ca(&self) -> Result<Cert<'_>, Error> {
        Cert::new(&self.root_ca.array)
    }

    pub fn with_fabric_desc<F, R>(&self, f: F) -> Result<R, Error>
    where
        F: FnOnce(&FabricDescriptor) -> Result<R, Error>,
    {
        let root_ca = self.root_ca()?;

        let desc = FabricDescriptor {
            root_public_key: OctetStr::new(root_ca.get_pubkey()),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: UtfStr(self.label.as_bytes()),
            fab_idx: self.fabric_idx,
        };

        f(&desc)
    }

    pub fn acl_iter(&self) -> impl Iterator<Item = &AclEntry> {
        self.acls.iter()
    }

    pub fn acl_add<I: Init<AclEntry, Error>>(&mut self, acl: I) -> Result<(), Error> {
        self.acls.push_init(acl, || ErrorCode::NoSpace.into())
    }

    pub fn acl_edit<I: Init<AclEntry, Error>>(
        &mut self,
        index: usize,
        acl: I,
    ) -> Result<(), Error> {
        if self.acls.len() >= index {
            Err(ErrorCode::NotFound)?;
        }

        acl.apply(&mut self.acls[index])
    }

    pub fn acl_remove(&mut self, index: usize) -> Result<(), Error> {
        if self.acls.len() >= index {
            Err(ErrorCode::NotFound)?;
        }

        self.acls.remove(index);

        Ok(())
    }

    pub fn acl_remove_all(&mut self) {
        self.acls.clear();
    }

    pub fn acl_allow(&self, req: &AccessReq) -> bool {
        for e in &self.acls {
            if e.allow(req) {
                return true;
            }
        }

        // error!(
        //     "ACL Disallow for subjects {} fab idx {}",
        //     req.accessor.subjects, req.accessor.fab_idx
        // );

        // error!("{}", self);

        false
    }
}

pub const MAX_SUPPORTED_FABRICS: usize = 3;

type FabricEntries = Vec<Option<Fabric>, MAX_SUPPORTED_FABRICS>;

pub struct FabricMgr {
    fabric_idx_ctr: u8,
    fabrics: crate::utils::vec::Vec<Fabric, MAX_SUPPORTED_FABRICS>,
    changed: bool,
}

impl Default for FabricMgr {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricMgr {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            fabric_idx_ctr: 0,
            fabrics: crate::utils::vec::Vec::new(),
            changed: false,
        }
    }

    pub fn init() -> impl Init<Self> {
        init!(Self {
            fabric_idx_ctr: 0,
            fabrics <- crate::utils::vec::Vec::init(),
            changed: false,
        })
    }

    pub fn load(&mut self, data: &[u8], mdns: &dyn Mdns) -> Result<(), Error> {
        // TODO: next_fabric_idx

        for fabric in &self.fabrics {
            mdns.remove(&fabric.mdns_service_name)?;
        }

        let root = TLVList::new(data).iter().next().ok_or(ErrorCode::Invalid)?;

        tlv::vec_from_tlv(&mut self.fabrics, &root)?;

        for fabric in &self.fabrics {
            mdns.add(&fabric.mdns_service_name, ServiceMode::Commissioned)?;
        }

        self.changed = false;

        Ok(())
    }

    pub fn store<'a>(&mut self, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
        if self.changed {
            let mut wb = WriteBuf::new(buf);
            let mut tw = TLVWriter::new(&mut wb);

            self.fabrics
                .as_slice()
                .to_tlv(&mut tw, TagType::Anonymous)?;

            self.changed = false;

            let len = tw.get_tail();

            Ok(Some(&buf[..len]))
        } else {
            Ok(None)
        }
    }

    pub fn is_changed(&self) -> bool {
        self.changed
    }

    pub fn add(&mut self) -> Result<&mut Fabric, Error> {
        let mut next_fabric_idx = Wrapping(self.fabric_idx_ctr);

        loop {
            next_fabric_idx += Wrapping(1);

            if next_fabric_idx.0 == self.fabric_idx_ctr {
                Err(ErrorCode::NoSpace)?;
            }

            if next_fabric_idx.0 == 0 {
                next_fabric_idx += Wrapping(1);
            }

            if self
                .fabrics
                .iter()
                .all(|fabric| fabric.fabric_idx.get() != next_fabric_idx.0)
            {
                break;
            }
        }

        self.fabrics.push_init(
            Fabric::init(NonZeroU8::new(next_fabric_idx.0).unwrap()).as_fallible(),
            || ErrorCode::NoSpace,
        )?;

        Ok(self.fabrics.last_mut().unwrap())
    }

    pub fn remove(&mut self, fab_idx: NonZeroU8, mdns: &dyn Mdns) -> Result<(), Error> {
        self.fabrics.retain(|fabric| fabric.fabric_idx != fab_idx);

        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Fabric> {
        self.fabrics.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Fabric> {
        self.fabrics.iter_mut()
    }

    pub fn get_by_dest_id(&self, random: &[u8], target: &[u8]) -> Option<&Fabric> {
        self.fabrics
            .iter()
            .find(|fabric| fabric.matches_dest_id(random, target).unwrap_or(false))
    }

    pub fn get(&self, idx: NonZeroU8) -> Option<&Fabric> {
        self.iter().find(|fabric| fabric.fabric_idx == idx)
    }

    pub fn get_mut(&mut self, idx: NonZeroU8) -> Option<&mut Fabric> {
        self.iter_mut().find(|fabric| fabric.fabric_idx == idx)
    }

    pub fn is_empty(&self) -> bool {
        self.fabrics.is_empty()
    }

    pub fn used_count(&self) -> usize {
        self.fabrics.len()
    }

    pub fn set_label(&mut self, index: NonZeroU8, label: &str) -> Result<(), Error> {
        if !label.is_empty() && self.iter().any(|f| f.label == label) {
            Err(ErrorCode::Invalid)?;
        }

        let Some(fabric) = self.get_mut(index) else {
            return Err(ErrorCode::NotFound.into());
        };

        fabric.label = label.try_into().unwrap();
        self.changed = true;

        Ok(())
    }
}
