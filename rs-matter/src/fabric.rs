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

use core::fmt::{self, Write};
use core::num::NonZeroU8;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use log::{error, info};

use crate::acl::{AccessReq, AclEntry, AuthMode};
use crate::cert::{Cert, MAX_CERT_TLV_LEN};
use crate::crypto::{self, hkdf_sha256, HmacSha256, KeyPair};
use crate::error::{Error, ErrorCode};
use crate::group_keys::KeySet;
use crate::mdns::{Mdns, ServiceMode};
use crate::tlv::{FromTLV, OctetStr, TLVList, TLVWriter, TagType, ToTLV, UtfStr};
use crate::utils::writebuf::WriteBuf;

const COMPRESSED_FABRIC_ID_LEN: usize = 8;

pub const MAX_FABRICS: usize = 3;
const MAX_ACL_ENTRIES: usize = 3;

pub type CompressedFabricId = [u8; COMPRESSED_FABRIC_ID_LEN];

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

#[derive(Debug, ToTLV, FromTLV)]
pub struct Fabric {
    idx: u8,
    node_id: u64,
    fabric_id: u64,
    compressed_id: CompressedFabricId,
    vendor_id: u16,
    key_pair: Option<KeyPair>,
    pub root_ca: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    pub icac: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    pub noc: heapless::Vec<u8, MAX_CERT_TLV_LEN>,
    pub ipk: KeySet,
    label: heapless::String<32>,
    mdns_service_name: heapless::String<33>,
    acl: heapless::Vec<AclEntry, MAX_ACL_ENTRIES>,
    commissioned: bool,
}

impl Fabric {
    pub const fn new_empty() -> Self {
        Self {
            idx: 0,
            node_id: 0,
            fabric_id: 0,
            compressed_id: [0; COMPRESSED_FABRIC_ID_LEN],
            vendor_id: 0,
            key_pair: None,
            root_ca: heapless::Vec::new(),
            icac: heapless::Vec::new(),
            noc: heapless::Vec::new(),
            ipk: KeySet::new_empty(),
            label: heapless::String::new(),
            mdns_service_name: heapless::String::new(),
            acl: heapless::Vec::new(),
            commissioned: false,
        }
    }

    pub fn clear(&mut self) {
        self.idx = 0;
        self.node_id = 0;
        self.fabric_id = 0;
        self.compressed_id = [0; COMPRESSED_FABRIC_ID_LEN];
        self.vendor_id = 0;
        self.key_pair = None;
        self.root_ca.clear();
        self.icac.clear();
        self.noc.clear();
        self.ipk.clear();
        self.label.clear();
        self.mdns_service_name.clear();
        self.acl_entries.clear();
        self.commissioned = false;
    }

    pub fn update_root_ca(&mut self, key_pair: KeyPair, root_ca: &[u8]) -> Result<(), Error> {
        self.root_ca.clear();
        self.root_ca.extend_from_slice(root_ca).map_err(|_| ErrorCode::NoSpace)?;

        self.key_pair = Some(key_pair);

        Ok(())
    }

    pub fn update_noc(&mut self, noc: &[u8], icac: &[u8], ipk: &[u8], vendor_id: u16) -> Result<(), Error> {
        {
            let noc_p = Cert::new(&noc)?;
            info!("Received NOC: {noc_p}");

            self.node_id = noc_p.get_node_id()?;
            self.fabric_id = noc_p.get_fabric_id()?;
        };

        {
            let root_ca_p = Cert::new(&self.root_ca)?;
            self.compressed_id = Fabric::get_compressed_id(root_ca_p.get_pubkey(), self.fabric_id)?;

            self.ipk.update(ipk, &self.compressed_id)?;
        };

        self.noc.clear();
        self.noc.extend_from_slice(noc).map_err(|_| ErrorCode::NoSpace)?;

        self.icac.clear();
        self.icac.extend_from_slice(icac).map_err(|_| ErrorCode::NoSpace)?;

        if !icac.is_empty() {
            info!("Received ICAC: {}", Cert::new(icac)?);
        }

        self.vendor_id = vendor_id;
        
        Ok(())
    }

    fn get_compressed_id(root_pubkey: &[u8], fabric_id: u64) -> Result<[u8; COMPRESSED_FABRIC_ID_LEN], Error> {
        let mut compressed_id = [0; COMPRESSED_FABRIC_ID_LEN];

        let root_pubkey = &root_pubkey[1..];
        let mut fabric_id_be: [u8; 8] = [0; 8];
        BigEndian::write_u64(&mut fabric_id_be, fabric_id);

        const COMPRESSED_FABRIC_ID_INFO: [u8; 16] = [
            0x43, 0x6f, 0x6d, 0x70, 0x72, 0x65, 0x73, 0x73, 0x65, 0x64, 0x46, 0x61, 0x62, 0x72,
            0x69, 0x63,
        ];

        hkdf_sha256(&fabric_id_be, root_pubkey, &COMPRESSED_FABRIC_ID_INFO, &mut compressed_id)
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(compressed_id)
    }

    pub fn write_mdns_service_name(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for c in self.compressed_id {
            write!(f, "{:02X}", c)?;
        }

        write!(f, "-")?;

        for c in self.node_id.to_be_bytes() {
            write!(f, "{:02X}", c)?;
        }

        Ok(())
    }

    pub fn match_dest_id(&self, random: &[u8], target: &[u8]) -> Result<(), Error> {
        let mut mac = HmacSha256::new(self.ipk.op_key())?;

        mac.update(random)?;
        mac.update(self.root_ca()?.get_pubkey())?;

        let mut buf: [u8; 8] = [0; 8];
        LittleEndian::write_u64(&mut buf, self.fabric_id);
        mac.update(&buf)?;

        LittleEndian::write_u64(&mut buf, self.node_id);
        mac.update(&buf)?;

        let mut id = [0_u8; crypto::SHA256_HASH_LEN_BYTES];
        mac.finish(&mut id)?;
        if id.as_slice() == target {
            Ok(())
        } else {
            Err(ErrorCode::NotFound.into())
        }
    }

    pub fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        let Some(key_pair) = &self.key_pair else {
            return Err(ErrorCode::NotFound.into());
        };

        key_pair.sign_msg(msg, signature)
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn fabric_id(&self) -> u64 {
        self.fabric_id
    }

    pub fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    pub fn idx(&self) -> NonZeroU8 {
        self.idx
    }

    pub fn root_ca(&self) -> Result<Cert<'_>, Error> {
        Cert::new(&self.root_ca)
    }

    pub fn desc<'a>(&'a self, root_ca_cert: &'a Cert) -> Result<FabricDescriptor<'a>, Error> {
        let desc = FabricDescriptor {
            root_public_key: OctetStr::new(root_ca_cert.get_pubkey()),
            vendor_id: self.vendor_id,
            fabric_id: self.fabric_id,
            node_id: self.node_id,
            label: UtfStr(self.label.as_bytes()),
            fab_idx: self.idx,
        };

        Ok(desc)
    }

    pub fn is_commissioned(&self) -> bool {
        self.commissioned
    }

    pub fn acl_iter(&self) -> impl Iterator<Item = &AclEntry> {
        self.acl.iter()
    }

    pub fn clear_acl(&mut self) {
        self.acl.clear();
    }

    pub fn add_acl_entry(&mut self, entry: AclEntry) -> Result<u8, Error> {
        todo!()
    }

    pub fn delete_acl_entry(&mut self, index: u8) -> Result<(), Error> {
        todo!()
    }

    pub fn edit_acl_entry(&mut self, index: u8, new: AclEntry) -> Result<(), Error> {
        todo!()
    }

    pub fn is_allowed(&self, req: &AccessReq) -> bool {
        // PASE Sessions with no fabric index have implicit access grant,
        // but only as long as the ACL list is empty
        //
        // As per the spec:
        // The Access Control List is able to have an initial entry added because the Access Control Privilege
        // Granting algorithm behaves as if, over a PASE commissioning channel during the commissioning
        // phase, the following implicit Access Control Entry were present on the Commissionee (but not on
        // the Commissioner):
        // Access Control Cluster: {
        //     ACL: [
        //         0: {
        //             // implicit entry only; does not explicitly exist!
        //             FabricIndex: 0, // not fabric-specific
        //             Privilege: Administer,
        //             AuthMode: PASE,
        //             Subjects: [],
        //             Targets: [] // entire node
        //         }
        //     ],
        //     Extension: []
        // }
        if req.accessor.auth_mode == AuthMode::Pase {
            return true;
        }

        for e in self.acl_iter() {
            if e.allow(req) {
                return true;
            }
        }

        error!(
            "ACL Disallow for subjects {} fab idx {}",
            req.accessor.subjects, req.accessor.fab_idx
        );
        error!("{}", self);
        
        false
    }
}

pub struct FabricMgr {
    next_fab_idx: u8,
    fabrics: heapless::Vec<Fabric, MAX_FABRICS>,
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
            next_fab_idx: 0,
            fabrics: heapless::Vec::new(),
            changed: false,
        }
    }

    pub fn load(&mut self, data: &[u8], mdns: &dyn Mdns) -> Result<(), Error> {
        for fabric in &self.fabrics {
            mdns.remove(&fabric.mdns_service_name)?;
        }

        let mut list = TLVList::new(data).iter();

        self.next_fab_idx = FromTLV::from_tlv(&list.next().ok_or(ErrorCode::Invalid)?)?;
        
        self.fabrics.clear();

        while let Some(element) = list.next() {
            let fabric = Fabric::from_tlv(&element)?;
            self.fabrics.push(fabric).map_err(|_| ErrorCode::NoSpace)?;
        }

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

            tw.start_list(TagType::Anonymous)?;

            self.next_fab_idx.to_tlv(&mut tw, TagType::Anonymous)?;

            for fabric in &self.fabrics {
                if fabric.is_commissioned() {
                    fabric.to_tlv(&mut tw, TagType::Anonymous)?;
                }
            }

            tw.end_container()?;

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

    pub fn add(&mut self, mut fabric: Fabric, mdns: &dyn Mdns) -> Result<&Fabric, Error> {
        fabric.idx = self.get_next_fab_idx().get();

        self.fabrics
            .push(fabric)
            .map_err(|_| ErrorCode::NoSpace)?;
        
        let fabric = self.fabrics.last_mut().unwrap();

        self.next_fab_idx = fabric.idx().get();
        self.changed = true;

        mdns.add(&fabric.mdns_service_name, ServiceMode::Commissioned)?;

        Ok(fabric)
    }

    pub fn remove(&mut self, fab_idx: NonZeroU8, mdns: &dyn Mdns) -> Result<(), Error> {
        let fabric = self.get_mut(fab_idx)?;

        mdns.remove(&fabric.mdns_service_name)?;

        self.fabrics.retain(|f| f.idx() != fab_idx);
        self.changed = true;

        Ok(())
    }

    pub fn get_by_dest_id(&self, random: &[u8], target: &[u8]) -> Result<&Fabric, Error> {
        for fabric in &self.fabrics {
            if fabric.match_dest_id(random, target).is_ok() {
                return Ok(fabric);
            }
        }

        Err(ErrorCode::NotFound.into())
    }

    pub fn get(&self, fab_idx: NonZeroU8) -> Result<&Fabric, Error> {
        for fabric in &self.fabrics {
            if fabric.idx() == fab_idx {
                return Ok(fabric);
            }
        }

        Err(ErrorCode::NotFound.into())
    }

    pub fn get_mut(&mut self, fab_idx: NonZeroU8) -> Result<&mut Fabric, Error> {
        for fabric in &mut self.fabrics {
            if fabric.idx() == fab_idx {
                return Ok(fabric);
            }
        }

        Err(ErrorCode::NotFound.into())
    }

    pub fn is_empty(&self) -> bool {
        self.fabrics.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Fabric> {
        self.fabrics.iter()
    }

    pub fn set_commissioned(&mut self, fab_idx: NonZeroU8) -> Result<(), Error> {
        let fabric = self.get_mut(fab_idx)?;

        fabric.commissioned = true;
        self.changed = true;

        Ok(())
    }

    pub fn set_label(&mut self, fab_idx: NonZeroU8, label: &str) -> Result<(), Error> {
        if !label.is_empty()
            && self
                .fabrics
                .iter()
                .any(|f| f.label == label)
        {
            Err(ErrorCode::Invalid)?;
        }

        let fabric = self.get_mut(fab_idx)?;
        fabric.label = label.try_into().unwrap();
        self.changed = true;

        Ok(())
    }

    fn get_next_fab_idx(&self) -> NonZeroU8 {
        let mut fab_idx = self.next_fab_idx;

        loop {
            if fab_idx == 0 {
                fab_idx = 1;
            }

            if self.fabrics.iter().all(|f| f.idx().get() != fab_idx) {
                break;
            }

            fab_idx = fab_idx.wrapping_add(1);
        }

        NonZeroU8::new(fab_idx).unwrap()
    }
}
