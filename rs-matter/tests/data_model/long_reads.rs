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

use rs_matter::data_model::objects::GlobalElements;
use rs_matter::data_model::sdm::{
    admin_commissioning as adm_comm, general_commissioning as gen_comm, noc, nw_commissioning,
};
use rs_matter::data_model::system_model::{access_control as acl, descriptor};
use rs_matter::data_model::{cluster_basic_information as basic_info, cluster_on_off as onoff};
use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::AttrPath;
use rs_matter::interaction_model::messages::msg::{StatusResp, SubscribeResp};
use rs_matter::interaction_model::messages::GenericPath;
use rs_matter::tlv::ElementType;

use crate::attr_data;
use crate::e2e::im::attributes::TestAttrResp;
use crate::e2e::im::{echo_cluster as echo, TestSubscribeReq};
use crate::e2e::im::{TestReadReq, TestReportDataMsg};
use crate::e2e::tlv::TlvTest;
use crate::e2e::ImEngine;

use crate::common::init_env_logger;

static DONT_CARE: &'static ElementType = &ElementType::Null;

static PART_1: &'static [TestAttrResp<'static>] = &[
    attr_data!(0, 29, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 29, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(0, 29, descriptor::Attributes::DeviceTypeList, DONT_CARE),
    attr_data!(0, 29, descriptor::Attributes::ServerList, DONT_CARE),
    attr_data!(0, 29, descriptor::Attributes::PartsList, DONT_CARE),
    attr_data!(0, 29, descriptor::Attributes::ClientList, DONT_CARE),
    attr_data!(0, 40, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 40, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::DMRevision,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::VendorName,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::VendorId,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::ProductName,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::ProductId,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::NodeLabel,
        DONT_CARE
    ),
    attr_data!(0, 40, basic_info::AttributesDiscriminants::HwVer, DONT_CARE),
    attr_data!(0, 40, basic_info::AttributesDiscriminants::SwVer, DONT_CARE),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::SwVerString,
        DONT_CARE
    ),
    attr_data!(
        0,
        40,
        basic_info::AttributesDiscriminants::SerialNo,
        DONT_CARE
    ),
    attr_data!(0, 48, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 48, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(
        0,
        48,
        gen_comm::AttributesDiscriminants::BreadCrumb,
        DONT_CARE
    ),
    attr_data!(
        0,
        48,
        gen_comm::AttributesDiscriminants::RegConfig,
        DONT_CARE
    ),
    attr_data!(
        0,
        48,
        gen_comm::AttributesDiscriminants::LocationCapability,
        DONT_CARE
    ),
    attr_data!(
        0,
        48,
        gen_comm::AttributesDiscriminants::BasicCommissioningInfo,
        DONT_CARE
    ),
    attr_data!(
        0,
        48,
        gen_comm::AttributesDiscriminants::SupportsConcurrentConnection,
        DONT_CARE
    ),
    attr_data!(0, 49, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 49, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(0, 49, nw_commissioning::Attributes::MaxNetworks, DONT_CARE),
    attr_data!(0, 49, nw_commissioning::Attributes::Networks, DONT_CARE),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::ConnectMaxTimeSecs,
        DONT_CARE
    ),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::InterfaceEnabled,
        DONT_CARE
    ),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::LastNetworkingStatus,
        DONT_CARE
    ),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::LastNetworkID,
        DONT_CARE
    ),
    attr_data!(
        0,
        49,
        nw_commissioning::Attributes::LastConnectErrorValue,
        DONT_CARE
    ),
    attr_data!(0, 60, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 60, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(
        0,
        60,
        adm_comm::AttributesDiscriminants::WindowStatus,
        DONT_CARE
    ),
];

static PART_2: &'static [TestAttrResp<'static>] = &[
    attr_data!(
        0,
        60,
        adm_comm::AttributesDiscriminants::AdminFabricIndex,
        DONT_CARE
    ),
    attr_data!(
        0,
        60,
        adm_comm::AttributesDiscriminants::AdminVendorId,
        DONT_CARE
    ),
    attr_data!(0, 62, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 62, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(
        0,
        62,
        noc::AttributesDiscriminants::CurrentFabricIndex,
        DONT_CARE
    ),
    attr_data!(0, 62, noc::AttributesDiscriminants::Fabrics, DONT_CARE),
    attr_data!(
        0,
        62,
        noc::AttributesDiscriminants::SupportedFabrics,
        DONT_CARE
    ),
    attr_data!(
        0,
        62,
        noc::AttributesDiscriminants::CommissionedFabrics,
        DONT_CARE
    ),
    attr_data!(0, 31, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, 31, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(0, 31, acl::AttributesDiscriminants::Acl, DONT_CARE),
    attr_data!(0, 31, acl::AttributesDiscriminants::Extension, DONT_CARE),
    attr_data!(
        0,
        31,
        acl::AttributesDiscriminants::SubjectsPerEntry,
        DONT_CARE
    ),
    attr_data!(
        0,
        31,
        acl::AttributesDiscriminants::TargetsPerEntry,
        DONT_CARE
    ),
    attr_data!(
        0,
        31,
        acl::AttributesDiscriminants::EntriesPerFabric,
        DONT_CARE
    ),
    attr_data!(0, echo::ID, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(0, echo::ID, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att1, DONT_CARE),
    attr_data!(0, echo::ID, echo::AttributesDiscriminants::Att2, DONT_CARE),
    attr_data!(
        0,
        echo::ID,
        echo::AttributesDiscriminants::AttCustom,
        DONT_CARE
    ),
    attr_data!(1, 29, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(1, 29, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(1, 29, descriptor::Attributes::DeviceTypeList, DONT_CARE),
    attr_data!(1, 29, descriptor::Attributes::ServerList, DONT_CARE),
    attr_data!(1, 29, descriptor::Attributes::PartsList, DONT_CARE),
    attr_data!(1, 29, descriptor::Attributes::ClientList, DONT_CARE),
    attr_data!(1, 6, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(1, 6, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(1, 6, onoff::AttributesDiscriminants::OnOff, DONT_CARE),
    attr_data!(1, echo::ID, GlobalElements::FeatureMap, DONT_CARE),
    attr_data!(1, echo::ID, GlobalElements::AttributeList, DONT_CARE),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att1, DONT_CARE),
    attr_data!(1, echo::ID, echo::AttributesDiscriminants::Att2, DONT_CARE),
    attr_data!(
        1,
        echo::ID,
        echo::AttributesDiscriminants::AttCustom,
        DONT_CARE
    ),
];

#[test]
fn test_long_read_success() {
    // Read the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    im.test_one(
        &handler,
        TlvTest::read(
            TestReadReq::reqs(&[AttrPath::new(&GenericPath::new(None, None, None))]),
            TestReportDataMsg {
                attr_reports: Some(PART_1),
                more_chunks: Some(true),
                suppress_response: Some(false),
                ..Default::default()
            },
        ),
    );

    im.test_one(
        &handler,
        TlvTest::read(
            StatusResp {
                status: IMStatusCode::Success,
            },
            TestReportDataMsg {
                attr_reports: Some(PART_2),
                more_chunks: Some(false),
                ..Default::default()
            },
        ),
    );
}

#[test]
fn test_long_read_subscription_success() {
    // Subscribe to the entire attribute database, which requires 2 reads to complete
    init_env_logger();

    let im = ImEngine::new_default();
    let handler = im.handler();

    im.add_default_acl();

    im.test_one(
        &handler,
        TlvTest::subscribe(
            TestSubscribeReq::reqs(&[AttrPath::new(&GenericPath::new(None, None, None))]),
            TestReportDataMsg {
                attr_reports: Some(PART_1),
                more_chunks: Some(true),
                suppress_response: Some(false),
                ..Default::default()
            },
        ),
    );

    im.test_one(
        &handler,
        TlvTest::read(
            StatusResp {
                status: IMStatusCode::Success,
            },
            TestReportDataMsg {
                attr_reports: Some(PART_2),
                more_chunks: Some(false),
                suppress_response: Some(false),
                ..Default::default()
            },
        ),
    );

    im.test_one(
        &handler,
        TlvTest::read(
            StatusResp {
                status: IMStatusCode::Success,
            },
            SubscribeResp {
                subs_id: 1,
                max_int: 100,
                ..Default::default()
            },
        ),
    );
}
