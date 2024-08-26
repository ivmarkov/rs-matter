/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
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

use rs_matter::interaction_model::core::IMStatusCode;
use rs_matter::interaction_model::messages::ib::{AttrPath, AttrStatus};
use rs_matter::interaction_model::messages::msg::{StatusResp, TimedReq};
use rs_matter::interaction_model::messages::GenericPath;

use crate::e2e::im::attributes::TestAttrData;
use crate::e2e::im::{echo_cluster, TestInvReq, TestInvResp, TestWriteReq, TestWriteResp};
use crate::e2e::test::E2eTest;
use crate::e2e::tlv::TlvTest;
use crate::e2e::ImEngine;
use crate::{echo_req, echo_resp};

use crate::common::init_env_logger;

#[test]
fn test_timed_write_fail_and_success() {
    // - 1 Timed Attr Write Transaction should fail due to timeout
    // - 1 Timed Attr Write Transaction should succeed
    let val0 = 10;
    init_env_logger();

    let ep_att = GenericPath::new(
        None,
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let input = &[TestAttrData::new(None, AttrPath::new(&ep_att), &val0 as _)];

    let ep0_att = GenericPath::new(
        Some(0),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );

    let ep1_att = GenericPath::new(
        Some(1),
        Some(echo_cluster::ID),
        Some(echo_cluster::AttributesDiscriminants::AttWrite as u32),
    );
    let expected = &[
        AttrStatus::new(&ep0_att, IMStatusCode::Success, 0),
        AttrStatus::new(&ep1_att, IMStatusCode::Success, 0),
    ];

    let im = ImEngine::new_default();
    let handler = im.handler();
    im.add_default_acl();

    // Test with incorrect handling
    im.test_one(
        &handler,
        TlvTest::write(
            TestWriteReq {
                timed_request: Some(true),
                ..TestWriteReq::reqs(input)
            },
            StatusResp {
                status: IMStatusCode::Timeout,
            },
        ),
    );

    // Test with correct handling
    let tests: [&dyn E2eTest; 2] = [
        &TlvTest {
            delay_ms: Some(100),
            ..TlvTest::timed(
                TimedReq { timeout: 500 },
                StatusResp {
                    status: IMStatusCode::Success,
                },
            )
        } as _,
        &TlvTest::write(
            TestWriteReq {
                timed_request: Some(true),
                ..TestWriteReq::reqs(input)
            },
            TestWriteResp::resp(expected),
        ) as _,
    ];

    im.test_all(&handler, tests);

    assert_eq!(val0, handler.echo_cluster(0).att_write.get());
}

#[test]
fn test_timed_cmd_success() {
    // A timed request that works
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];
    let expected = &[echo_resp!(0, 10), echo_resp!(1, 30)];

    let im = ImEngine::new_default();
    let handler = im.handler();
    im.add_default_acl();

    // Test with correct handling
    let tests: [&dyn E2eTest; 2] = [
        &TlvTest {
            delay_ms: Some(100),
            ..TlvTest::timed(
                TimedReq { timeout: 2000 },
                StatusResp {
                    status: IMStatusCode::Success,
                },
            )
        } as _,
        &TlvTest::invoke(
            TestInvReq {
                timed_request: Some(true),
                ..TestInvReq::reqs(input)
            },
            TestInvResp::resp(expected),
        ) as _,
    ];

    im.test_all(&handler, tests);
}

#[test]
fn test_timed_cmd_timeout() {
    // A timed request that is executed after a timeout
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];

    let im = ImEngine::new_default();
    let handler = im.handler();
    im.add_default_acl();

    let tests: [&dyn E2eTest; 2] = [
        &TlvTest {
            delay_ms: Some(2000),
            ..TlvTest::timed(
                TimedReq { timeout: 100 },
                StatusResp {
                    status: IMStatusCode::Success,
                },
            )
        },
        &TlvTest::invoke(
            TestInvReq {
                timed_request: Some(true),
                ..TestInvReq::reqs(input)
            },
            StatusResp {
                status: IMStatusCode::Timeout,
            },
        ),
    ];

    im.test_all(&handler, tests);
}

#[test]
fn test_timed_cmd_timedout_mismatch() {
    // A timed request with timeout mismatch
    init_env_logger();

    let input = &[echo_req!(0, 5), echo_req!(1, 10)];

    let im = ImEngine::new_default();
    let handler = im.handler();
    im.add_default_acl();

    let tests: [&dyn E2eTest; 2] = [
        &TlvTest {
            delay_ms: Some(2000),
            ..TlvTest::timed(
                TimedReq { timeout: 0 },
                StatusResp {
                    status: IMStatusCode::Success,
                },
            )
        },
        &TlvTest::write(
            TestInvReq {
                timed_request: Some(false),
                ..TestInvReq::reqs(input)
            },
            StatusResp {
                status: IMStatusCode::TimedRequestMisMatch,
            },
        ),
    ];

    im.test_all(&handler, tests);

    im.test_one(
        &handler,
        TlvTest::write(
            TestInvReq {
                timed_request: Some(true),
                ..TestInvReq::reqs(input)
            },
            StatusResp {
                status: IMStatusCode::TimedRequestMisMatch,
            },
        ),
    );
}
