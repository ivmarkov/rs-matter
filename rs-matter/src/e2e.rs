use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use core::num::NonZeroU8;

use embassy_futures::{block_on, join::join, select::select3};
use embassy_sync::{
    blocking_mutex::raw::NoopRawMutex,
    zerocopy_channel::{Channel, Receiver, Sender},
};
use embassy_time::{Duration, Timer};

use crate::acl::{AclEntry, AuthMode};
use crate::data_model::cluster_basic_information::{self, BasicInfoConfig};
use crate::data_model::cluster_on_off::{self, OnOffCluster};
use crate::data_model::core::{DataModel, IMBuffer};
use crate::data_model::device_types::{DEV_TYPE_ON_OFF_LIGHT, DEV_TYPE_ROOT_NODE};
use crate::data_model::objects::{
    AsyncHandler, AsyncMetadata, AttrDataEncoder, AttrDetails, CmdDataEncoder, CmdDetails, Dataver,
    Endpoint, Handler, HandlerCompat, Metadata, Node, NonBlockingHandler, Privilege,
};
use crate::data_model::root_endpoint::{self, EthRootEndpointHandler};
use crate::data_model::sdm::admin_commissioning;
use crate::data_model::sdm::dev_att::{DataType, DevAttDataFetcher};
use crate::data_model::sdm::general_commissioning;
use crate::data_model::sdm::noc;
use crate::data_model::sdm::nw_commissioning;
use crate::data_model::subscriptions::Subscriptions;
use crate::data_model::system_model::access_control;
use crate::data_model::system_model::descriptor::{self, DescriptorCluster};
use crate::error::Error;
use crate::handler_chain_type;
use crate::interaction_model::core::{OpCode, PROTO_ID_INTERACTION_MODEL};
use crate::interaction_model::messages::ib::{
    AttrData, AttrPath, AttrResp, AttrStatus, DataVersionFilter,
};
use crate::interaction_model::messages::msg::{
    ReadReq, ReadReqTag, ReportDataMsg, WriteReqTag, WriteResp,
};
use crate::interaction_model::messages::GenericPath;
use crate::mdns::MdnsService;
use crate::respond::Responder;
use crate::tlv::{FromTLV, TLVArray, TLVElement, TLVTag, TLVValue, TLVWrite, TLV};
use crate::transport::exchange::{Exchange, MessageMeta};
use crate::transport::network::{
    Address, NetworkReceive, NetworkSend, MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE,
};
use crate::transport::session::{NocCatIds, ReservedSession, SessionMode};
use crate::utils::buf::PooledBuffers;
use crate::utils::select::Coalesce;
use crate::utils::writebuf::WriteBuf;
use crate::Matter;
use crate::MATTER_PORT;

#[derive(Debug, PartialEq)]
pub enum AttrReadResp<'a> {
    AttrStatus(AttrStatus),
    AttrData(AttrTLVData<'a>),
}

pub type ImEngine = E2eTestRunner;

pub const IM_ENGINE_PEER_ID: u64 = E2eTestRunner::PEER_ID;
pub const IM_ENGINE_REMOTE_PEER_ID: u64 = E2eTestRunner::REMOTE_PEER_ID;

impl<'a> AttrReadResp<'a> {
    pub fn data(path: &GenericPath, answer: TLVValue<'a>) -> Self {
        Self::AttrData(AttrTLVData::new(None, AttrPath::new(path), answer))
    }

    pub fn assert_match(&self, resp: &AttrResp) {
        match self {
            AttrReadResp::AttrStatus(expected) => match resp {
                AttrResp::Status(status) => assert_eq!(expected, status),
                _ => panic!("Expected status {expected:?}, got {resp:?}"),
            },
            AttrReadResp::AttrData(expected) => match resp {
                AttrResp::Data(data) => expected.assert_match(data),
                _ => panic!("Expected data {expected:?}, got {resp:?}"),
            },
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AttrTLVData<'a> {
    pub data_ver: Option<u32>,
    pub path: AttrPath,
    pub answer: TLVValue<'a>,
}

impl<'a> AttrTLVData<'a> {
    pub const fn new(data_ver: Option<u32>, path: AttrPath, answer: TLVValue<'a>) -> Self {
        Self {
            data_ver,
            path,
            answer,
        }
    }

    pub fn assert_match(&self, data: &AttrData<'a>) {
        assert_eq!(self.data_ver, data.data_ver);
        assert_eq!(self.path, data.path);
        assert_eq!(self.answer, TLVValue::from_tlv(&data.data).unwrap());
    }
}

#[macro_export]
macro_rules! attr_status {
    ($path:expr, $status:expr) => {
        $crate::e2e::AttrReadResp::AttrStatus(AttrStatus::new($path, $status, 0))
    };
}

#[macro_export]
macro_rules! attr_data_path {
    ($path:expr, $data:expr) => {
        $crate::e2e::AttrReadResp::AttrData($crate::e2e::AttrTLVData {
            data_ver: None,
            path: AttrPath {
                endpoint: $path.endpoint,
                cluster: $path.cluster,
                attr: $path.leaf.map(|x| x as u16),
                ..Default::default()
            },
            answer: $data,
        })
    };
}

impl E2eTestRunner {
    pub async fn handle_read_reqs<'a, H>(
        &self,
        handler: H,
        input: &'a [AttrPath],
        expected: &'a [AttrReadResp<'a>],
    ) -> Result<(), Error>
    where
        H: AsyncHandler + AsyncMetadata,
    {
        self.run_one(handler, AttrReadTest::new(input, expected))
            .await
    }

    pub async fn handle_write_reqs<'a, H>(
        &self,
        handler: H,
        input: &'a [AttrTLVData<'a>],
        expected: &'a [AttrStatus],
    ) -> Result<(), Error>
    where
        H: AsyncHandler + AsyncMetadata,
    {
        self.run_one(handler, AttrWriteTest::new(input, expected))
            .await
    }
}

pub struct AttrReadTest<'a> {
    input: &'a [AttrPath],
    expected: &'a [AttrReadResp<'a>],
    data_ver_filters: &'a [DataVersionFilter],
}

impl<'a> AttrReadTest<'a> {
    pub const fn new(input: &'a [AttrPath], expected: &'a [AttrReadResp<'a>]) -> Self {
        Self {
            input,
            expected,
            data_ver_filters: &[],
        }
    }
}

impl<'a> E2eTest for AttrReadTest<'a> {
    fn fill_input(&mut self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error> {
        let meta = MessageMeta::new(PROTO_ID_INTERACTION_MODEL, OpCode::ReadRequest as _, true);

        let tw = message_buf;

        tw.start_struct(&TLVTag::Anonymous)?;

        if !self.input.is_empty() {
            tw.start_array(&TLVTag::Context(ReadReqTag::AttrRequests as _))?;

            for input in self.input {
                // TODO tw.write(&TLVTag::Anonymous, &answer.path)?;
            }

            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(meta)
    }

    fn validate_result(&mut self, meta: MessageMeta, message: &[u8]) -> Result<(), Error> {
        let element = TLVElement::new(message);

        let report_data = ReportDataMsg::from_tlv(&element)
            .unwrap_or_else(|_| panic!("Expected a ReadResponse structure, got:\n{element}"));

        let mut answers = report_data
            .attr_reports
            .unwrap_or(TLVArray::new(TLVElement::new(&[]))?)
            .iter();
        let mut expected = self.expected.iter();

        while let Some(answer) = answers.next() {
            let answer = answer?; // TODO

            let expected = expected.next().unwrap();

            expected.assert_match(&answer);
        }

        // TODO: Check lengths

        Ok(())
    }
}

pub struct AttrWriteTest<'a> {
    input: &'a [AttrTLVData<'a>],
    expected: &'a [AttrStatus],
}

impl<'a> AttrWriteTest<'a> {
    pub const fn new(input: &'a [AttrTLVData<'a>], expected: &'a [AttrStatus]) -> Self {
        Self { input, expected }
    }
}

impl<'a> E2eTest for AttrWriteTest<'a> {
    fn fill_input(&mut self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error> {
        let meta = MessageMeta::new(PROTO_ID_INTERACTION_MODEL, OpCode::WriteRequest as _, true);

        let tw = message_buf;

        tw.start_struct(&TLVTag::Anonymous)?;

        if !self.input.is_empty() {
            tw.start_array(&TLVTag::Context(WriteReqTag::WriteRequests as _))?;

            for input in self.input {
                // TODO tw.write(&TLVTag::Anonymous, &answer.path)?;
            }

            tw.end_container()?;
        }

        tw.end_container()?;

        Ok(meta)
    }

    fn validate_result(&mut self, meta: MessageMeta, message: &[u8]) -> Result<(), Error> {
        let element = TLVElement::new(message);

        let write_response = WriteResp::from_tlv(&element)
            .unwrap_or_else(|_| panic!("Expected a WriteResponse structure, got:\n{element}"));

        let mut answers = write_response.write_responses.iter();
        let mut expected = self.expected.iter();

        while let Some(answer) = answers.next() {
            let answer = answer?; // TODO

            let expected = expected.next().unwrap();

            assert_eq!(expected, &answer);
        }

        Ok(())
    }
}

pub trait E2eTest {
    fn fill_input(&mut self, message_buf: &mut WriteBuf) -> Result<MessageMeta, Error>;

    fn validate_result(&mut self, meta: MessageMeta, message: &[u8]) -> Result<(), Error>;

    fn delay(&mut self) -> Option<u64> {
        None
    }
}

pub struct E2eTestRunner {
    pub matter: Matter<'static>,
    cat_ids: NocCatIds,
}

impl E2eTestRunner {
    const ADDR: Address = Address::Udp(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

    const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
        vid: 1,
        pid: 1,
        hw_ver: 1,
        sw_ver: 1,
        sw_ver_str: "1",
        serial_no: "E2E",
        device_name: "E2E Test",
        product_name: "E2E",
        vendor_name: "E2E",
    };

    const NODE: Node<'static> = Node {
        id: 0,
        endpoints: &[
            Endpoint {
                id: 0,
                clusters: &[
                    descriptor::CLUSTER,
                    cluster_basic_information::CLUSTER,
                    general_commissioning::CLUSTER,
                    nw_commissioning::ETH_CLUSTER,
                    admin_commissioning::CLUSTER,
                    noc::CLUSTER,
                    access_control::CLUSTER,
                    //echo_cluster::CLUSTER,
                ],
                device_type: DEV_TYPE_ROOT_NODE,
            },
            Endpoint {
                id: 1,
                clusters: &[
                    descriptor::CLUSTER,
                    cluster_on_off::CLUSTER,
                    //echo_cluster::CLUSTER,
                ],
                device_type: DEV_TYPE_ON_OFF_LIGHT,
            },
        ],
    };

    pub const PEER_ID: u64 = 445566;
    pub const REMOTE_PEER_ID: u64 = 123456;

    /// Create the interaction model engine
    pub fn new() -> Self {
        Self {
            matter: Self::new_matter(),
            cat_ids: NocCatIds::default(),
        }
    }

    pub fn new_with_cat_ids(cat_ids: NocCatIds) -> Self {
        Self {
            matter: Self::new_matter(),
            cat_ids,
        }
    }

    pub fn matter(&self) -> &Matter<'static> {
        &self.matter
    }

    pub fn default_handler(&self) -> E2eTestDefaultHandler<'_> {
        E2eTestDefaultHandler::new(&self.matter)
    }

    pub fn add_default_acl(&self) {
        // Only allow the standard peer node id of the IM Engine
        let mut default_acl =
            AclEntry::new(NonZeroU8::new(1).unwrap(), Privilege::ADMIN, AuthMode::Case);
        default_acl.add_subject(Self::PEER_ID).unwrap();
        self.matter.acl_mgr.borrow_mut().add(default_acl).unwrap();
    }

    pub async fn run_one<H, T>(&self, handler: H, test: T) -> Result<(), Error>
    where
        H: AsyncHandler + AsyncMetadata,
        T: E2eTest,
    {
        self.run(handler, core::iter::once(test)).await
    }

    pub async fn run<H, I, T>(&self, handler: H, tests: I) -> Result<(), Error>
    where
        H: AsyncHandler + AsyncMetadata,
        I: Iterator<Item = T>,
        T: E2eTest,
    {
        Self::init_matter(
            &self.matter,
            Self::REMOTE_PEER_ID,
            Self::PEER_ID,
            &self.cat_ids,
        );

        let matter_client = Self::new_matter();
        Self::init_matter(
            &matter_client,
            Self::PEER_ID,
            Self::REMOTE_PEER_ID,
            &self.cat_ids,
        );

        let mut buf1 = [heapless::Vec::new(); 1];
        let mut buf2 = [heapless::Vec::new(); 1];

        let mut pipe1 = NetworkPipe::<MAX_RX_PACKET_SIZE>::new(&mut buf1);
        let mut pipe2 = NetworkPipe::<MAX_TX_PACKET_SIZE>::new(&mut buf2);

        let (send_remote, recv_local) = pipe1.split();
        let (send_local, recv_remote) = pipe2.split();

        let matter_client = &matter_client;

        let buffers = PooledBuffers::<10, NoopRawMutex, IMBuffer>::new(0);

        let subscriptions = Subscriptions::<1>::new();

        let responder = Responder::new(
            "Default",
            DataModel::new(&buffers, &subscriptions, handler),
            &self.matter,
            0,
        );

        block_on(
            select3(
                matter_client
                    .transport_mgr
                    .run(NetworkSendImpl(send_local), NetworkReceiveImpl(recv_local)),
                self.matter.transport_mgr.run(
                    NetworkSendImpl(send_remote),
                    NetworkReceiveImpl(recv_remote),
                ),
                join(responder.respond_once("0"), async move {
                    let mut exchange = Exchange::initiate(
                        matter_client,
                        1, /*just one fabric in tests*/
                        Self::REMOTE_PEER_ID,
                        true,
                    )
                    .await?;

                    for mut test in tests {
                        exchange
                            .send_with(|_, wb| {
                                let meta = test.fill_input(wb)?;

                                Ok(Some(meta))
                            })
                            .await?;

                        {
                            // In a separate block so that the RX message is dropped before we start waiting

                            let rx = exchange.recv().await?;

                            test.validate_result(rx.meta(), rx.payload())?;
                        }

                        let delay = test.delay().unwrap_or(0);
                        if delay > 0 {
                            Timer::after(Duration::from_millis(delay as _)).await;
                        }
                    }

                    exchange.acknowledge().await?;

                    Ok(())
                })
                .coalesce(),
            )
            .coalesce(),
        )
    }

    fn new_matter() -> Matter<'static> {
        #[cfg(feature = "std")]
        use crate::utils::epoch::sys_epoch as epoch;

        #[cfg(not(feature = "std"))]
        use crate::utils::epoch::dummy_epoch as epoch;

        #[cfg(feature = "std")]
        use crate::utils::rand::sys_rand as rand;

        #[cfg(not(feature = "std"))]
        use crate::utils::rand::dummy_rand as rand;

        let matter = Matter::new(
            &Self::BASIC_INFO,
            &E2eDummyDevAtt,
            MdnsService::Disabled,
            epoch,
            rand,
            MATTER_PORT,
        );

        matter.initialize_transport_buffers().unwrap();

        matter
    }

    fn init_matter(matter: &Matter, local_nodeid: u64, remote_nodeid: u64, cat_ids: &NocCatIds) {
        matter.transport_mgr.reset().unwrap();

        let mut session = ReservedSession::reserve_now(matter).unwrap();

        session
            .update(
                local_nodeid,
                remote_nodeid,
                1,
                1,
                Self::ADDR,
                SessionMode::Case {
                    fab_idx: NonZeroU8::new(1).unwrap(),
                    cat_ids: *cat_ids,
                },
                None,
                None,
                None,
            )
            .unwrap();

        session.complete();
    }
}

pub struct E2eTestDefaultHandler<'a> {
    handler: handler_chain_type!(OnOffCluster, DescriptorCluster<'static> | EthRootEndpointHandler<'a>),
}

impl<'a> E2eTestDefaultHandler<'a> {
    pub fn new(matter: &'a Matter<'a>) -> Self {
        let handler = root_endpoint::eth_handler(0, matter.rand())
            // .chain(
            //     0,
            //     echo_cluster::ID,
            //     EchoCluster::new(2, Dataver::new_rand(matter.rand())),
            // )
            .chain(
                1,
                descriptor::ID,
                DescriptorCluster::new(Dataver::new_rand(matter.rand())),
            )
            // .chain(
            //     1,
            //     echo_cluster::ID,
            //     EchoCluster::new(3, Dataver::new_rand(matter.rand())),
            // )
            .chain(
                1,
                cluster_on_off::ID,
                OnOffCluster::new(Dataver::new_rand(matter.rand())),
            );

        Self { handler }
    }

    // pub fn echo_cluster(&self, endpoint: u16) -> &EchoCluster {
    //     match endpoint {
    //         0 => &self.handler.next.next.next.handler,
    //         1 => &self.handler.next.handler,
    //         _ => panic!(),
    //     }
    // }
}

impl<'a> Handler for E2eTestDefaultHandler<'a> {
    fn read(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        encoder: AttrDataEncoder,
    ) -> Result<(), Error> {
        self.handler.read(exchange, attr, encoder)
    }

    fn write(
        &self,
        exchange: &Exchange,
        attr: &AttrDetails,
        data: crate::data_model::objects::AttrData,
    ) -> Result<(), Error> {
        self.handler.write(exchange, attr, data)
    }

    fn invoke(
        &self,
        exchange: &Exchange,
        cmd: &CmdDetails,
        data: &TLVElement,
        encoder: CmdDataEncoder,
    ) -> Result<(), Error> {
        self.handler.invoke(exchange, cmd, data, encoder)
    }
}

impl<'a> NonBlockingHandler for E2eTestDefaultHandler<'a> {}

impl<'a> AsyncHandler for E2eTestDefaultHandler<'a> {
    async fn read(
        &self,
        exchange: &Exchange<'_>,
        attr: &AttrDetails<'_>,
        encoder: AttrDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.handler.read(exchange, attr, encoder)
    }

    fn read_awaits(&self, _exchange: &Exchange, _attr: &AttrDetails) -> bool {
        false
    }

    fn write_awaits(&self, _exchange: &Exchange, _attr: &AttrDetails) -> bool {
        false
    }

    fn invoke_awaits(&self, _exchange: &Exchange, _cmd: &CmdDetails) -> bool {
        false
    }

    async fn write(
        &self,
        exchange: &Exchange<'_>,
        attr: &AttrDetails<'_>,
        data: crate::data_model::objects::AttrData<'_>,
    ) -> Result<(), Error> {
        self.handler.write(exchange, attr, data)
    }

    async fn invoke(
        &self,
        exchange: &Exchange<'_>,
        cmd: &CmdDetails<'_>,
        data: &TLVElement<'_>,
        encoder: CmdDataEncoder<'_, '_, '_>,
    ) -> Result<(), Error> {
        self.handler.invoke(exchange, cmd, data, encoder)
    }
}

impl<'a> Metadata for E2eTestDefaultHandler<'a> {
    type MetadataGuard<'g> = Node<'g> where Self: 'g;

    fn lock(&self) -> Self::MetadataGuard<'_> {
        E2eTestRunner::NODE
    }
}

impl<'a> AsyncMetadata for E2eTestDefaultHandler<'a> {
    type MetadataGuard<'g> = Node<'g> where Self: 'g;

    async fn lock(&self) -> Self::MetadataGuard<'_> {
        E2eTestRunner::NODE
    }
}
struct E2eDummyDevAtt;

impl DevAttDataFetcher for E2eDummyDevAtt {
    fn get_devatt_data(&self, _data_type: DataType, _data: &mut [u8]) -> Result<usize, Error> {
        Ok(2)
    }

    fn with_devatt_data(
        &self,
        _data_type: DataType,
        f: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        f(&[0, 1])
    }
}

type NetworkPipe<'a, const N: usize> = Channel<'a, NoopRawMutex, heapless::Vec<u8, N>>;

struct NetworkReceiveImpl<'a, const N: usize>(Receiver<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<'a, const N: usize> NetworkSend for NetworkSendImpl<'a, N> {
    async fn send_to(&mut self, data: &[u8], _addr: Address) -> Result<(), Error> {
        let vec = self.0.send().await;

        vec.clear();
        vec.extend_from_slice(data).unwrap();

        self.0.send_done();

        Ok(())
    }
}

struct NetworkSendImpl<'a, const N: usize>(Sender<'a, NoopRawMutex, heapless::Vec<u8, N>>);

impl<'a, const N: usize> NetworkReceive for NetworkReceiveImpl<'a, N> {
    async fn wait_available(&mut self) -> Result<(), Error> {
        self.0.receive().await;

        Ok(())
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        let vec = self.0.receive().await;

        buffer[..vec.len()].copy_from_slice(vec);
        let len = vec.len();

        self.0.receive_done();

        Ok((len, E2eTestRunner::ADDR))
    }
}
