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

use core::borrow::Borrow;
use core::future::Future;
use core::marker::PhantomData;
use core::ops::DerefMut;

use embassy_futures::select::select4;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_time::{Duration, Instant, Timer};

use log::trace;

use crate::data_model::cluster_basic_information::BasicInfoConfig;
use crate::error::{Error, ErrorCode};
use crate::transport::network::{Address, BtAddr, NetworkReceive, NetworkSend};
use crate::utils::ifmutex::IfMutex;
use crate::utils::select::Coalesce;
use crate::CommissioningData;

pub use context::{BtpContext, MAX_BTP_SESSIONS};
pub use gatt::*;

use self::context::SessionSendLock;

mod context;
mod gatt;
mod session;

/// The maximum size of a BTP segment.
pub(crate) const MAX_BTP_SEGMENT_SIZE: usize = 244;
/// The size of the GATT header. `MAX_BTP_SEGMENT_SIZE` + `GATT_HEADER_SIZE` is 247 bytes, which is the maximum ATT MTU size supported by the BTP protocol.
pub(crate) const GATT_HEADER_SIZE: usize = 3;

/// The minimum MTU that can be used as per specification.
pub(crate) const MIN_MTU: u16 = (20 + GATT_HEADER_SIZE) as u16;
/// The maximum MTU that can be used as per specification.
pub(crate) const MAX_MTU: u16 = (MAX_BTP_SEGMENT_SIZE + GATT_HEADER_SIZE) as u16;

/// An implementation of the Matter BTP protocol.
/// This is a low-level protocol that is used to send and receive Matter messages over BLE.
///
/// The implementation needs a `Gatt` trait implementation which is OS/platform-specific.
/// All aspects of the BTP protocol however are implemented in platform-neutral way.
pub struct Btp<C, M, T> {
    gatt: T,
    context: C,
    send_buf: IfMutex<NoopRawMutex, heapless::Vec<u8, MAX_BTP_SEGMENT_SIZE>>,
    _mutex: PhantomData<M>,
}

#[cfg(all(feature = "std", target_os = "linux"))]
impl<C, M> Btp<C, M, BuiltinGattPeripheral>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
{
    #[inline(always)]
    pub fn new_builtin(context: C) -> Self {
        Self::new(BuiltinGattPeripheral::new(None), context)
    }
}

impl<C, M, T> Btp<C, M, T>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
    T: GattPeripheral,
{
    /// Construct a new BTP object with the provided `GattPeripheral` trait implementation and with the
    /// provided BTP `context`.
    #[inline(always)]
    pub const fn new(gatt: T, context: C) -> Self {
        Self {
            gatt,
            context,
            send_buf: IfMutex::new(heapless::Vec::new()),
            _mutex: PhantomData,
        }
    }

    /// Run the BTP protocol
    ///
    /// While all sending and receiving of Matter packets (a.k.a. BTP SDUs) is done via the `recv` and `send` methods
    /// on the `Btp` struct, this method is responsible for managing internal implementation aspects of
    /// the BTP protocol implementation, like e.g. the sessions' keepalive logic.
    ///
    /// Therefore, user is expected to call this method in order to run the BTP protocol.
    pub fn run<'a>(
        &'a self,
        service_name: &'a str,
        dev_det: &BasicInfoConfig<'_>,
        dev_comm: &CommissioningData,
    ) -> impl Future<Output = Result<(), Error>> + 'a {
        let adv_data = AdvData::new(dev_det, dev_comm);

        let context = self.context.clone();

        async move {
            select4(
                self.gatt.run(service_name, &adv_data, move |event| {
                    context.borrow().on_event(event)
                }),
                self.handshake(),
                self.ack(),
                self.remove_expired(),
            )
            .coalesce()
            .await
        }
    }

    /// Wait until there is at least one Matter (a.k.a. BTP SDU) packet available for consumption.
    pub async fn wait_available(&self) -> Result<(), Error> {
        self.context.borrow().wait_available().await
    }

    /// Receive a Matter (a.k.a. BTP SDU) packet.
    ///
    /// If there is no packet available, this method will block asynchronously until a packet is available.
    /// Returns the size of the received packet, as well as the address of the BLE peer from where the packet originates.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, BtAddr), Error> {
        self.context.borrow().recv(buf).await
    }

    /// Send a Matter (a.k.a. BTP SDU) packet to the specified BLE peer.
    ///
    /// The `data` parameter is the data to be sent.
    /// The `address` parameter is the BLE address of the peer to which the data should be sent.
    ///
    /// If the peer is not connected, this method will return an error.
    /// If the BTP stack is busy sending data to another peer, this method will block asynchronously until the stack is ready to send the data.
    pub async fn send(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
        let context = self.context.borrow();

        loop {
            if let Some(session_lock) =
                SessionSendLock::try_lock(context, |session| session.address() == address)
                    .map_err(|_| ErrorCode::NoNetworkInterface)?
            {
                self.do_send(&session_lock, data).await?;
                break;
            }

            context.send_notif.wait().await;
        }

        Ok(())
    }

    /// Internal utility method that sends a BTP SDU packet on behalf of a session which is locked for sending.
    ///
    /// The `session_lock` parameter represents a session which had been locked for sending.
    /// The `data` parameter is the data to be sent as part of the BTP SDU packet.
    async fn do_send(
        &self,
        session_lock: &SessionSendLock<'_, M>,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut offset = 0;

        loop {
            let mut buf = self.send_buf().await;

            let packet = session_lock
                .with_session(|session| session.prep_tx_data(data, offset, &mut buf))?;

            if let Some((slice, new_offset)) = packet {
                self.gatt.indicate(slice, session_lock.address()).await?;
                offset = new_offset;

                trace!(
                    "Sent {slice:02x?} bytes to address {}",
                    session_lock.address()
                );

                if offset == data.len() {
                    break;
                }
            } else {
                drop(buf);

                self.context.borrow().send_notif.wait().await;
            }
        }

        Ok(())
    }

    /// A job that is responsible for removing all sessions, which are considered expired due to
    /// the remote peers not sending an ACK packet on time.
    async fn remove_expired(&self) -> Result<(), Error> {
        let context = self.context.borrow();

        loop {
            Timer::after(Duration::from_secs(1)).await;

            // Remove all timed-out sessions
            context.remove(|session| session.is_timed_out(Instant::now()))?;
        }
    }

    /// A job that is responsible for sending ACK on behalf of all sessions, which
    /// either have their receive windows full, or which would otherwise expire due to inactivity.
    async fn ack(&self) -> Result<(), Error> {
        let context = self.context.borrow();

        loop {
            while let Some(session_lock) =
                SessionSendLock::lock(context, |session| session.is_ack_due(Instant::now()))
            {
                self.do_send(&session_lock, &[]).await?;
            }

            context.ack_notif.wait().await;
        }
    }

    /// A job that is resposible for sending the Handshake Response packet to all remote peers that
    /// in the meantime have connected to the peripheral, subscribed to chracteristic `C2` and had
    /// written the Handshake Request packet to characteristic `C1`.
    async fn handshake(&self) -> Result<(), Error> {
        let context = self.context.borrow();

        loop {
            while let Some(session_lock) =
                SessionSendLock::lock(context, session::Session::is_handshake_resp_due)
            {
                let mut buf = self.send_buf().await;

                let slice =
                    session_lock.with_session(|session| session.prep_tx_handshake(&mut buf))?;

                self.gatt.indicate(slice, session_lock.address()).await?;

                trace!(
                    "Sent {slice:02x?} bytes to address {}",
                    session_lock.address()
                );
            }

            context.handshake_notif.wait().await;
        }
    }

    /// Get a mutable reference to the send buffer, asybchronously waiting for the buffer to become available,
    /// in case it is used by another operation.
    async fn send_buf(
        &self,
    ) -> impl DerefMut<Target = heapless::Vec<u8, MAX_BTP_SEGMENT_SIZE>> + '_ {
        let mut buf = self.send_buf.lock().await;

        // Unwrap is safe because the max size of the buffer is MAX_PDU_SIZE
        buf.resize_default(MAX_BTP_SEGMENT_SIZE).unwrap();

        buf
    }
}

impl<C, M, T> NetworkSend for &Btp<C, M, T>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
    T: GattPeripheral,
{
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        (*self)
            .send(data, addr.btp().ok_or(ErrorCode::NoNetworkInterface)?)
            .await
    }
}

impl<C, M, T> NetworkReceive for &Btp<C, M, T>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
    T: GattPeripheral,
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        (*self).wait_available().await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        (*self)
            .recv(buffer)
            .await
            .map(|(len, addr)| (len, Address::Btp(addr)))
    }
}

impl<C, M, T> NetworkSend for Btp<C, M, T>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
    T: GattPeripheral,
{
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        (&*self).send_to(data, addr).await
    }
}

impl<C, M, T> NetworkReceive for Btp<C, M, T>
where
    C: Borrow<BtpContext<M>> + Clone + Send + Sync + 'static,
    M: RawMutex + Send + Sync,
    T: GattPeripheral,
{
    async fn wait_available(&mut self) -> Result<(), Error> {
        (*self).wait_available().await
    }

    async fn recv_from(&mut self, buffer: &mut [u8]) -> Result<(usize, Address), Error> {
        (&*self).recv_from(buffer).await
    }
}

#[cfg(test)]
mod test {
    use core::pin::Pin;

    use alloc::sync::Arc;

    use async_channel::{Receiver, Sender};
    use embassy_futures::{block_on, select::select};

    use crate::secure_channel::spake2p::VerifierData;
    use crate::utils::{rand::sys_rand, std_mutex::StdRawMutex};

    use super::*;

    const PEER_ADDR: BtAddr = BtAddr([1, 2, 3, 4, 5, 6]);

    const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
        vid: 10,
        pid: 11,
        hw_ver: 12,
        sw_ver: 13,
        sw_ver_str: "13",
        serial_no: "aabbccdd",
        device_name: "Test Device",
        product_name: "TestProd",
        vendor_name: "TestVendor",
    };

    #[derive(Debug, Clone)]
    enum GattPeripheralEventMock {
        Subscribed(BtAddr),
        Unsubscribed(BtAddr),
        Write {
            address: BtAddr,
            data: Vec<u8>,
            gatt_mtu: Option<u16>,
        },
    }

    #[derive(Debug, Eq, PartialEq)]
    struct GattIndicateMock {
        data: Vec<u8>,
        address: BtAddr,
    }

    struct GattPeripheralDriver {
        peer_sender: async_channel::Sender<GattPeripheralEventMock>,
        peer_receiver: async_channel::Receiver<GattIndicateMock>,
    }

    impl GattPeripheralDriver {
        pub async fn send(&mut self, event: GattPeripheralEventMock) {
            self.peer_sender.send(event).await.unwrap();
        }

        pub async fn expect(&mut self, indication: GattIndicateMock) {
            let received = self.peer_receiver.recv().await.unwrap();

            assert_eq!(received, indication);
        }
    }

    struct Packet {
        data: Vec<u8>,
        address: BtAddr,
    }

    struct IoMock {
        send: async_channel::Sender<Packet>,
        recv: async_channel::Receiver<Packet>,
        context: Arc<BtpContext<StdRawMutex>>,
    }

    struct GattPeriheralMock {
        sender: async_channel::Sender<GattIndicateMock>,
        receiver: async_channel::Receiver<GattPeripheralEventMock>,
    }

    impl GattPeriheralMock {
        fn run<T>(test: T)
        where
            T: FnOnce(
                GattPeripheralDriver,
                IoMock,
            )
                -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>,
        {
            let (sender, peer_receiver) = async_channel::unbounded();
            let (peer_sender, receiver) = async_channel::unbounded();

            let mock = GattPeriheralMock { sender, receiver };

            let context = Arc::new(BtpContext::<StdRawMutex>::new());
            let btp = Arc::new(Btp::new(mock, context.clone()));

            let (io_sender, io_btp_receiver) = async_channel::unbounded();
            let (io_btp_sender, io_receiver) = async_channel::unbounded();

            block_on(
                select4(
                    btp.run(
                        "test",
                        &BASIC_INFO,
                        &CommissioningData {
                            // TODO: Hard-coded for now
                            verifier: VerifierData::new_with_pw(123456, sys_rand),
                            discriminator: 250,
                        },
                    ),
                    async {
                        loop {
                            let mut buf = vec![0; 1500];

                            let Ok((len, addr)) = btp.recv(&mut buf).await else {
                                break;
                            };

                            buf.truncate(len);

                            io_btp_sender
                                .send(Packet {
                                    data: buf,
                                    address: addr,
                                })
                                .await
                                .unwrap();
                        }

                        Ok(())
                    },
                    async {
                        while let Ok::<Packet, _>(packet) = io_btp_receiver.recv().await {
                            btp.send(&packet.data, packet.address).await.unwrap();
                        }

                        Ok(())
                    },
                    test(
                        GattPeripheralDriver {
                            peer_sender,
                            peer_receiver,
                        },
                        IoMock {
                            send: io_sender,
                            recv: io_receiver,
                            context,
                        },
                    ),
                )
                .coalesce(),
            )
            .unwrap();
        }
    }

    impl GattPeripheral for GattPeriheralMock {
        async fn indicate(&self, data: &[u8], address: BtAddr) -> Result<(), Error> {
            self.sender
                .send(GattIndicateMock {
                    data: data.to_vec(),
                    address,
                })
                .await
                .unwrap();

            Ok(())
        }

        async fn run<F>(
            &self,
            _service_name: &str,
            _adv_data: &AdvData,
            callback: F,
        ) -> Result<(), Error>
        where
            F: Fn(GattPeripheralEvent) + Send + Sync + Clone + 'static,
        {
            while let Ok(msg) = self.receiver.recv().await {
                match msg {
                    GattPeripheralEventMock::Subscribed(addr) => {
                        callback(GattPeripheralEvent::NotifySubscribed(addr));
                    }
                    GattPeripheralEventMock::Unsubscribed(addr) => {
                        callback(GattPeripheralEvent::NotifyUnsubscribed(addr));
                    }
                    GattPeripheralEventMock::Write {
                        address,
                        data,
                        gatt_mtu,
                    } => {
                        callback(GattPeripheralEvent::Write {
                            address,
                            data: &data,
                            gatt_mtu,
                        });
                    }
                }
            }

            Ok(())
        }
    }

    #[test]
    fn mytest() {
        init_env_logger();

        // MTUs match
        GattPeriheralMock::run(|mut driver, io| {
            Box::pin(async move {
                driver
                    .send(GattPeripheralEventMock::Write {
                        address: PEER_ADDR,
                        data: vec![0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                        gatt_mtu: Some(0xc8),
                    })
                    .await;

                driver
                    .send(GattPeripheralEventMock::Subscribed(PEER_ADDR))
                    .await;

                driver
                    .expect(GattIndicateMock {
                        data: vec![0x65, 0x6c, 0x05, 0xc5, 0x00, 0x05],
                        address: PEER_ADDR,
                    })
                    .await;

                driver
                    .send(GattPeripheralEventMock::Unsubscribed(PEER_ADDR))
                    .await;

                Timer::after(Duration::from_secs(1)).await;

                Ok(())
            })
        });
    }

    pub fn init_env_logger() {
        #[cfg(all(feature = "std", not(target_os = "espidf")))]
        {
            let _ = env_logger::try_init_from_env(
                env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
            );
        }
    }
}
