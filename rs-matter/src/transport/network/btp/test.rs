use core::pin::Pin;

use alloc::sync::Arc;
use alloc::vec::Vec;

use embassy_futures::block_on;

use crate::secure_channel::spake2p::VerifierData;
use crate::utils::{rand::sys_rand, std_mutex::StdRawMutex};

use super::*;

extern crate alloc;

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
enum PeripheralIncoming {
    Subscribed(BtAddr),
    Unsubscribed(BtAddr),
    Write {
        address: BtAddr,
        data: Vec<u8>,
        gatt_mtu: Option<u16>,
    },
}

#[derive(Debug, Eq, PartialEq)]
struct PeripheralOutgoing {
    data: Vec<u8>,
    address: BtAddr,
}

/// A utlity struct to send and receive data on behalf of the peer (the "peripheral").
struct Peripheral {
    peer_sender: async_channel::Sender<PeripheralIncoming>,
    peer_receiver: async_channel::Receiver<PeripheralOutgoing>,
}

impl Peripheral {
    /// Generate `GattPeripheralEvent::NotifySubscribed` event for the peer
    async fn subscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(PeripheralIncoming::Subscribed(addr))
            .await
            .unwrap();
    }

    /// Generate `GattPeripheralEvent::NotifyUnsubscribed` event for the peer
    async fn unsubscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(PeripheralIncoming::Unsubscribed(addr))
            .await
            .unwrap();
    }

    /// Generate `GattPeripheralEvent::Write` event for the peer
    async fn send(&self, data: &[u8], addr: BtAddr, gatt_mtu: Option<u16>) {
        self.peer_sender
            .send(PeripheralIncoming::Write {
                address: addr,
                data: data.to_vec(),
                gatt_mtu,
            })
            .await
            .unwrap();
    }

    /// Expect to receive the provided data from the peer as if the BTP protocol
    /// did call `indicate`
    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let received = self.peer_receiver.recv().await.unwrap();

        assert_eq!(received.data, data);
        assert_eq!(received.address, addr);
    }
}

#[derive(Debug)]
struct IoPacket {
    data: Vec<u8>,
    address: BtAddr,
}

/// A utility struct so that we can send and receive data on behalf of the BTP protocol.
struct Io {
    send: async_channel::Sender<IoPacket>,
    recv: async_channel::Receiver<IoPacket>,
    context: Arc<BtpContext<StdRawMutex>>,
}

impl Io {
    /// Drive the BTP protocol by sending the provided data to the peer
    async fn send(&self, data: &[u8], addr: BtAddr) {
        let packet = IoPacket {
            data: data.to_vec(),
            address: addr,
        };

        self.send.send(packet).await.unwrap();
    }

    /// Drive the BTP protocol by expecting to receive the provided data from the peer
    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let packet = self.recv.recv().await.unwrap();

        assert_eq!(packet.data, data);
        assert_eq!(packet.address, addr);
    }
}

/// A mocked peripheral that can be used to test the BTP protocol
///
/// It provides facilities to send data as if it is the peer (the "peripheral") which is sending it,
/// as well as facilities to assert what data is expected to be received by the peer.
///
/// Sending/receiving data on behalf of the peer (the "peripheral") is done using the `Peripheral` struct,
/// while sending/receiving data on behalf of us (the BTP protocol) is done using the `Io` struct.
struct GattPeriheralMock {
    sender: async_channel::Sender<PeripheralOutgoing>,
    receiver: async_channel::Receiver<PeripheralIncoming>,
}

impl GattPeriheralMock {
    /// Run the provided test closure using the mock peripheral
    ///
    /// The test closure may use the provided `Peripheral` instance
    /// to send and receive data on behalf of the peer ("peripheral").
    ///
    /// The test closure may use the provided `Io` instance to send
    /// and receive data on behalf of "us" (i.e. the BTP protocol).
    fn run<T>(test: T)
    where
        T: FnOnce(
            Peripheral,
            Io,
        ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>,
    {
        // Pipe send/receive data between the mocked peripheral and the BTP protocol using channels.

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
                            .send(IoPacket {
                                data: buf,
                                address: addr,
                            })
                            .await
                            .unwrap();
                    }

                    Ok(())
                },
                async {
                    while let Ok::<IoPacket, _>(packet) = io_btp_receiver.recv().await {
                        btp.send(&packet.data, packet.address).await.unwrap();
                    }

                    Ok(())
                },
                test(
                    Peripheral {
                        peer_sender,
                        peer_receiver,
                    },
                    Io {
                        send: io_sender.clone(),
                        recv: io_receiver.clone(),
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
            .send(PeripheralOutgoing {
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
                PeripheralIncoming::Subscribed(addr) => {
                    callback(GattPeripheralEvent::NotifySubscribed(addr));
                }
                PeripheralIncoming::Unsubscribed(addr) => {
                    callback(GattPeripheralEvent::NotifyUnsubscribed(addr));
                }
                PeripheralIncoming::Write {
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
    GattPeriheralMock::run(|peripheral, io| {
        Box::pin(async move {
            peripheral
                .send(
                    &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                    PEER_ADDR,
                    Some(0xc8),
                )
                .await;

            peripheral.subscribe(PEER_ADDR).await;

            // io.context.sessions.lock(|sessions| {
            //     assert!(sessions.borrow().len() == 1);
            // });

            peripheral
                .expect(&[0x65, 0x6c, 0x05, 0xc5, 0x00, 0x05], PEER_ADDR)
                .await;

            peripheral.unsubscribe(PEER_ADDR).await;

            Timer::after(Duration::from_secs(1)).await;

            io.context.sessions.lock(|sessions| {
                assert!(sessions.borrow().is_empty());
            });

            /////////////////////////////////

            peripheral
                .send(
                    &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                    PEER_ADDR,
                    None,
                )
                .await;

            peripheral.subscribe(PEER_ADDR).await;

            // io.context.sessions.lock(|sessions| {
            //     assert!(sessions.borrow().len() == 1);
            // });

            // Peer window = 1 because of this handshake resp
            peripheral
                .expect(&[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05], PEER_ADDR)
                .await;

            io.send(&[0, 1, 2, 3], PEER_ADDR).await;

            // Peer window = 2
            peripheral
                .expect(&[5, 1, 4, 0, 0, 1, 2, 3], PEER_ADDR)
                .await;

            io.send(&[0; 100], PEER_ADDR).await;

            // Peer window = 3
            peripheral
                .expect(
                    &[1, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            // Peer window = 4
            peripheral
                .expect(
                    &[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            // Send ACK from the peer as its window is full by now (5 - 1) = 4
            peripheral.send(&[8, 3, 0], PEER_ADDR, None).await;

            // Peer window = 0, final packet
            peripheral
                .expect(
                    &[10, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            // ----------------------

            peripheral.unsubscribe(PEER_ADDR).await;

            Timer::after(Duration::from_secs(1)).await;

            io.context.sessions.lock(|sessions| {
                assert!(sessions.borrow().is_empty());
            });

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
