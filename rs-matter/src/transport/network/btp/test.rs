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
    async fn subscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(GattPeripheralEventMock::Subscribed(addr))
            .await
            .unwrap();
    }

    async fn unsubscribe(&self, addr: BtAddr) {
        self.peer_sender
            .send(GattPeripheralEventMock::Unsubscribed(addr))
            .await
            .unwrap();
    }

    async fn send(&self, data: &[u8], addr: BtAddr, gatt_mtu: Option<u16>) {
        self.peer_sender
            .send(GattPeripheralEventMock::Write {
                address: addr,
                data: data.to_vec(),
                gatt_mtu,
            })
            .await
            .unwrap();
    }

    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let received = self.peer_receiver.recv().await.unwrap();

        assert_eq!(received.data, data);
        assert_eq!(received.address, addr);
    }
}

#[derive(Debug)]
struct Packet {
    data: Vec<u8>,
    address: BtAddr,
}

struct IoMock {
    send: async_channel::Sender<Packet>,
    recv: async_channel::Receiver<Packet>,
    context: Arc<BtpContext<StdRawMutex>>,
}

impl IoMock {
    async fn send(&self, data: &[u8], addr: BtAddr) {
        let packet = Packet {
            data: data.to_vec(),
            address: addr,
        };

        self.send.send(packet).await.unwrap();
    }

    async fn expect(&self, data: &[u8], addr: BtAddr) {
        let packet = self.recv.recv().await.unwrap();

        assert_eq!(packet.data, data);
        assert_eq!(packet.address, addr);
    }
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
        ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'static>>,
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
    GattPeriheralMock::run(|driver, io| {
        Box::pin(async move {
            driver
                .send(
                    &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                    PEER_ADDR,
                    Some(0xc8),
                )
                .await;

            driver.subscribe(PEER_ADDR).await;

            // io.context.sessions.lock(|sessions| {
            //     assert!(sessions.borrow().len() == 1);
            // });

            driver
                .expect(&[0x65, 0x6c, 0x05, 0xc5, 0x00, 0x05], PEER_ADDR)
                .await;

            driver.unsubscribe(PEER_ADDR).await;

            Timer::after(Duration::from_secs(1)).await;

            io.context.sessions.lock(|sessions| {
                assert!(sessions.borrow().is_empty());
            });

            /////////////////////////////////

            driver
                .send(
                    &[0x65, 0x6c, 0x54, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x05],
                    PEER_ADDR,
                    None,
                )
                .await;

            driver.subscribe(PEER_ADDR).await;

            // io.context.sessions.lock(|sessions| {
            //     assert!(sessions.borrow().len() == 1);
            // });

            driver
                .expect(&[0x65, 0x6c, 0x05, 0x14, 0x00, 0x05], PEER_ADDR)
                .await;

            io.send(&[0, 1, 2, 3], PEER_ADDR).await;

            driver.expect(&[5, 1, 4, 0, 0, 1, 2, 3], PEER_ADDR).await;

            io.send(&[0; 100], PEER_ADDR).await;

            driver
                .expect(
                    &[1, 2, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            driver
                .expect(
                    &[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            driver.send(&[1, 2, 3, 4], PEER_ADDR, None).await;

            driver
                .expect(
                    &[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    PEER_ADDR,
                )
                .await;

            // ----------------------

            driver.unsubscribe(PEER_ADDR).await;

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
