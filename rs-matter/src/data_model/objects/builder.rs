// response struct ScanNetworksResponse = 1 {
//     NetworkCommissioningStatusEnum networkingStatus = 0;
//     optional char_string debugText = 1;
//     optional WiFiInterfaceScanResultStruct wiFiScanResults[] = 2;
//     optional ThreadInterfaceScanResultStruct threadScanResults[] = 3;
//   }

use core::marker::PhantomData;

use crate::{error::Error, tlv::{TLVTag, TLVWrite}};

pub mod state {
    pub struct S0;
    pub struct S1;
    pub struct S2;
    pub struct S3;
    pub struct S4;
    pub struct S5;
    pub struct S6;
    pub struct S7;
    pub struct S8;
    pub struct S9;
    pub struct S10;
    pub struct S11;
    pub struct S12;
    pub struct S13;
    pub struct S14;
    pub struct S15;
    pub struct S16;
    pub struct S17;
    pub struct S18;
    pub struct S19;
    pub struct S20;

}

pub trait AsWrite {
    type Write: TLVWrite;

    fn as_write(&mut self) -> &mut Self::Write;
}

impl<T> AsWrite for &mut T 
where 
    T: AsWrite,
{
    type Write = T::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        (**self).as_write()
    }
}

pub struct CmdResponse<W, T, S = state::S0>(W, PhantomData<S>, PhantomData<T>);

impl<W, S, T> CmdResponse<W, S, T> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData, PhantomData)
    }
}

pub trait Builder<W>: Sized {
    fn new(tag: &TLVTag, write: W) -> Result<Self, Error>;
}

pub trait BuilderFactory {
    type Builder<W>: Builder<W> where W: AsWrite;
}

impl<W, T> CmdResponse<W, T, state::S0> 
where 
    W: AsWrite,
    T: BuilderFactory,
{
    pub fn resp(mut write: W) -> Result<T::Builder<CmdResponse<W, T, state::S1>>, Error> {
        write.as_write().start_struct(&TLVTag::Context(0))?;

        T::Builder::new(&TLVTag::Context(1), CmdResponse::wrap_unchecked(write))
    }
}

impl<W, T> CmdResponse<W, T, state::S1> 
where 
    W: AsWrite,
    T: BuilderFactory,
{
    pub fn complete(mut self) -> Result<W, Error> {
        self.0.as_write().end_container()?;

        Ok(self.0)
    }
}

impl<W, T, S> AsWrite for CmdResponse<W, T, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

pub struct WifiInterfaceScanResultFactory;

impl BuilderFactory for WifiInterfaceScanResultFactory {
    type Builder<W> = WiFiInterfaceScanResult<W, state::S0> where W: AsWrite;
}

pub struct WiFiInterfaceScanResult<W, S = state::S0>(W, PhantomData<S>);

impl<W, S> WiFiInterfaceScanResult<W, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData)
    }
}

impl<W> WiFiInterfaceScanResult<W, state::S0>
where 
    W: AsWrite,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_struct(tag)?;

        Ok(Self::wrap_unchecked(write))
    }
}

impl<W, S> AsWrite for WiFiInterfaceScanResult<W, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

impl<W> Builder<W> for WiFiInterfaceScanResult<W, state::S0> 
where 
    W: AsWrite,
{
    fn new(tag: &TLVTag, write: W) -> Result<Self, Error> {
        WiFiInterfaceScanResult::new(tag, write)
    }
}

pub struct TLVArrayFactory<T>(PhantomData<T>);

impl<T> BuilderFactory for TLVArrayFactory<T> 
where 
    T: BuilderFactory,
{
    type Builder<W> = TLVArray<W, T, state::S0> where W: AsWrite;
}

impl<W, T> Builder<W> for TLVArray<W, T, state::S0> 
where 
    T: BuilderFactory,
    W: AsWrite,
{
    fn new(tag: &TLVTag, write: W) -> Result<Self, Error> {
        TLVArray::new(tag, write)
    }
}

pub struct TLVArray<W, T, S = state::S0>(W, PhantomData<S>, PhantomData<T>);

impl<W, T, S> TLVArray<W, T, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData, PhantomData)
    }
}

impl<W, T> TLVArray<W, T, state::S0> 
where 
    W: AsWrite,
    T: BuilderFactory,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_array(tag)?;

        Ok(Self::wrap_unchecked(write))
    }

    pub fn push(self) -> Result<T::Builder<Self>, Error> {
        T::Builder::new(&TLVTag::Anonymous, Self::wrap_unchecked(self.0))
    }

    pub fn complete(mut self) -> Result<W, Error> {
        self.0.as_write().end_container()?;

        Ok(self.0)
    }
}

impl<W, T, S> AsWrite for TLVArray<W, T, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

pub struct WifiInterfaceScanResultArray<W, S = state::S0>(W, PhantomData<S>);

impl<W, S> WifiInterfaceScanResultArray<W, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData)
    }
}

impl<W> WifiInterfaceScanResultArray<W, state::S0> 
where 
    W: AsWrite,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_array(tag)?;

        Ok(Self::wrap_unchecked(write))
    }

    pub fn push(self) -> Result<WiFiInterfaceScanResult<Self>, Error> {
        WiFiInterfaceScanResult::new(&TLVTag::Anonymous, Self::wrap_unchecked(self.0))
    }

    pub fn complete(mut self) -> Result<W, Error> {
        self.0.as_write().end_container()?;

        Ok(self.0)
    }
}

impl<W, S> AsWrite for WifiInterfaceScanResultArray<W, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

pub struct ThreadInterfaceScanResultFactory;

impl BuilderFactory for ThreadInterfaceScanResultFactory {
    type Builder<W> = ThreadInterfaceScanResult<W, state::S0> where W: AsWrite;
}

pub struct ThreadInterfaceScanResult<W, S = state::S0>(W, PhantomData<S>);

impl<W, S> ThreadInterfaceScanResult<W, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData)
    }
}

impl<W> ThreadInterfaceScanResult<W, state::S0>
where 
    W: AsWrite,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_struct(tag)?;

        Ok(Self::wrap_unchecked(write))
    }
}

impl<W, S> AsWrite for ThreadInterfaceScanResult<W, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

impl<W> Builder<W> for ThreadInterfaceScanResult<W, state::S0> 
where 
    W: AsWrite,
{
    fn new(tag: &TLVTag, write: W) -> Result<Self, Error> {
        ThreadInterfaceScanResult::new(tag, write)
    }
}

pub struct ThreadInterfaceScanResultArray<W, S = state::S0>(W, PhantomData<S>);

impl<W, S> ThreadInterfaceScanResultArray<W, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData)
    }
}

impl<W> ThreadInterfaceScanResultArray<W, state::S0> 
where 
    W: AsWrite,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_array(tag)?;

        Ok(Self::wrap_unchecked(write))
    }

    pub fn push(self) -> Result<ThreadInterfaceScanResult<Self>, Error> {
        ThreadInterfaceScanResult::new(&TLVTag::Anonymous, Self::wrap_unchecked(self.0))
    }

    pub fn complete(mut self) -> Result<W, Error> {
        self.0.as_write().end_container()?;

        Ok(self.0)
    }
}

impl<W, S> AsWrite for ThreadInterfaceScanResultArray<W, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}

pub struct ScanNetworksResponse<W, S = state::S0>(W, PhantomData<S>);

impl<W, S> ScanNetworksResponse<W, S> {
    const fn wrap_unchecked(write: W) -> Self {
        Self(write, PhantomData)
    }
}

impl<W> ScanNetworksResponse<W, state::S0> 
where 
    W: AsWrite,
{
    pub fn new(tag: &TLVTag, mut write: W) -> Result<Self, Error> {
        write.as_write().start_array(tag)?;

        Ok(Self::wrap_unchecked(write))
    }

    pub fn networking_status(mut self, networking_status: u32) -> Result<ScanNetworksResponse<W, state::S1>, Error> {
        self.0.as_write().u32(&TLVTag::Context(0), networking_status)?;

        Ok(ScanNetworksResponse::wrap_unchecked(self.0))
    }
}


impl<W> ScanNetworksResponse<W, state::S1> 
where 
    W: AsWrite,
{
    pub fn debug_text(mut self, debug_text: &str) -> Result<ScanNetworksResponse<W, state::S2>, Error> {
        self.0.as_write().utf8(&TLVTag::Context(1), debug_text)?;

        Ok(ScanNetworksResponse::wrap_unchecked(self.0))
    }
}

impl<W> ScanNetworksResponse<W, state::S2> 
where 
    W: AsWrite,
{
    pub fn wi_fi_scan_results(self) -> Result<TLVArray<ScanNetworksResponse<W, state::S3>, WifiInterfaceScanResultFactory, state::S0>, Error> {
        TLVArray::new(&TLVTag::Context(2), ScanNetworksResponse::wrap_unchecked(self.0))
    }
}

impl<W> ScanNetworksResponse<W, state::S3> 
where 
    W: AsWrite,
{
    pub fn thread_scan_results(self) -> Result<TLVArray<ScanNetworksResponse<W, state::S4>, ThreadInterfaceScanResultFactory>, Error> {
        TLVArray::new(&TLVTag::Context(3), ScanNetworksResponse::wrap_unchecked(self.0))
    }
}

impl<W> ScanNetworksResponse<W, state::S4> 
where 
    W: AsWrite,
{
    pub fn complete(mut self) -> Result<W, Error> {
        self.0.as_write().end_container()?;

        Ok(self.0)
    }
}

impl<W, S> AsWrite for ScanNetworksResponse<W, S> 
where 
    W: AsWrite,
{
    type Write = W::Write;

    fn as_write(&mut self) -> &mut Self::Write {
        self.0.as_write()
    }
}
