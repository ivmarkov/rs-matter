use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};

use embassy_sync::{
    blocking_mutex::{raw::NoopRawMutex, Mutex},
    waitqueue::WakerRegistration,
};

struct State<S> {
    state: S,
    waker: WakerRegistration,
}

pub struct Notification2<S>(Mutex<NoopRawMutex, RefCell<State<S>>>);

impl<S> Notification2<S> {
    pub const fn new(state: S) -> Self {
        Self(Mutex::new(RefCell::new(State {
            state,
            waker: WakerRegistration::new(),
        })))
    }

    pub fn modify<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut S) -> R,
    {
        self.0.lock(|s| {
            let mut s = s.borrow_mut();

            let result = f(&mut s.state);

            s.waker.wake();

            result
        })
    }

    pub async fn wait<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut S) -> Option<R>,
    {
        poll_fn(move |ctx| self.poll_wait(ctx, &mut f)).await
    }

    pub fn poll_wait<F, R>(&self, ctx: &mut Context, f: F) -> Poll<R>
    where
        F: FnOnce(&mut S) -> Option<R>,
    {
        self.0.lock(|s| {
            let mut s = s.borrow_mut();

            if let Some(result) = f(&mut s.state) {
                Poll::Ready(result)
            } else {
                s.waker.register(ctx.waker());
                Poll::Pending
            }
        })
    }
}
