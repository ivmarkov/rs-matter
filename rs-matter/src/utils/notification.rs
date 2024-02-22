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

use core::future::Future;
use core::num::NonZeroUsize;
use core::task::{Context, Poll, Waker};

use atomic_waker::AtomicWaker;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::mutex::{Mutex, MutexGuard};
use portable_atomic::{AtomicUsize, Ordering};

/// Single-slot lock-free signaling primitive supporting signalling with a `usize` bit-set.
///
/// It is useful for sending data between tasks when the receiver only cares about
/// the latest data, and therefore it's fine to "lose" messages. This is often the case for "state"
/// updates.
///
/// The sending part of the primitive is non-blocking, so it is also useful for notifying asynchronous tasks
/// from contexts where blocking or async wait is not possible.
pub struct Notification {
    waker: AtomicWaker,
    notified: AtomicUsize,
}

impl Notification {
    /// Creates a new `Notification`.
    pub const fn new() -> Self {
        Self {
            waker: AtomicWaker::new(),
            notified: AtomicUsize::new(0),
        }
    }

    /// Marks the supplied bits in this `Notification` as notified.
    /// Returns `true` if there was a registered waker which got awoken.
    pub fn notify(&self, bits: NonZeroUsize) -> bool {
        if let Some(waker) = self.notify_waker(bits) {
            waker.wake();

            true
        } else {
            false
        }
    }

    /// A utility to help in implementing a custom `wait` logic:
    /// Adds the supplied bits as notified in the notification instance and returns the registered waker (if any).
    pub fn notify_waker(&self, bits: NonZeroUsize) -> Option<Waker> {
        self.notified.fetch_or(bits.into(), Ordering::SeqCst);

        self.waker.take()
    }

    /// Clears the state of this notification by removing any registered waker and setting all bits to 0.
    pub fn reset(&self) {
        self.waker.take();
        self.notified.store(0, Ordering::SeqCst);
    }

    /// Future that completes when this `Notification` has been notified.
    #[allow(unused)]
    pub fn wait(&self, bits: NonZeroUsize) -> impl Future<Output = NonZeroUsize> + '_ {
        core::future::poll_fn(move |cx| self.poll_wait(cx, bits))
    }

    /// Non-blocking method to check whether this notification has been notified.
    pub fn poll_wait(&self, cx: &Context<'_>, bits: NonZeroUsize) -> Poll<NonZeroUsize> {
        self.waker.register(cx.waker());

        let raised_bits = self.notified.fetch_and(!bits.get(), Ordering::SeqCst) & bits.get();

        if raised_bits != 0 {
            Poll::Ready(NonZeroUsize::new(raised_bits).unwrap())
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Notification {
    fn drop(&mut self) {
        self.reset();
    }
}

impl Notification {
    pub async fn get<'a, F, T>(
        &'a self,
        shared: &'a Mutex<NoopRawMutex, T>,
        index: u8,
        f: F,
    ) -> DataCarrier<'a, T>
    where
        F: Fn(&T) -> bool,
    {
        loop {
            let guard = shared.lock().await;

            if f(&*guard) {
                break DataCarrier {
                    notification: self,
                    guard,
                    index,
                    notify_others: false,
                };
            }

            drop(guard);

            self.wait(NonZeroUsize::new(1 << index).unwrap()).await;
        }
    }

    pub fn notify_others(&self, index: u8) {
        self.notify(NonZeroUsize::new(!(1 << index)).unwrap());
    }
}

pub struct DataCarrier<'a, T> {
    guard: MutexGuard<'a, NoopRawMutex, T>,
    notification: &'a Notification,
    index: u8,
    notify_others: bool,
}

impl<'a, T> DataCarrier<'a, T> {
    pub fn data(&self) -> &T {
        &self.guard
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.guard
    }

    pub fn notify(&mut self, notify_others: bool) {
        self.notify_others = notify_others;
    }
}

impl<'a, T> Drop for DataCarrier<'a, T> {
    fn drop(&mut self) {
        if self.notify_others {
            self.notification.notify_others(self.index);
        }
    }
}
