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

//! A variation of the `embassy-sync` async mutex that only locks the mutex if a certain condition on the content of the data holds true.
//! Check `embassy_sync::Mutex` for the original unconditional implementation.
use core::cell::{RefCell, UnsafeCell};
use core::future::poll_fn;
use core::ops::{Deref, DerefMut};
use core::task::Poll;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex as BlockingMutex;
use embassy_sync::waitqueue::WakerRegistration;

/// Error returned by [`Mutex::try_lock`]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TryLockError;

struct State {
    locked: bool,
    waker: WakerRegistration,
}

/// Async mutex with conditional locking based on the data inside the mutex.
/// Check `embassy_sync::Mutex` for the original unconditional implementation.
pub struct IfMutex<M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    state: BlockingMutex<M, RefCell<State>>,
    inner: UnsafeCell<T>,
}

unsafe impl<M: RawMutex + Send, T: ?Sized + Send> Send for IfMutex<M, T> {}
unsafe impl<M: RawMutex + Sync, T: ?Sized + Send> Sync for IfMutex<M, T> {}

/// Async mutex.
impl<M, T> IfMutex<M, T>
where
    M: RawMutex,
{
    /// Create a new mutex with the given value.
    #[inline(always)]
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
            state: BlockingMutex::new(RefCell::new(State {
                locked: false,
                waker: WakerRegistration::new(),
            })),
        }
    }
}

impl<M, T> IfMutex<M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked.
    pub async fn lock(&self) -> IfMutexGuard<'_, M, T> {
        self.lock_if(|_| true).await
    }

    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked _and_ for the provided condition on the data to become true.
    pub async fn lock_if<F>(&self, f: F) -> IfMutexGuard<'_, M, T>
    where
        F: Fn(&T) -> bool,
    {
        poll_fn(|cx| {
            let ready = self.state.lock(|s| {
                let mut s = s.borrow_mut();
                if s.locked || !f(unsafe { &*self.inner.get() }) {
                    s.waker.register(cx.waker());
                    false
                } else {
                    s.locked = true;
                    true
                }
            });

            if ready {
                Poll::Ready(IfMutexGuard { mutex: self })
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Lock the mutex.
    ///
    /// This will wait for the mutex to be unlocked if it's already locked _and_ for the provided condition on the data to become true.
    pub async fn with<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut T) -> Option<R>,
    {
        poll_fn(|cx| {
            let result = self.state.lock(|s| {
                let mut s = s.borrow_mut();
                if s.locked {
                    s.waker.register(cx.waker());
                    None
                } else if let Some(result) = f(unsafe { &mut *self.inner.get() }) {
                    s.waker.wake();
                    Some(result)
                } else {
                    s.waker.register(cx.waker());
                    None
                }
            });

            if let Some(result) = result {
                Poll::Ready(result)
            } else {
                Poll::Pending
            }
        })
        .await
    }

    // /// Attempt to immediately lock the mutex.
    // ///
    // /// If the mutex is already locked or the condition on the data is not true, this will return an error instead of waiting.
    // pub fn try_lock_if<F, R>(&self, mut f: F) -> Result<(R, IfMutexGuard<'_, M, T>), TryLockError>
    // where
    //     F: FnMut(&mut T) -> Option<R>,
    // {
    //     let result = self.state.lock(|s| {
    //         let mut s = s.borrow_mut();
    //         if s.locked {
    //             Err(TryLockError)
    //         } else if let Some(result) = f(unsafe { &mut *self.inner.get() }) {
    //             s.locked = true;
    //             Ok(result)
    //         } else {
    //             Err(TryLockError)
    //         }
    //     })?;

    //     Ok((result, IfMutexGuard { mutex: self }))
    // }

    /// Consumes this mutex, returning the underlying data.
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        self.inner.into_inner()
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the Mutex mutably, no actual locking needs to
    /// take place -- the mutable borrow statically guarantees no locks exist.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

/// Async mutex guard.
///
/// Owning an instance of this type indicates having
/// successfully locked the mutex, and grants access to the contents.
///
/// Dropping it unlocks the mutex.
pub struct IfMutexGuard<'a, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    mutex: &'a IfMutex<M, T>,
}

impl<'a, M, T> Drop for IfMutexGuard<'a, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    fn drop(&mut self) {
        self.mutex.state.lock(|s| {
            let mut s = s.borrow_mut();
            s.locked = false;
            s.waker.wake();
        })
    }
}

impl<'a, M, T> Deref for IfMutexGuard<'a, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &*(self.mutex.inner.get() as *const T) }
    }
}

impl<'a, M, T> DerefMut for IfMutexGuard<'a, M, T>
where
    M: RawMutex,
    T: ?Sized,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        // Safety: the MutexGuard represents exclusive access to the contents
        // of the mutex, so it's OK to get it.
        unsafe { &mut *(self.mutex.inner.get()) }
    }
}
