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

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;

use portable_atomic::AtomicBool;
use portable_atomic::Ordering;

use super::boxed::Box;
use super::{Alloc, Dealloc};

/// A simple memory pool based on a fixed-size array of `MaybeUninit<T>`
/// that can allocate memory for objects of type `T`.
///
/// `Pool` has four key properties that make it suitable for use in embedded systems:
/// - It pre-allocates all memory upfront, so there are no dynamic memory allocations;
/// - It is `const`-newable and thread-safe and therefore can be statically allocated,
///   as in `static POOL: Pool<Foo, 4> = Pool::new()`;
/// - It has a very carefully chosen memory layout that contains only 0s and `MaybeUninit`
///   and thus static instances of it will be placed in the `.bss` section by the linker,
///   thus not occupying any flash size (`.rodata`) memory;
/// - It is expected that the compiler will not reserve flash memory for constants of type `Pool`
///   either, but would rather generate the pool's memory layout at runtime with `memset`.
///
/// References to the pool (i.e. `&Pool<T, N>`) implement the `Alloc` contract and therefore
/// can be used with the `Box` type.
pub struct Pool<T, const N: usize> {
    used: [AtomicBool; N],
    slots: UnsafeCell<[MaybeUninit<T>; N]>,
}

impl<T, const N: usize> Pool<T, N> {
    const INIT: [MaybeUninit<T>; N] = [Self::ELEM_INIT; N]; // Important for optimization of `new`
    const ELEM_INIT: MaybeUninit<T> = MaybeUninit::uninit();
    #[allow(clippy::declare_interior_mutable_const)]
    const ATOMIC_INIT: AtomicBool = AtomicBool::new(false);

    /// Create a new pool with `N` slots.
    pub const fn new() -> Self {
        Self {
            used: [Self::ATOMIC_INIT; N],
            slots: UnsafeCell::new(Self::INIT),
        }
    }

    /// Allocates a slot from the pool or returns `None` if no slots are available.
    fn alloc(&self) -> Option<(*mut MaybeUninit<T>, PoolSlot<T, N>)> {
        for slot in 0..N {
            if let Ok(prev_used) =
                self.used[slot].compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            {
                assert!(!prev_used, "Double alloc");

                let ptr = unsafe { self.slots.get().as_mut() }.unwrap()[slot].as_mut_ptr()
                    as *mut MaybeUninit<T>;

                let slot = PoolSlot { slot, pool: self };

                return Some((ptr, slot));
            }
        }

        None
    }

    /// Retruns an allocated slot to the pool.
    unsafe fn dealloc(&self, index: usize) {
        let prev = self.used[index].swap(false, Ordering::SeqCst);
        assert!(prev, "Double free");
    }
}

impl<'a, T, const N: usize> Alloc<T> for &'a Pool<T, N> {
    type Dealloc = PoolSlot<'a, T, N>;

    fn alloc(&mut self) -> Option<(*mut MaybeUninit<T>, Self::Dealloc)> {
        Pool::alloc(self)
    }
}

unsafe impl<T, const N: usize> Send for Pool<T, N> {}
unsafe impl<T, const N: usize> Sync for Pool<T, N> {}

impl<T, const N: usize> Default for Pool<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

/// A type alias for a `Box` that uses a `Pool` as its `Alloc` allocator.
pub type PoolBox<'a, T, const N: usize> = Box<T, PoolSlot<'a, T, N>>;

/// A deallocator for memory allocated from a `Pool`.
pub struct PoolSlot<'a, T, const N: usize> {
    /// The slot index in the pool which was allocated
    slot: usize,
    /// The pool from which the memory was allocated
    pool: &'a Pool<T, N>,
}

impl<'a, T, const N: usize> fmt::Debug for PoolSlot<'a, T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolSlot")
            .field("slot", &self.slot)
            .finish()
    }
}

impl<'a, T, const N: usize> Clone for PoolSlot<'a, T, N> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot,
            pool: self.pool,
        }
    }
}

impl<'a, T, const N: usize> PoolSlot<'a, T, N> {
    unsafe fn dealloc(&mut self) {
        self.pool.dealloc(self.slot);
    }
}

impl<'a, T, const N: usize> Dealloc<T> for PoolSlot<'a, T, N> {
    unsafe fn dealloc(&mut self, _ptr: *mut T) {
        self.dealloc();
    }
}

impl<'a, T, const N: usize> Dealloc<MaybeUninit<T>> for PoolSlot<'a, T, N> {
    unsafe fn dealloc(&mut self, _ptr: *mut MaybeUninit<T>) {
        self.dealloc();
    }
}
