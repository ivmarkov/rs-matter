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

use core::mem::MaybeUninit;

pub mod boxed;
pub mod pool;

/// An allocator trat capable of allocating and deallocating memory for a type `T`.
///
/// Allocation might be done from a global heap, or from a pool of pre-allocated memory.
pub trait Alloc<T> {
    /// The type of the deallocator returned by `alloc`.
    type Dealloc: Dealloc<T>;

    /// Allocate memory for a value of type `T`.
    fn alloc(&mut self) -> Option<(*mut MaybeUninit<T>, Self::Dealloc)>;
}

impl<A, T> Alloc<T> for &mut A
where
    A: Alloc<T>,
{
    type Dealloc = A::Dealloc;

    fn alloc(&mut self) -> Option<(*mut MaybeUninit<T>, Self::Dealloc)> {
        (*self).alloc()
    }
}

/// A trait capable of deallocating memory for a type `T`.
pub trait Dealloc<T> {
    /// Deallocate memory for a value of type `T`.
    ///
    /// # Safety
    /// TBD
    unsafe fn dealloc(&mut self, ptr: *mut T);
}

impl<D, T> Dealloc<T> for &mut D
where
    D: Dealloc<T>,
{
    unsafe fn dealloc(&mut self, ptr: *mut T) {
        (*self).dealloc(ptr)
    }
}
