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

use core::fmt;
use core::hash::Hash;
use core::hash::Hasher;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ops;
use core::pin::Pin;

use super::{Alloc, Dealloc};

/// A pointer type that uniquely owns a (possibly pooled) allocation of type `T`.
///
/// There are three main differences between this `Box` type and the Rust standard `alloc::boxed::Box` type:
/// - This `Box` type is not tied to the global allocator, and can be used with custom allocators
/// - This `Box` type can be used with pooled allocators, because - unlike the `core::alloc::Allocator` trait
///   which is part of the unstable Rust [allocator-api]() feature - this type uses an `Alloc` and `Dealloc` traits
///   which are generic over `T`. TBD: Show where in the `allocator-api` RFC the `ObjectAllocator` was discussed.
/// - This `Box` type only supports fallible allocations. I.e. `Box::new` returns an `Option<Box<T>>` instead of a `Box<T>`.
///
/// These properties of the `Box` type make it suitable for use in embedded systems, where the allocations might be done from
/// a pool rather than from a global or a local heap.
pub struct Box<T, D: Dealloc<T>> {
    ptr: *mut T,
    dealloc: D,
}

impl<T, D: Dealloc<T>> Box<T, D> {
    /// Constructs a box from a raw pointer and a deallocator.
    ///
    /// After calling this function, the raw pointer and the deallocator
    /// are owned by the resulting `Box`.
    /// Specifically, the `Box` destructor will call
    /// the destructor of `T` and free the allocated memory using the deallocator `D`.
    /// For this to be safe, the memory must have been allocated with an `Alloc`
    /// allocator where `Alloc<Dealloc = D>`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because improper use may lead to
    /// memory problems. For example, a double-free may occur if the
    /// function is called twice on the same raw pointer.
    ///
    pub const unsafe fn from_raw(raw: *mut T, dealloc: D) -> Self {
        Self { ptr: raw, dealloc }
    }

    /// Consumes the `Box`, returning a wrapped raw pointer and the deallocator.
    ///
    /// The pointer will be properly aligned and non-null.
    ///
    /// After calling this function, the caller is responsible for the
    /// memory previously managed by the `Box`. In particular, the
    /// caller should properly destroy `T` and release the memory, taking
    /// into account the [memory layout] used by `Box`. The easiest way to
    /// do this is to convert the raw pointer and the deallocator back into a `Box` with the
    /// [`Box::from_raw`] function, allowing the `Box` destructor to perform
    /// the cleanup.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `Box::into_raw(b)` instead of `b.into_raw()`. This
    /// is so that there is no conflict with a method on the inner type.
    pub fn into_raw(b: Self) -> (*mut T, D)
    where
        D: Clone,
    {
        let b = ManuallyDrop::new(b);
        let raw = b.ptr;
        let dealloc = b.dealloc.clone();

        (raw, dealloc)
    }

    // Consumes and leaks the `Box`, returning a mutable reference,
    /// `&'a mut T`. Note that the type `T` must outlive the chosen lifetime
    /// `'a`. If the type has only static references, or none at all, then this
    /// may be chosen to be `'static`.
    ///
    /// This function is mainly useful for data that lives for the remainder of
    /// the program's life. Dropping the returned reference will cause a memory
    /// leak. If this is not acceptable, the reference should first be wrapped
    /// with the [`Box::from_raw`] function producing a `Box`. This `Box` can
    /// then be dropped which will properly destroy `T` and release the
    /// allocated memory.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `Box::leak(b)` instead of `b.leak()`. This
    /// is so that there is no conflict with a method on the inner type.
    #[inline]
    pub fn leak<'b>(self) -> &'b mut T {
        unsafe { &mut *core::mem::ManuallyDrop::new(self).ptr }
    }

    /// Converts a `Box<T, D>` into a `Pin<Box<T, D>>`. If `T` does not implement [`Unpin`], then
    /// `*boxed` will be pinned in memory and unable to be moved.
    ///
    /// This conversion does not allocate on the heap and happens in place.
    ///
    /// This is also available via [`From`].
    ///
    /// Constructing and pinning a `Box` with <code>Box::into_pin([Box::new]\(x, ...))</code>
    /// can also be written more concisely using <code>[Box::pin]\(x)</code>.
    /// This `into_pin` method is useful if you already have a `Box<T>`, or you are
    /// constructing a (pinned) `Box` in a different way than with [`Box::new`].
    ///
    /// # Notes
    ///
    /// It's not recommended that crates add an impl like `From<Box<T>> for Pin<T>`,
    /// as it'll introduce an ambiguity when calling `Pin::from`.
    pub fn into_pin(boxed: Self) -> Pin<Self>
    where
        T: 'static,
    {
        // It's not possible to move or replace the insides of a `Pin<Box<T>>`
        // when `T: !Unpin`, so it's safe to pin it directly without any
        // additional requirements.
        unsafe { Pin::new_unchecked(boxed) }
    }
}

impl<T, D: Dealloc<MaybeUninit<T>>> Box<MaybeUninit<T>, D> {
    /// Allocates memory for object `T` using the provided allocator and then places `value` into it.
    ///
    /// If the allocator does not have enough memory to allocate the object, this function will return `None`.
    #[inline(always)]
    pub fn new<A>(alloc: A, value: T) -> Option<Box<T, D>>
    where
        A: Alloc<T, Dealloc = D>,
        D: Dealloc<T> + Clone,
    {
        Self::new_uninit(alloc).map(|b| Box::write(b, value))
    }

    // Constructs a new `Pin<Box<T, D>>`. If `T` does not implement [`Unpin`], then
    /// `value` will be pinned in memory and unable to be moved.
    ///
    /// Constructing and pinning of the `Box` can also be done in two steps: `Box::pin(alloc, value)`
    /// does the same as <code>[Box::into_pin]\([Box::new]\(alloc_value))</code>. Consider using
    /// [`into_pin`](Box::into_pin) if you already have a `Box<T>`, or if you want to
    /// construct a (pinned) `Box` in a different way than with [`Box::new`].    
    ///
    /// If the allocator does not have enough memory to allocate the object, this function will return `None`.
    pub fn pin<A>(alloc: A, value: T) -> Option<Pin<Box<T, D>>>
    where
        A: Alloc<T, Dealloc = D>,
        D: Dealloc<T> + Clone,
        T: 'static,
    {
        Self::new(alloc, value).map(Into::into)
    }

    /// Constructs a new box with uninitialized contents using the supplied `Alloc` instance,
    /// returning `None` if the allocation fails
    pub fn new_uninit<A>(mut alloc: A) -> Option<Self>
    where
        A: Alloc<T, Dealloc = D>,
        D: Dealloc<T>,
    {
        let (ptr, dealloc) = alloc.alloc()?;

        Some(Box { ptr, dealloc })
    }

    /// Writes the value and converts to `Box<T, D>`.
    ///
    /// This method converts the box similarly to [`Box::assume_init`] but
    /// writes `value` into it before conversion thus guaranteeing safety.
    /// In some scenarios use of this method may improve performance because
    /// the compiler may be able to optimize copying from stack.
    #[inline(always)]
    pub fn write(mut boxed: Self, value: T) -> Box<T, D>
    where
        D: Dealloc<T> + Clone,
    {
        unsafe {
            (*boxed).write(value);
            boxed.assume_init()
        }
    }

    /// Converts to `Box<T, D>`.
    ///
    /// # Safety
    ///
    /// As with [`MaybeUninit::assume_init`],
    /// it is up to the caller to guarantee that the value
    /// really is in an initialized state.
    /// Calling this when the content is not yet fully initialized
    /// causes immediate undefined behavior.
    ///
    /// [`MaybeUninit::assume_init`]: mem::MaybeUninit::assume_init
    #[inline(always)]
    pub unsafe fn assume_init(self) -> Box<T, D>
    where
        D: Dealloc<T> + Clone,
    {
        let (raw, dealloc) = Box::into_raw(self);

        Box {
            ptr: raw as *mut T,
            dealloc,
        }
    }
}

impl<T, D> From<Box<T, D>> for Pin<Box<T, D>>
where
    T: 'static,
    D: Dealloc<T>,
{
    fn from(boxed: Box<T, D>) -> Pin<Box<T, D>> {
        Box::into_pin(boxed)
    }
}

// impl<T> Clone for Box<T>
// where
//     T: Clone,
// {
//     fn clone(&self) -> Self {
//         Box::new((**self).clone())
//     }
// }

impl<T, D: Dealloc<T>> fmt::Debug for Box<T, D>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::fmt(self, f)
    }
}

impl<T, D: Dealloc<T>> ops::Deref for Box<T, D> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr.cast::<T>() }
    }
}

impl<T, D: Dealloc<T>> ops::DerefMut for Box<T, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr.cast::<T>() }
    }
}

impl<T, D: Dealloc<T>> fmt::Display for Box<T, D>
where
    T: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::fmt(self, f)
    }
}

impl<T, D: Dealloc<T>> Drop for Box<T, D> {
    fn drop(&mut self) {
        let ptr = self.ptr;

        unsafe {
            core::ptr::drop_in_place(ptr);

            self.dealloc.dealloc(ptr);
        }
    }
}

impl<T, D: Dealloc<T>> Eq for Box<T, D> where T: Eq {}

impl<T, D: Dealloc<T>> Hash for Box<T, D>
where
    T: Hash,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        (**self).hash(state)
    }
}

impl<T, D: Dealloc<T>> Ord for Box<T, D>
where
    T: Ord,
{
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        T::cmp(self, other)
    }
}

impl<A, AD, B, BD> PartialEq<Box<B, BD>> for Box<A, AD>
where
    A: PartialEq<B>,
    AD: Dealloc<A>,
    BD: Dealloc<B>,
{
    fn eq(&self, other: &Box<B, BD>) -> bool {
        A::eq(self, other)
    }
}

impl<A, AD, B, BD> PartialOrd<Box<B, BD>> for Box<A, AD>
where
    A: PartialOrd<B>,
    AD: Dealloc<A>,
    BD: Dealloc<B>,
{
    fn partial_cmp(&self, other: &Box<B, BD>) -> Option<core::cmp::Ordering> {
        A::partial_cmp(self, other)
    }
}

unsafe impl<T, D: Dealloc<T>> Send for Box<T, D> where T: Send {}
unsafe impl<T, D: Dealloc<T>> Sync for Box<T, D> where T: Sync {}
