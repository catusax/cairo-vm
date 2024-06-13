use std::borrow::Cow;

use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::memory_errors::MemoryError;
use crate::Felt252;
use crate::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use std::ops::Shl;

/// A helper struct to continuously write and read from a buffer in the VM memory.
pub struct MemBuffer<'a> {
    /// The VM to write to.
    /// This is a trait so that we would borrow the actual VM only once.
    vm: &'a mut VirtualMachine,
    /// The current location of the buffer.
    pub ptr: Relocatable,
}
impl<'a> MemBuffer<'a> {
    /// Creates a new buffer.
    pub fn new(vm: &'a mut VirtualMachine, ptr: Relocatable) -> Self {
        Self { vm, ptr }
    }

    /// Creates a new segment and returns a buffer wrapping it.
    pub fn new_segment(vm: &'a mut VirtualMachine) -> Self {
        let ptr = vm.add_memory_segment();
        Self::new(vm, ptr)
    }

    /// Returns the current position of the buffer and advances it by one.
    fn next(&mut self) -> Relocatable {
        let ptr = self.ptr;
        self.ptr += 1;
        ptr
    }

    /// Returns the felt252 value in the current position of the buffer and advances it by one.
    /// Fails if the value is not a felt252.
    /// Borrows the buffer since a reference is returned.
    pub fn next_felt252(&mut self) -> Result<Cow<'_, Felt252>, MemoryError> {
        let ptr = self.next();
        self.vm.get_integer(ptr)
    }

    /// Returns the bool value in the current position of the buffer and advances it by one.
    /// Fails with `MemoryError` if the value is not a felt252.
    /// Panics if the value is not a bool.
    pub fn next_bool(&mut self) -> Result<bool, MemoryError> {
        let ptr = self.next();
        Ok(!(self.vm.get_integer(ptr)?.is_zero()))
    }

    /// Returns the usize value in the current position of the buffer and advances it by one.
    /// Fails with `MemoryError` if the value is not a felt252.
    /// Panics if the value is not a usize.
    pub fn next_usize(&mut self) -> Result<usize, MemoryError> {
        Ok(self.next_felt252()?.to_usize().unwrap())
    }

    /// Returns the u128 value in the current position of the buffer and advances it by one.
    /// Fails with `MemoryError` if the value is not a felt252.
    /// Panics if the value is not a u128.
    pub fn next_u128(&mut self) -> Result<u128, MemoryError> {
        Ok(self.next_felt252()?.to_u128().unwrap())
    }

    /// Returns the u64 value in the current position of the buffer and advances it by one.
    /// Fails with `MemoryError` if the value is not a felt252.
    /// Panics if the value is not a u64.
    #[allow(unused)]
    pub fn next_u64(&mut self) -> Result<u64, MemoryError> {
        Ok(self.next_felt252()?.to_u64().unwrap())
    }

    /// Returns the u256 value encoded starting from the current position of the buffer and advances
    /// it by two.
    /// Fails with `MemoryError` if any of the next two values are not felt252s.
    /// Panics if any of the next two values are not u128.
    pub fn next_u256(&mut self) -> Result<BigUint, MemoryError> {
        Ok(self.next_u128()? + BigUint::from(self.next_u128()?).shl(128))
    }

    /// Returns the address value in the current position of the buffer and advances it by one.
    /// Fails if the value is not an address.
    #[allow(unused)]
    pub fn next_addr(&mut self) -> Result<Relocatable, MemoryError> {
        let ptr = self.next();
        self.vm.get_relocatable(ptr)
    }

    // /// Returns the array of integer values pointed to by the two next addresses in the buffer and
    // /// advances it by two. Will fail if the two values are not addresses or if the addresses do
    // /// not point to an array of integers.
    // pub fn next_arr(&mut self) -> Result<Vec<Felt252>, HintError> {
    //     let start = self.next_addr()?;
    //     let end = self.next_addr()?;
    //     vm_get_range(self.vm, start, end)
    // }

    /// Writes a value to the current position of the buffer and advances it by one.
    pub fn write<T: Into<MaybeRelocatable>>(&mut self, value: T) -> Result<(), MemoryError> {
        let ptr = self.next();
        self.vm.insert_value(ptr, value)
    }
    /// Writes an iterator of values starting from the current position of the buffer and advances
    /// it to after the end of the written value.
    pub fn write_data<T: Into<MaybeRelocatable>, Data: Iterator<Item = T>>(
        &mut self,
        data: Data,
    ) -> Result<(), MemoryError> {
        for value in data {
            self.write(value)?;
        }
        Ok(())
    }

    /// Writes an array into a new segment and writes the start and end pointers to the current
    /// position of the buffer. Advances the buffer by two.
    pub fn write_arr<T: Into<MaybeRelocatable>, Data: Iterator<Item = T>>(
        &mut self,
        data: Data,
    ) -> Result<(), MemoryError> {
        let (start, end) = segment_with_data(self.vm, data)?;
        self.write(start)?;
        self.write(end)
    }
}

/// Creates a new segment in the VM memory and writes data to it, returning the start and end
/// pointers of the segment.
fn segment_with_data<T: Into<MaybeRelocatable>, Data: Iterator<Item = T>>(
    vm: &mut VirtualMachine,
    data: Data,
) -> Result<(Relocatable, Relocatable), MemoryError> {
    let mut segment = MemBuffer::new_segment(vm);
    let start = segment.ptr;
    segment.write_data(data)?;
    Ok((start, segment.ptr))
}
