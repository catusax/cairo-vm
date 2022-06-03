use crate::{types::relocatable::MaybeRelocatable, utils::from_relocatable_to_indexes};

#[derive(Clone)]
pub struct Memory {
    pub data: Vec<Vec<MaybeRelocatable>>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            data: Vec::<Vec<MaybeRelocatable>>::new(),
        }
    }
    pub fn insert(&mut self, key: &MaybeRelocatable, val: &MaybeRelocatable) {
        if let MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable.clone());
            //Check that the memory segment exists
            if self.data.len() < i {
                panic!("Cant insert to a non-allocated memory segment")
            }
            //Check that the element is inserted next to the las one on the segment
            //Forgoing this check would allow data to be inserted in a different index
            if self.data[i].len() < j {
                panic!("Memory must be continuous")
            }
            self.data[i].push(val.clone())
        } else {
            panic!("Memory addresses must be relocatable")
        }
    }
    pub fn get(&self, key: &MaybeRelocatable) -> Option<&MaybeRelocatable> {
        if let MaybeRelocatable::RelocatableValue(relocatable) = key {
            let (i, j) = from_relocatable_to_indexes(relocatable.clone());
            if self.data.len() <= i && self.data[i].len() <= j {
                Some(&self.data[i][j])
            } else {
                None
            }
        } else {
            panic!("Memory addresses must be relocatable")
        }
    }

    #[allow(dead_code)]
    pub fn from(
        key_val_list: Vec<(MaybeRelocatable, MaybeRelocatable)>,
        num_segements: usize,
    ) -> Self {
        let mut memory = Memory::new();
        for _ in 0..num_segements {
            memory.data.push(Vec::new());
        }
        for (key, val) in key_val_list.iter() {
            memory.insert(key, val);
        }
        memory
    }
}

#[cfg(test)]
mod memory_tests {
    use crate::relocatable;

    use super::*;
    use num_bigint::BigInt;
    use num_traits::FromPrimitive;

    #[test]
    fn get_test() {
        let key = MaybeRelocatable::RelocatableValue(relocatable!(0, 0));
        let val = MaybeRelocatable::Int(BigInt::from_i32(5).unwrap());
        let _val_clone = val.clone();
        let mut mem = Memory::new();
        mem.data.push(Vec::new());
        mem.insert(&key, &val);
        assert_eq!(matches!(mem.get(&key), _val_clone), true);
    }

    #[test]
    fn from_array_test() {
        let mem = Memory::from(
            vec![(
                MaybeRelocatable::RelocatableValue(relocatable!(1, 0)),
                MaybeRelocatable::Int(BigInt::from_i32(5).unwrap()),
            )],
            2,
        );
        assert_eq!(
            matches!(
                mem.get(&MaybeRelocatable::RelocatableValue(relocatable!(1, 0))),
                _val_clone
            ),
            true
        );
    }
}
