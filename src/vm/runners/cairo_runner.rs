use crate::bigint;
use crate::types::program::Program;
use crate::types::relocatable::{relocate_value, MaybeRelocatable, Relocatable};
use crate::utils::is_subsequence;
use crate::vm::runners::builtin_runner::{
    BuiltinRunner, OutputBuiltinRunner, RangeCheckBuiltinRunner,
};
use crate::vm::trace::trace_entry::{relocate_trace_register, RelocatedTraceEntry};
use crate::vm::vm_core::VirtualMachine;
use crate::vm::vm_core::VirtualMachineError;
use crate::vm::vm_memory::memory_segments::MemorySegmentManager;
use num_bigint::BigInt;
use num_traits::FromPrimitive;
use std::collections::BTreeMap;

pub struct CairoRunner {
    program: Program,
    pub vm: VirtualMachine,
    _layout: String,
    pub segments: MemorySegmentManager,
    final_pc: Option<Relocatable>,
    program_base: Option<Relocatable>,
    execution_base: Option<Relocatable>,
    initial_ap: Option<Relocatable>,
    initial_fp: Option<Relocatable>,
    initial_pc: Option<Relocatable>,
    relocated_memory: Vec<Option<BigInt>>,
    relocated_trace: Vec<RelocatedTraceEntry>,
}

#[allow(dead_code)]
impl CairoRunner {
    pub fn new(program: &Program) -> CairoRunner {
        let builtin_ordered_list = vec![
            String::from("output"),
            String::from("pedersen"),
            String::from("range_check"),
            String::from("ecdsa"),
            String::from("bitwise"),
        ];
        assert!(
            is_subsequence(&program.builtins, &builtin_ordered_list),
            "Given builtins are not in appropiate order"
        );
        let mut builtin_runners = BTreeMap::<String, Box<dyn BuiltinRunner>>::new();
        for builtin_name in program.builtins.iter() {
            if builtin_name == "output" {
                builtin_runners.insert(
                    builtin_name.clone(),
                    Box::new(OutputBuiltinRunner::new(true)),
                );
            }

            if builtin_name == "range_check" {
                //Information for Buitin info taken from here https://github.com/starkware-libs/cairo-lang/blob/b614d1867c64f3fb2cf4a4879348cfcf87c3a5a7/src/starkware/cairo/lang/instances.py#L115
                builtin_runners.insert(
                    builtin_name.clone(),
                    Box::new(RangeCheckBuiltinRunner::new(true, bigint!(8), 8)),
                );
            }
        }
        //Initialize a vm, with empty values, will later be filled with actual data in initialize_vm
        CairoRunner {
            program: program.clone(),
            _layout: String::from("plain"),
            segments: MemorySegmentManager::new(),
            vm: VirtualMachine::new(program.prime.clone(), builtin_runners),
            final_pc: None,
            program_base: None,
            execution_base: None,
            initial_ap: None,
            initial_fp: None,
            initial_pc: None,
            relocated_memory: Vec::new(),
            relocated_trace: Vec::new(),
        }
    }
    ///Creates the necessary segments for the program, execution, and each builtin on the MemorySegmentManager and stores the first adress of each of this new segments as each owner's base
    pub fn initialize_segments(&mut self, program_base: Option<Relocatable>) {
        self.program_base = match program_base {
            Some(base) => Some(base),
            None => Some(self.segments.add(None)),
        };
        self.execution_base = Some(self.segments.add(None));
        for (_key, builtin_runner) in self.vm.builtin_runners.iter_mut() {
            builtin_runner.initialize_segments(&mut self.segments);
        }
    }

    fn initialize_state(&mut self, entrypoint: usize, stack: Vec<MaybeRelocatable>) {
        if let Some(prog_base) = self.program_base.clone() {
            let initial_pc = Relocatable {
                segment_index: prog_base.segment_index,
                offset: prog_base.offset + entrypoint,
            };
            self.initial_pc = Some(initial_pc);
            self.segments.load_data(
                &MaybeRelocatable::RelocatableValue(prog_base),
                self.program.data.clone(),
            );
            if let Some(exec_base) = &self.execution_base {
                self.segments.load_data(
                    &MaybeRelocatable::RelocatableValue(exec_base.clone()),
                    stack,
                );
            } else {
                panic!("Cant initialize state without an execution base");
            }
        } else {
            panic!("Cant initialize state without a program base");
        }
    }

    fn initialize_function_entrypoint(
        &mut self,
        entrypoint: usize,
        mut stack: Vec<MaybeRelocatable>,
        return_fp: MaybeRelocatable,
    ) -> Relocatable {
        let end = self.segments.add(None);
        stack.append(&mut vec![
            return_fp,
            MaybeRelocatable::RelocatableValue(end.clone()),
        ]);
        if let Some(base) = &self.execution_base {
            self.initial_fp = Some(Relocatable {
                segment_index: base.segment_index,
                offset: base.offset + stack.len(),
            });
            self.initial_ap = self.initial_fp.clone();
        } else {
            panic!("Cant initialize the function entrypoint without an execution base");
        }
        self.initialize_state(entrypoint, stack);
        self.final_pc = Some(end.clone());
        end
    }
    ///Initializes state for running a program from the main() entrypoint.
    ///If self.proof_mode == True, the execution starts from the start label rather then the main() function.
    ///Returns the value of the program counter after returning from main.
    pub fn initialize_main_entrypoint(&mut self) -> Relocatable {
        //self.execution_public_memory = Vec::new() -> Not used now
        let mut stack = Vec::new();
        for (_name, builtin_runner) in self.vm.builtin_runners.iter() {
            stack.append(&mut builtin_runner.initial_stack());
        }
        //Different process if proof_mode is enabled
        let return_fp = self.segments.add(None);
        if let Some(main) = &self.program.main {
            let main_clone = *main;
            self.initialize_function_entrypoint(
                main_clone,
                stack,
                MaybeRelocatable::RelocatableValue(return_fp),
            )
        } else {
            panic!("Missing main()")
        }
    }

    pub fn initialize_vm(&mut self) {
        //TODO hint_locals and static_locals
        self.vm.run_context.pc =
            MaybeRelocatable::RelocatableValue(self.initial_pc.clone().unwrap());
        self.vm.run_context.ap =
            MaybeRelocatable::RelocatableValue(self.initial_ap.clone().unwrap());
        self.vm.run_context.fp =
            MaybeRelocatable::RelocatableValue(self.initial_fp.clone().unwrap());
        self.vm.memory = self.segments.memory.clone();
        self.vm._program_base = Some(MaybeRelocatable::RelocatableValue(
            self.program_base.clone().unwrap(),
        ));
        self.vm.memory = self.segments.memory.clone();
        for (_key, builtin) in self.vm.builtin_runners.iter() {
            let vec = builtin.validate_existing_memory(
                &self.vm.memory.data[builtin.base().unwrap().segment_index],
            );
            if let Some(mut validated_addresses) = vec {
                self.vm.validated_addresses.append(&mut validated_addresses)
            }
        }
    }

    pub fn run_until_pc(&mut self, address: MaybeRelocatable) -> Result<(), VirtualMachineError> {
        while self.vm.run_context.pc != address {
            self.vm.step()?;
        }
        Ok(())
    }
    fn relocate_memory(&mut self) {
        assert!(
            self.relocated_memory.is_empty(),
            "Memory has been already relocated"
        );
        let relocation_table = self.segments.relocate_segments();
        self.relocated_memory.push(None);
        for (index, segment) in self.segments.memory.data.iter().enumerate() {
            assert_eq!(self.relocated_memory.len(), relocation_table[index]);
            for element in segment {
                if element != &None {
                    self.relocated_memory.push(Some(relocate_value(
                        element.clone().unwrap(),
                        relocation_table.clone(),
                    )));
                } else {
                    self.relocated_memory.push(None);
                }
            }
        }
    }

    fn relocate_trace(&mut self, relocation_table: Vec<usize>) {
        assert!(
            self.relocated_trace.is_empty(),
            "Trace has already been relocated"
        );
        for entry in self.vm.trace.iter() {
            self.relocated_trace.push(RelocatedTraceEntry {
                pc: relocate_trace_register(entry.pc.clone(), relocation_table.clone()),
                ap: relocate_trace_register(entry.ap.clone(), relocation_table.clone()),
                fp: relocate_trace_register(entry.fp.clone(), relocation_table.clone()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;

    use super::*;
    use crate::vm::trace::trace_entry::TraceEntry;
    use crate::{bigint64, bigint_str, relocatable};

    #[test]
    #[should_panic]
    fn create_cairo_runner_with_disordered_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check"), String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let _cairo_runner = CairoRunner::new(&program);
    }

    #[test]
    fn create_cairo_runner_with_ordered_but_missing_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output"), String::from("ecdsa")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        //We only check that the creation doesnt panic
        let _cairo_runner = CairoRunner::new(&program);
    }

    #[test]
    fn initialize_segments_with_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        let program_base = Some(Relocatable {
            segment_index: 5,
            offset: 9,
        });
        cairo_runner.segments.num_segments = 6;
        cairo_runner.initialize_segments(program_base);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: 5,
                offset: 9,
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: 6,
                offset: 0,
            })
        );

        assert_eq!(
            cairo_runner.vm.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: 7,
                offset: 0,
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 8);
    }

    #[test]
    fn initialize_segments_no_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        assert_eq!(
            cairo_runner.program_base,
            Some(Relocatable {
                segment_index: 0,
                offset: 0
            })
        );
        assert_eq!(
            cairo_runner.execution_base,
            Some(Relocatable {
                segment_index: 1,
                offset: 0
            })
        );

        assert_eq!(
            cairo_runner.vm.builtin_runners[&String::from("output")].base(),
            Some(Relocatable {
                segment_index: 2,
                offset: 0
            })
        );

        assert_eq!(cairo_runner.segments.num_segments, 3);
    }

    #[test]
    fn initialize_state_empty_data_and_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = Vec::new();
        cairo_runner.initialize_state(1, stack);
        assert_eq!(
            cairo_runner.initial_pc,
            Some(Relocatable {
                segment_index: 1,
                offset: 1
            })
        );
    }

    #[test]
    fn initialize_state_some_data_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::from(bigint!(4)),
                MaybeRelocatable::from(bigint!(6)),
            ],
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..2 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.program_base = Some(Relocatable {
            segment_index: 1,
            offset: 0,
        });
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = Vec::new();
        cairo_runner.initialize_state(1, stack);
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(
                    cairo_runner.program_base.unwrap()
                )),
            Some(&MaybeRelocatable::from(bigint!(4)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from(bigint!(6)))
        );
    }

    #[test]
    fn initialize_state_empty_data_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..3 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.program_base = Some(relocatable!(1, 0));
        cairo_runner.execution_base = Some(relocatable!(2, 0));
        let stack = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        cairo_runner.initialize_state(1, stack);
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::RelocatableValue(
                    cairo_runner.execution_base.unwrap()
                )),
            Some(&MaybeRelocatable::from(bigint!(4)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((2, 1))),
            Some(&MaybeRelocatable::from(bigint!(6)))
        );
    }

    #[test]
    #[should_panic]
    fn initialize_state_no_program_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..2 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.execution_base = Some(Relocatable {
            segment_index: 2,
            offset: 0,
        });
        let stack = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        cairo_runner.initialize_state(1, stack);
    }

    #[test]
    #[should_panic]
    fn initialize_state_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..2 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.program_base = Some(relocatable!(1, 0));
        let stack = vec![
            MaybeRelocatable::from(bigint!(4)),
            MaybeRelocatable::from(bigint!(6)),
        ];
        cairo_runner.initialize_state(1, stack);
    }

    #[test]
    fn initialize_function_entrypoint_empty_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..2 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = Vec::new();
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner.initialize_function_entrypoint(0, stack, return_fp);
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 2)));
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 0))),
            Some(&MaybeRelocatable::from(bigint!(9)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from((2, 0)))
        );
    }

    #[test]
    fn initialize_function_entrypoint_some_stack() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..2 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(1, 0));
        let stack = vec![MaybeRelocatable::from(bigint!(7))];
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner.initialize_function_entrypoint(1, stack, return_fp);
        assert_eq!(cairo_runner.initial_fp, cairo_runner.initial_ap);
        assert_eq!(cairo_runner.initial_fp, Some(relocatable!(1, 3)));
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 0))),
            Some(&MaybeRelocatable::from(bigint!(7)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from(bigint!(9)))
        );
        assert_eq!(
            cairo_runner
                .segments
                .memory
                .get(&MaybeRelocatable::from((1, 2))),
            Some(&MaybeRelocatable::from((2, 0)))
        );
    }

    #[test]
    #[should_panic]
    fn initialize_function_entrypoint_no_execution_base() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        let stack = vec![MaybeRelocatable::from(bigint!(7))];
        let return_fp = MaybeRelocatable::from(bigint!(9));
        cairo_runner.initialize_function_entrypoint(1, stack, return_fp);
    }

    #[test]
    #[should_panic]
    fn initialize_main_entrypoint_no_main() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_main_entrypoint();
    }

    #[test]
    fn initialize_main_entrypoint() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(1),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.execution_base = Some(relocatable!(0, 0));
        let return_pc = cairo_runner.initialize_main_entrypoint();
        assert_eq!(return_pc, relocatable!(1, 0));
    }

    #[test]
    fn initialize_vm_no_builtins() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(1),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.program_base = Some(relocatable!(0, 0));
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_vm();
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((0, 1))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 2))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((1, 2))
        );
        assert_eq!(
            cairo_runner.vm._program_base,
            Some(MaybeRelocatable::from((0, 0)))
        );
    }

    #[test]
    fn initialize_vm_with_range_check_valid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(1),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_segments(None);
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((2, 0)),
            &MaybeRelocatable::from(bigint!(23)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((2, 1)),
            &MaybeRelocatable::from(bigint!(233)),
        );
        cairo_runner.initialize_vm();
        assert_eq!(
            cairo_runner.vm.builtin_runners[&String::from("range_check")].base(),
            Some(relocatable!(2, 0))
        );
        assert!(cairo_runner
            .vm
            .validated_addresses
            .contains(&MaybeRelocatable::from((2, 0))));
        assert!(cairo_runner
            .vm
            .validated_addresses
            .contains(&MaybeRelocatable::from((2, 1))));
        assert_eq!(cairo_runner.vm.validated_addresses.len(), 2);
    }

    #[test]
    #[should_panic]
    fn initialize_vm_with_range_check_invalid() {
        //This test works with basic Program definition, will later be updated to use Program::new() when fully defined
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: Vec::new(),
            main: Some(1),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initial_pc = Some(relocatable!(0, 1));
        cairo_runner.initial_ap = Some(relocatable!(1, 2));
        cairo_runner.initial_fp = Some(relocatable!(1, 2));
        cairo_runner.initialize_segments(None);
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((2, 1)),
            &MaybeRelocatable::from(bigint!(23)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((2, 4)),
            &MaybeRelocatable::from(bigint!(-1)),
        );
        cairo_runner.initialize_vm();
    }

    //Integration tests for initialization phase

    #[test]
    /*Program used:
    func myfunc(a: felt) -> (r: felt):
        let b = a * 2
        return(b)
    end

    func main():
        let a = 1
        let b = myfunc(a)
        return()
    end

    main = 3
    data = [5207990763031199744, 2, 2345108766317314046, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020476, 2345108766317314046]
    */
    fn initialization_phase_no_builtins() {
        let program = Program {
            builtins: vec![],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(5207990763031199744).unwrap()),
                MaybeRelocatable::from(bigint!(2)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(3),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(3, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((0, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 2))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((1, 2))
        );
        //Memory
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5207990763031199744).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Some(&MaybeRelocatable::from(bigint!(2)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 2))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 4))),
            Some(&MaybeRelocatable::from(bigint!(1)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 5))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 6))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728,
                ],
            )))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 7))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Some(&MaybeRelocatable::from((2, 0)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from((3, 0)))
        );
    }

    #[test]
    /*Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        return()
    end

    main = 4
    data = [4612671182993129469, 5198983563776393216, 1, 2345108766317314046, 5191102247248822272, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020474, 2345108766317314046]
    */
    fn initialization_phase_output_builtin() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967290, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(4),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((0, 4))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((1, 3))
        );
        //Memory
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(4612671182993129469).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5198983563776393216).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 2))),
            Some(&MaybeRelocatable::from(bigint!(1)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 4))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5191102247248822272).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 5))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 6))),
            Some(&MaybeRelocatable::from(bigint!(1)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 7))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 8))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967290, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728
                ]
            )))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 9))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Some(&MaybeRelocatable::from((2, 0)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from((3, 0)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 2))),
            Some(&MaybeRelocatable::from((4, 0)))
        );
    }

    #[test]
    /*Program used:
    %builtins range_check

    func check_range{range_check_ptr}(num):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return()
    end

    func main{range_check_ptr}():
        check_range(7)
        return()
    end

    main = 8
    data = [4612671182993129469, 5189976364521848832, 18446744073709551615, 5199546496550207487, 4612389712311386111, 5198983563776393216, 2, 2345108766317314046, 5191102247248822272, 5189976364521848832, 7, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020470, 2345108766317314046]
    */
    fn initialization_phase_range_check_builtin() {
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: bigint!(17),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i128(18446744073709551615).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5199546496550207487).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(4612389712311386111).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(2)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(7)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(8),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();

        assert_eq!(cairo_runner.program_base, Some(relocatable!(0, 0)));
        assert_eq!(cairo_runner.execution_base, Some(relocatable!(1, 0)));
        assert_eq!(cairo_runner.final_pc, Some(relocatable!(4, 0)));

        //RunContext check
        //Registers
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((0, 8))
        );
        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 3))
        );
        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((1, 3))
        );
        //Memory
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 0))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(4612671182993129469).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 1))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 2))),
            Some(&MaybeRelocatable::Int(
                BigInt::from_i128(18446744073709551615).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 3))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5199546496550207487).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 4))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(4612389712311386111).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 5))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5198983563776393216).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 6))),
            Some(&MaybeRelocatable::from(bigint!(2)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 7))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 8))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5191102247248822272).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 9))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(5189976364521848832).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 10))),
            Some(&MaybeRelocatable::from(bigint!(7)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 11))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(1226245742482522112).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 12))),
            Some(&MaybeRelocatable::Int(BigInt::new(
                Sign::Plus,
                vec![
                    4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                    134217728
                ]
            )))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((0, 13))),
            Some(&MaybeRelocatable::from(
                BigInt::from_i64(2345108766317314046).unwrap()
            ))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 0))),
            Some(&MaybeRelocatable::from((2, 0)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 1))),
            Some(&MaybeRelocatable::from((3, 0)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((1, 2))),
            Some(&MaybeRelocatable::from((4, 0)))
        );
    }

    //Integration tests for initialization + execution phase

    #[test]
    /*Program used:
    func myfunc(a: felt) -> (r: felt):
        let b = a * 2
        return(b)
    end

    func main():
        let a = 1
        let b = myfunc(a)
        return()
    end

    main = 3
    data = [5207990763031199744, 2, 2345108766317314046, 5189976364521848832, 1, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020476, 2345108766317314046]
    */
    fn initialize_and_run_function_call() {
        //Initialization Phase
        let program = Program {
            builtins: vec![],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(5207990763031199744).unwrap()),
                MaybeRelocatable::from(bigint!(2)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967292, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(3),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        assert_eq!(end, relocatable!(3, 0));
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((3, 0))
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 6))
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((2, 0))
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 5);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 3)),
                ap: MaybeRelocatable::from((1, 2)),
                fp: MaybeRelocatable::from((1, 2)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 5)),
                ap: MaybeRelocatable::from((1, 3)),
                fp: MaybeRelocatable::from((1, 2)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 0)),
                ap: MaybeRelocatable::from((1, 5)),
                fp: MaybeRelocatable::from((1, 5)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 2)),
                ap: MaybeRelocatable::from((1, 6)),
                fp: MaybeRelocatable::from((1, 5)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 7)),
                ap: MaybeRelocatable::from((1, 6)),
                fp: MaybeRelocatable::from((1, 2)),
            }
        );
    }

    #[test]
    /*Program used:
    %builtins range_check

    func check_range{range_check_ptr}(num):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return()
    end

    func main{range_check_ptr}():
        check_range(7)
        return()
    end

    main = 8
    data = [4612671182993129469, 5189976364521848832, 18446744073709551615, 5199546496550207487, 4612389712311386111, 5198983563776393216, 2, 2345108766317314046, 5191102247248822272, 5189976364521848832, 7, 1226245742482522112, 3618502788666131213697322783095070105623107215331596699973092056135872020470, 2345108766317314046]
    */
    fn initialize_and_run_range_check_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i128(18446744073709551615).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5199546496550207487).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(4612389712311386111).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(2)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(7)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::Int(BigInt::new(
                    Sign::Plus,
                    vec![
                        4294967286, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 16,
                        134217728,
                    ],
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(8),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((4, 0))
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 10))
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((3, 0))
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 10);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 8)),
                ap: MaybeRelocatable::from((1, 3)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 9)),
                ap: MaybeRelocatable::from((1, 4)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 11)),
                ap: MaybeRelocatable::from((1, 5)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 0)),
                ap: MaybeRelocatable::from((1, 7)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 1)),
                ap: MaybeRelocatable::from((1, 7)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[5],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 3)),
                ap: MaybeRelocatable::from((1, 8)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[6],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 4)),
                ap: MaybeRelocatable::from((1, 9)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[7],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 5)),
                ap: MaybeRelocatable::from((1, 9)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[8],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 7)),
                ap: MaybeRelocatable::from((1, 10)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[9],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 13)),
                ap: MaybeRelocatable::from((1, 10)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        //Check the range_check builtin segment
        assert_eq!(
            cairo_runner.vm.builtin_runners["range_check"].base(),
            Some(relocatable!(2, 0))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Some(&MaybeRelocatable::from(bigint!(7)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 1))),
            Some(&MaybeRelocatable::from(bigint!(2).pow(64) - bigint!(8)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 2))),
            None
        );
    }

    #[test]
    /*Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        let b = 17 * a
        serialize_word(b)
        return()
    end

    main = 4
    data = [
    4612671182993129469,
    5198983563776393216,
    1,
    2345108766317314046,
    5191102247248822272,
    5189976364521848832,
    1,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020474,
    5189976364521848832,
    17,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020470,
    2345108766317314046
    ]
    */
    fn initialize_and_run_output_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474"
                )),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(17)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470"
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(4),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((4, 0))
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 12))
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((3, 0))
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 12);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 4)),
                ap: MaybeRelocatable::from((1, 3)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 5)),
                ap: MaybeRelocatable::from((1, 4)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 7)),
                ap: MaybeRelocatable::from((1, 5)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 0)),
                ap: MaybeRelocatable::from((1, 7)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 1)),
                ap: MaybeRelocatable::from((1, 7)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[5],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 3)),
                ap: MaybeRelocatable::from((1, 8)),
                fp: MaybeRelocatable::from((1, 7)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[6],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 9)),
                ap: MaybeRelocatable::from((1, 8)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[7],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 11)),
                ap: MaybeRelocatable::from((1, 9)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[8],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 0)),
                ap: MaybeRelocatable::from((1, 11)),
                fp: MaybeRelocatable::from((1, 11)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[9],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 1)),
                ap: MaybeRelocatable::from((1, 11)),
                fp: MaybeRelocatable::from((1, 11)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[10],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 3)),
                ap: MaybeRelocatable::from((1, 12)),
                fp: MaybeRelocatable::from((1, 11)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[11],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 13)),
                ap: MaybeRelocatable::from((1, 12)),
                fp: MaybeRelocatable::from((1, 3)),
            }
        );
        //Check that the output to be printed is correct
        assert_eq!(
            cairo_runner.vm.builtin_runners["output"].base(),
            Some(relocatable!(2, 0))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 0))),
            Some(&MaybeRelocatable::from(bigint!(1)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 1))),
            Some(&MaybeRelocatable::from(bigint!(17)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 2))),
            None
        );
    }

    #[test]
    /*Program used:
    %builtins output range_check

    from starkware.cairo.common.serialize import serialize_word

    func check_range{range_check_ptr}(num) -> (num : felt):

        # Check that 0 <= num < 2**64.
        [range_check_ptr] = num
        assert [range_check_ptr + 1] = 2 ** 64 - 1 - num
        let range_check_ptr = range_check_ptr + 2
        return(num)
    end

    func main{output_ptr: felt*, range_check_ptr: felt}():
        let num: felt = check_range(7)
        serialize_word(num)
        return()
    end

    main = 13
    data = [
    4612671182993129469,
    5198983563776393216,
    1,
    2345108766317314046,
    4612671182993129469,
    5189976364521848832,
    18446744073709551615,
    5199546496550207487,
    4612389712311386111,
    5198983563776393216,
    2,
    5191102247248822272,
    2345108766317314046,
    5191102247248822272,
    5189976364521848832,
    7,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020469,
    5191102242953854976,
    5193354051357474816,
    1226245742482522112,
    3618502788666131213697322783095070105623107215331596699973092056135872020461,
    5193354029882638336,
    2345108766317314046]
    */
    fn initialize_and_run_output_range_check_builtin() {
        //Initialization Phase
        let program = Program {
            builtins: vec![String::from("output"), String::from("range_check")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::Int(BigInt::from_i128(18446744073709551615).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5199546496550207487).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(4612389712311386111).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(2)),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(7)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020469"
                )),
                MaybeRelocatable::from(BigInt::from_i64(5191102242953854976).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5193354051357474816).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020461"
                )),
                MaybeRelocatable::from(BigInt::from_i64(5193354029882638336).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(13),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();
        //Execution Phase
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        //Check final values against Python VM
        //Check final register values
        assert_eq!(
            cairo_runner.vm.run_context.pc,
            MaybeRelocatable::from((5, 0))
        );

        assert_eq!(
            cairo_runner.vm.run_context.ap,
            MaybeRelocatable::from((1, 18))
        );

        assert_eq!(
            cairo_runner.vm.run_context.fp,
            MaybeRelocatable::from((4, 0))
        );

        //Check each TraceEntry in trace
        assert_eq!(cairo_runner.vm.trace.len(), 18);
        assert_eq!(
            cairo_runner.vm.trace[0],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 13)),
                ap: MaybeRelocatable::from((1, 4)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[1],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 14)),
                ap: MaybeRelocatable::from((1, 5)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[2],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 16)),
                ap: MaybeRelocatable::from((1, 6)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[3],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 4)),
                ap: MaybeRelocatable::from((1, 8)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[4],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 5)),
                ap: MaybeRelocatable::from((1, 8)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[5],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 7)),
                ap: MaybeRelocatable::from((1, 9)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[6],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 8)),
                ap: MaybeRelocatable::from((1, 10)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[7],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 9)),
                ap: MaybeRelocatable::from((1, 10)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[8],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 11)),
                ap: MaybeRelocatable::from((1, 11)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[9],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 12)),
                ap: MaybeRelocatable::from((1, 12)),
                fp: MaybeRelocatable::from((1, 8)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[10],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 18)),
                ap: MaybeRelocatable::from((1, 12)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[11],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 19)),
                ap: MaybeRelocatable::from((1, 13)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[12],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 20)),
                ap: MaybeRelocatable::from((1, 14)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[13],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 0)),
                ap: MaybeRelocatable::from((1, 16)),
                fp: MaybeRelocatable::from((1, 16)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[14],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 1)),
                ap: MaybeRelocatable::from((1, 16)),
                fp: MaybeRelocatable::from((1, 16)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[15],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 3)),
                ap: MaybeRelocatable::from((1, 17)),
                fp: MaybeRelocatable::from((1, 16)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[16],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 22)),
                ap: MaybeRelocatable::from((1, 17)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        assert_eq!(
            cairo_runner.vm.trace[17],
            TraceEntry {
                pc: MaybeRelocatable::from((0, 23)),
                ap: MaybeRelocatable::from((1, 18)),
                fp: MaybeRelocatable::from((1, 4)),
            }
        );
        //Check the range_check builtin segment
        assert!(cairo_runner
            .vm
            .builtin_runners
            .contains_key(&String::from("range_check")));
        assert_eq!(
            relocatable!(3, 0),
            cairo_runner.vm.builtin_runners["range_check"]
                .base()
                .unwrap(),
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((3, 0))),
            Some(&MaybeRelocatable::from(bigint!(7)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((3, 1))),
            Some(&MaybeRelocatable::from(bigint!(2).pow(64) - bigint!(8)))
        );
        assert_eq!(
            cairo_runner.vm.memory.get(&MaybeRelocatable::from((2, 2))),
            None
        );

        //Check the output segment
        assert!(cairo_runner
            .vm
            .builtin_runners
            .contains_key(&String::from("output")));
        assert_eq!(
            relocatable!(2, 0),
            cairo_runner.vm.builtin_runners["output"].base().unwrap(),
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&(MaybeRelocatable::from((2, 0)))),
            Some(&MaybeRelocatable::from(bigint!(7)))
        );
        assert_eq!(
            cairo_runner
                .vm
                .memory
                .get(&(MaybeRelocatable::from((2, 1)))),
            None
        );
    }

    #[test]
    /*Memory from this test is taken from a cairo program execution
    Program used:
        func main():
        let a = 1
        [ap + 3] = 5
        return()

    end
    Final Memory:
    {RelocatableValue(segment_index=0, offset=0): 4613515612218425347,
     RelocatableValue(segment_index=0, offset=1): 5,
     RelocatableValue(segment_index=0, offset=2): 2345108766317314046,
     RelocatableValue(segment_index=1, offset=0): RelocatableValue(segment_index=2, offset=0),
     RelocatableValue(segment_index=1, offset=1): RelocatableValue(segment_index=3, offset=0),
     RelocatableValue(segment_index=1, offset=5): 5}
    Relocated Memory:
        1     4613515612218425347
        2     5
        3     2345108766317314046
        4     10
        5     10
        ⋮
        9     5
    */
    fn relocate_memory_with_gap() {
        let program = Program {
            builtins: Vec::new(),
            prime: bigint!(17),
            data: Vec::new(),
            main: None,
        };
        let mut cairo_runner = CairoRunner::new(&program);
        for _ in 0..4 {
            cairo_runner.segments.add(None);
        }
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((0, 0)),
            &MaybeRelocatable::from(bigint64!(4613515612218425347)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((0, 1)),
            &MaybeRelocatable::from(bigint!(5)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((0, 2)),
            &MaybeRelocatable::from(bigint64!(2345108766317314046)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((1, 0)),
            &MaybeRelocatable::from((2, 0)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((1, 1)),
            &MaybeRelocatable::from((3, 0)),
        );
        cairo_runner.segments.memory.insert(
            &MaybeRelocatable::from((1, 5)),
            &MaybeRelocatable::from(bigint!(5)),
        );
        cairo_runner.segments.compute_effective_sizes();
        cairo_runner.relocate_memory();
        assert_eq!(cairo_runner.relocated_memory[0], None);
        assert_eq!(
            cairo_runner.relocated_memory[1],
            Some(bigint64!(4613515612218425347))
        );
        assert_eq!(cairo_runner.relocated_memory[2], Some(bigint!(5)));
        assert_eq!(
            cairo_runner.relocated_memory[3],
            Some(bigint64!(2345108766317314046))
        );
        assert_eq!(cairo_runner.relocated_memory[4], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[5], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[6], None);
        assert_eq!(cairo_runner.relocated_memory[7], None);
        assert_eq!(cairo_runner.relocated_memory[8], None);
        assert_eq!(cairo_runner.relocated_memory[9], Some(bigint!(5)));
    }

    /* Program used:
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{output_ptr: felt*}():
        let a = 1
        serialize_word(a)
        let b = 17 * a
        serialize_word(b)
        return()
    end
    Relocated Memory:
        1     4612671182993129469
        2     5198983563776393216
        3     1
        4     2345108766317314046
        5     5191102247248822272
        6     5189976364521848832
        7     1
        8     1226245742482522112
        9     -7
        10    5189976364521848832
        11    17
        12    1226245742482522112
        13    -11
        14    2345108766317314046
        15    27
        16    29
        17    29
        18    27
        19    1
        20    18
        21    10
        22    28
        23    17
        24    18
        25    14
        26    29
        27    1
        28    17
     */

    #[test]
    fn initialize_run_and_relocate_output_builtin() {
        let program = Program {
            builtins: vec![String::from("output")],
            prime: BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            data: vec![
                MaybeRelocatable::from(BigInt::from_i64(4612671182993129469).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5198983563776393216).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5191102247248822272).unwrap()),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(1)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020474"
                )),
                MaybeRelocatable::from(BigInt::from_i64(5189976364521848832).unwrap()),
                MaybeRelocatable::from(bigint!(17)),
                MaybeRelocatable::from(BigInt::from_i64(1226245742482522112).unwrap()),
                MaybeRelocatable::from(bigint_str!(
                    b"3618502788666131213697322783095070105623107215331596699973092056135872020470"
                )),
                MaybeRelocatable::from(BigInt::from_i64(2345108766317314046).unwrap()),
            ],
            main: Some(4),
        };
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner.initialize_main_entrypoint();
        cairo_runner.initialize_vm();
        assert_eq!(
            cairo_runner.run_until_pc(MaybeRelocatable::RelocatableValue(end)),
            Ok(())
        );
        cairo_runner.segments.memory = cairo_runner.vm.memory.clone();
        cairo_runner.segments.compute_effective_sizes();
        cairo_runner.relocate_memory();
        assert_eq!(cairo_runner.relocated_memory[0], None);
        assert_eq!(
            cairo_runner.relocated_memory[1],
            Some(bigint64!(4612671182993129469))
        );
        assert_eq!(
            cairo_runner.relocated_memory[2],
            Some(bigint64!(5198983563776393216))
        );
        assert_eq!(cairo_runner.relocated_memory[3], Some(bigint!(1)));
        assert_eq!(
            cairo_runner.relocated_memory[4],
            Some(bigint64!(2345108766317314046))
        );
        assert_eq!(
            cairo_runner.relocated_memory[5],
            Some(bigint64!(5191102247248822272))
        );
        assert_eq!(
            cairo_runner.relocated_memory[6],
            Some(bigint64!(5189976364521848832))
        );
        assert_eq!(cairo_runner.relocated_memory[7], Some(bigint!(1)));
        assert_eq!(
            cairo_runner.relocated_memory[8],
            Some(bigint64!(1226245742482522112))
        );
        assert_eq!(
            cairo_runner.relocated_memory[9],
            Some(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020474"
            ))
        );
        assert_eq!(
            cairo_runner.relocated_memory[10],
            Some(bigint64!(5189976364521848832))
        );
        assert_eq!(cairo_runner.relocated_memory[11], Some(bigint!(17)));
        assert_eq!(
            cairo_runner.relocated_memory[12],
            Some(bigint64!(1226245742482522112))
        );
        assert_eq!(
            cairo_runner.relocated_memory[13],
            Some(bigint_str!(
                b"3618502788666131213697322783095070105623107215331596699973092056135872020470"
            ))
        );
        assert_eq!(
            cairo_runner.relocated_memory[14],
            Some(bigint64!(2345108766317314046))
        );
        assert_eq!(cairo_runner.relocated_memory[15], Some(bigint!(27)));
        assert_eq!(cairo_runner.relocated_memory[16], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[17], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[18], Some(bigint!(27)));
        assert_eq!(cairo_runner.relocated_memory[19], Some(bigint!(1)));
        assert_eq!(cairo_runner.relocated_memory[20], Some(bigint!(18)));
        assert_eq!(cairo_runner.relocated_memory[21], Some(bigint!(10)));
        assert_eq!(cairo_runner.relocated_memory[22], Some(bigint!(28)));
        assert_eq!(cairo_runner.relocated_memory[23], Some(bigint!(17)));
        assert_eq!(cairo_runner.relocated_memory[24], Some(bigint!(18)));
        assert_eq!(cairo_runner.relocated_memory[25], Some(bigint!(14)));
        assert_eq!(cairo_runner.relocated_memory[26], Some(bigint!(29)));
        assert_eq!(cairo_runner.relocated_memory[27], Some(bigint!(1)));
        assert_eq!(cairo_runner.relocated_memory[28], Some(bigint!(17)));
    }
}
