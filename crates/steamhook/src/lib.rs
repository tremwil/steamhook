#![feature(abi_thiscall)]
#![feature(associated_type_defaults)]
#![feature(fn_traits, unboxed_closures)]
#![feature(tuple_trait)]
#![feature(let_chains)]
#![feature(naked_functions)]
#![feature(downcast_unchecked)]
#![feature(core_intrinsics)]
#![feature(associated_type_bounds)]

mod singleton;
mod memory_utils;
mod dbghelp;
mod vtable_scan;
mod iced_extensions;
mod code_analysis;
mod vtable_hook_types;
mod vtable_hook;