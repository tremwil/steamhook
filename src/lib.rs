#![allow(dead_code)]

#![feature(abi_thiscall)]
#![feature(associated_type_defaults)]
#![feature(fn_traits, unboxed_closures)]
#![feature(tuple_trait)]
#![feature(let_chains)]
#![feature(naked_functions)]
#![feature(downcast_unchecked)]
#![feature(associated_type_bounds)]

pub mod singleton;
pub mod dbghelp;
pub mod memory_utils;
pub mod vtable_scan;
pub mod iced_extensions;
pub mod code_analysis;
pub mod vtable_hook_types;
pub mod vtable_hook;
pub mod client_analysis;
pub mod server_analysis;
pub mod steamhook;

pub use crate::steamhook::*;
pub use vtable_hook::*;