use std::{collections::HashMap, io::{Cursor, Result, Write}, ptr::NonNull, sync::{*, atomic::Ordering::*}, ffi::c_void};
use once_cell::sync::Lazy;
use pelite::pe::{PeView, Pe};
use windows::Win32::System::Memory::{HeapCreate, HeapAlloc, HeapHandle, HEAP_CREATE_ENABLE_EXECUTE, VirtualProtect, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, HEAP_FLAGS};
use byteorder::*;
use iced_x86::*;

use crate::singleton::*;
pub use crate::vtable_hook_types::*;

#[derive(Default)]
pub struct VtableHookMan {
    hooks: HashMap<*mut *const (), NonNull<VtableHook>>,
    rwe_heap_handle: HeapHandle
}

unsafe impl Send for VtableHookMan {}
unsafe impl Sync for VtableHookMan {}

/// Generates a thunk function in a RWE heap which will invoque the provided `rust_thunk`
/// with the `dummy_call` return value being replaced by `hook_ptr`.
/// # Safety 
/// - `rwe_heap` must be a valid heap handle to RWE memory obtained from [`HeapCreate`]
/// - `rust_thunk` must be a pointer returned by [`VtableHookArgs::thiscall_thunk`]
/// - `hook_ptr` must be a pointer to a leaked (static lifetime) [`VtableHook`] structure 
unsafe fn create_asm_thunk(rwe_heap: HeapHandle, rust_thunk: *const (), hook_ptr: *const VtableHook) -> *const () {
    let pe = PeView::new();
    let text = pe
        .section_headers()
        .iter()
        .find(|sec| &sec.Name == b".text\0\0\0")
        .expect("Failed to find .text section of current module");      

    const MAX_PROLOGUE_LENGTH: usize = 0x400;

    let start = rust_thunk as u64;
    let end = pe.rva_to_va(text.virtual_range().end).unwrap() as usize;
    let code_sz = std::cmp::min(end - rust_thunk as usize, MAX_PROLOGUE_LENGTH);
    let code = std::slice::from_raw_parts(rust_thunk as *const u8, code_sz);

    let dummy_call_addr = dummy_call as *const () as u64;
    let mut decoder = Decoder::with_ip(std::mem::size_of::<usize>() as u32 * 8, code, start, DecoderOptions::NONE);
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_call_near() && instr.near_branch_target() == dummy_call_addr {
            #[cfg(target_arch = "x86")]
            const TRAMPOLINE_SIZE: usize = 10;
            #[cfg(target_arch = "x86_64")]
            const TRAMPOLINE_SIZE: usize = 23;
            let jmp_target = instr.next_ip();
            let prologue = std::slice::from_raw_parts(rust_thunk as *const u8, (instr.ip() - start) as usize);

            let thunk_size = TRAMPOLINE_SIZE + prologue.len() as usize;
            let asm_thunk = NonNull::new(HeapAlloc(rwe_heap, HEAP_FLAGS::default(), thunk_size) as *mut ())
                .expect("Failed to allocate executable memory for vtable hook thunk").as_ptr();

            let mut thunk_writer = Cursor::new(std::slice::from_raw_parts_mut(asm_thunk as *mut u8, thunk_size));

            // Any instruction in the function prologue should be able to be relocated via simple copying 
            thunk_writer.write(prologue).unwrap();

            #[cfg(target_arch = "x86")] {
                // mov eax, ptr to hook data
               thunk_writer.write_u8(0xB8).unwrap();
               thunk_writer.write_u32::<LE>(hook_ptr as u32).unwrap();

               let cpos = asm_thunk as u32 + thunk_writer.position() as u32;
               let offset = (jmp_target as u32).overflowing_sub(cpos + 5).0;
               // jmp offset
               thunk_writer.write_u8(0xe9).unwrap();
               thunk_writer.write_u32::<LE>(offset).unwrap();
            }
            #[cfg(target_arch = "x86_64")] {
                // movabs rax, ptr to hook data
                thunk_writer.write_u16::<BE>(0x48B8).unwrap();
                thunk_writer.write_u64::<LE>(hook_ptr as u64).unwrap();
                // movabs r11, jmp_target
                thunk_writer.write_u16::<BE>(0x49BB).unwrap();
                thunk_writer.write_u64::<LE>(jmp_target).unwrap();
                // jmp r11
                thunk_writer.write(&[0x41, 0xff, 0xe3]).unwrap();
            }

            return asm_thunk;
        }
    }
    panic!("Failed to find dummy_call call in rust thunk");
}

impl VtableHookMan {
    pub unsafe fn install_hook<A: VtableHookArgs>(&mut self, vtable: *mut *const (), i_fun: isize, hook: impl VtableHookCb<A>) -> HookHandle {
        
        let thiscall_thunk = hook.thiscall_thunk_ref();
        let mut b : Box<VtableHook> = Box::new(VtableHook::new(vtable, i_fun, hook));

        #[cfg(target_arch = "x86")]
        const THUNK_SIZE: usize = 10;
        #[cfg(target_arch = "x86_64")]
        const THUNK_SIZE: usize = 23;

        b.asm_thunk = create_asm_thunk(self.rwe_heap_handle, thiscall_thunk, b.as_ref() as *const VtableHook);
        let ptr_to_fun = vtable.offset(i_fun);

        if let Some(last) = self.hooks.get_mut(&ptr_to_fun) {
            b.prev.store(last.as_ptr(), Relaxed);
            b.original = last.as_ref().original;

            let hook_data = Box::into_raw(b);
            last.as_mut().next.store(hook_data, Relaxed);

            *last = NonNull::new_unchecked(hook_data);
            HookHandle { hook_data }
        }
        else {
            b.original = *ptr_to_fun;
            let hook_data = Box::into_raw(b);
            self.hooks.insert(ptr_to_fun, NonNull::new_unchecked(hook_data));

            let mut oldprotect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(ptr_to_fun as *const c_void, std::mem::size_of::<usize>(), PAGE_READWRITE, &mut oldprotect).as_bool() {
                panic!("Failed to change memory protections when installing virtual function hook");
            }
            *ptr_to_fun = (*hook_data).asm_thunk;
            VirtualProtect(ptr_to_fun as *const c_void, std::mem::size_of::<usize>(), oldprotect, &mut oldprotect);

            HookHandle { hook_data }
        }
    }
    
    /// Safety guarantees: handle is a valid [HookHandle] returned by [VtableHookMan].install_hook.
    unsafe fn uninstall_hook_ref(&mut self, handle: &HookHandle) {
        let h : &VtableHook = &*handle.hook_data;
        let ptr_to_fun = h.vtable.offset(h.i_fun);

        let hprev = h.prev.load(Relaxed);
        let hnext = h.next.load(Relaxed);

        // Removing the first hook in the chain, must edit the vtable
        if hprev.is_null() {
            let next_thunk = if hnext.is_null() {
                h.original 
            } else {
                (*hnext).asm_thunk
            };

            let mut oldprotect: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
            if !VirtualProtect(ptr_to_fun as *const c_void, std::mem::size_of::<usize>(), PAGE_READWRITE, &mut oldprotect).as_bool() {
                panic!("Failed to change memory protections when uninstalling virtual function hook");
            }
            *ptr_to_fun = next_thunk;
            VirtualProtect(ptr_to_fun as *const c_void, std::mem::size_of::<usize>(), oldprotect, &mut oldprotect);
        }
        else {
            (*hprev).next.store(hnext, Relaxed);
        }
        // Removing hook in the chain, must update tail in hashmap
        if hnext.is_null() {
            if hprev.is_null() {
                self.hooks.remove(&ptr_to_fun);
            }
            else {
                self.hooks.insert(ptr_to_fun, NonNull::new(hprev).unwrap());
            }
        }
        else {
            (*hnext).prev.store(hprev, Relaxed);
        }
    }

    /// Safety guarantees: handle is a valid [HookHandle] returned by [VtableHookMan].install_hook.
    pub unsafe fn uninstall_hook(&mut self, handle: HookHandle) {
        self.uninstall_hook_ref(&handle);
    }

    /// Return the pointer to the original virtual function given its vtable and index.
    pub unsafe fn get_original(&self, vtable: *mut *const (), i_fun: isize) -> *const () {
        let ptr_to_fun = vtable.offset(i_fun);
        self.hooks.get(&ptr_to_fun).and_then(|h| Some(h.as_ref().original)).unwrap_or(*ptr_to_fun)
    }
}

impl RwSingleton for VtableHookMan {
    fn get_or_create() -> &'static std::sync::RwLock<Self> {
        static INSTANCE : Lazy<RwLock<VtableHookMan>> = Lazy::new(|| RwLock::new(VtableHookMan {
            hooks: HashMap::new(),
            rwe_heap_handle: unsafe {
                HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1 << 20, 0).expect("Creation of executable heap for vtable hook thunks failed")
            }
        }));
        &INSTANCE
    }
}

pub struct HookHandle {
    hook_data: *mut VtableHook
}

impl Drop for HookHandle {
    fn drop(&mut self) {
        unsafe { VtableHookMan::instance_mut().uninstall_hook_ref(self); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test with different parameter sizes and a return type wider than the register size
    #[cfg(target_arch = "x86")]
    type Fun = extern "thiscall" fn(*mut (), f64, u16, u32, [u8; 32]) -> u128;
    #[cfg(target_arch = "x86")]
    extern "thiscall" fn test_fun(instance: *mut (), w: f64, x: u16, y: u32, z: [u8; 32]) -> u128 {
        let z_sum : u128 = z.iter().map(|&x| x as u128).sum();
        (x as u128 + y as u128 + z_sum) * w.round() as u128
    }
    #[cfg(target_arch = "x86_64")]
    type Fun = extern "fastcall" fn(*mut (), f64, u16, u32, [u8; 32]) -> u128;
    #[cfg(target_arch = "x86_64")]
    extern "fastcall" fn test_fun(instance: *mut (), w: f64, x: u16, y: u32, z: [u8; 32]) -> u128 {
        let z_sum : u128 = z.iter().map(|&x| x as u128).sum();
        (x as u128 + y as u128 + z_sum) * w.round() as u128
    }

    // Simple struct to emulate a one function vtable and store data relvant to the tests
    struct TestData {
        fun_box: Box<Fun>,
        vmt: *mut *const (),
        arr: [u8; 32]
    }
    impl TestData {
        fn new() -> Self {
            let mut b : Box<Fun> = Box::new(test_fun);
            let vmt = b.as_mut() as *mut Fun as *mut *const ();
            TestData { fun_box: b, vmt, arr: [0u8; 32] }
        }
        fn fun(&self) -> Fun {
            self.fun_box.as_ref().clone()
        }
    }

    #[test]
    fn simple_replacement_hook() {
        let mut data = TestData::new();
        data.arr[3] = 2;
        let instance = 0xDEADBEEF as *mut ();

        assert_eq!(data.fun()(instance, 1.0, 2, 3, data.arr.clone()), 7u128);
        
        let handle = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> u128 {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            w.round() as u128 
        }) };
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 2u128);
        
        std::mem::drop(handle);
        
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 14u128);
    }

    
    #[test]
    fn simple_call_original_hook() {
        let mut data = TestData::new();
        data.arr[5] = 2;
        let instance = 0xDEADBEEF as *mut ();

        assert_eq!(data.fun()(instance, 1.3, 2, 3, data.arr.clone()), 7u128);
        
        let handle = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> u128 {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            w.round() as u128 + ctx.call_orig((w, x, y, z.clone())) + ctx.call_next((w, x, y, z.clone()))
        }) };
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 30u128);
        
        std::mem::drop(handle);
        
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 14u128);
    }

    #[test]
    fn two_hooks() {
        let mut data = TestData::new();
        data.arr[5] = 2;
        let instance = 0xDEADBEEF as *mut ();

        assert_eq!(data.fun()(instance, 1.3, 2, 3, data.arr.clone()), 7u128);
        
        let handle1 = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> u128 {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            w.round() as u128 + ctx.call_orig((w, x, y, z.clone())) + ctx.call_next((w, 0u16, y, z.clone()))
        }) };
        assert_eq!(data.fun()(instance, 1.0, 2, 3, data.arr.clone()), 13u128);

        let handle2 = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> u128 {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            10 + ctx.call_next((w, x, y, z.clone()))
        }) };
        assert_eq!(data.fun()(instance, 1.0, 2, 3, data.arr.clone()), 23u128);
        
        std::mem::drop(handle1);
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 24u128);

        std::mem::drop(handle2);
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 14u128);
    }

    #[test]
    fn filter() {
        let mut data = TestData::new();
        data.arr[5] = 2;
        let instance = 0xDEADBEEF as *mut ();

        assert_eq!(data.fun()(instance, 1.3, 2, 3, data.arr.clone()), 7u128);

        let cl = move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> u128 {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            10 + unsafe { ctx.call_next((w, x, y, z.clone())) }
        }.with_filter(|(_, w, _, _, _) : (_, f64, _, _, _)| w == 1.0);

        let handle = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, cl) };
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 14u128);
        assert_eq!(data.fun()(instance, 1.0, 2, 3, data.arr.clone()), 17u128);
        
        std::mem::drop(handle);
        assert_eq!(data.fun()(instance, 2.0, 2, 3, data.arr.clone()), 14u128);
    }

    #[test]
    fn option() {
        let mut data = TestData::new();
        data.arr[5] = 2;
        let instance = 0xDEADBEEF as *mut ();

        assert_eq!(data.fun()(instance, 1.3, 2, 5, data.arr.clone()), 9u128);

        let cl = move |ctx: VtableHookCtx<u128>, w: f64, x: u16, y: u32, z: [u8; 32]| -> Option<u128> {
            assert_eq!(ctx.thisptr(), instance, "thisptr mismatch");
            Some(*z.get(y as usize)? as u128 + unsafe { ctx.call_next((w, x, y, z.clone())) })
        }.unwrap_or_next();
        
        let handle = unsafe { VtableHookMan::instance_mut().install_hook(data.vmt, 0, cl) };
        assert_eq!(data.fun()(instance, 1.0, 2, 32, data.arr.clone()), 36u128);
        assert_eq!(data.fun()(instance, 1.0, 2, 5, data.arr.clone()), 11u128);
        
        std::mem::drop(handle);
        assert_eq!(data.fun()(instance, 1.0, 2, 5, data.arr.clone()), 9u128);
    }
}