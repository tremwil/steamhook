use std::{ops::{Range, Deref}, arch::asm, sync::{RwLockReadGuard, RwLockWriteGuard, RwLock}, mem::{MaybeUninit, align_of}, io::Write, ptr::NonNull};
use once_cell::sync::OnceCell;
use pelite::pe::{PeView, Va, Pe};
use crate::vtable_scan::ModuleId;
use std::ffi::*;

use windows::Win32::System::Diagnostics::Debug::{self as windbg, AddVectoredExceptionHandler};
use windbg::EXCEPTION_POINTERS;

use std::mem::size_of;

// Intead of using SEH or IsBadReadPtr to read potentially inaccessible memory, 
// we use VEH. IsBadReadPtr is vulnerable to race conditions and doesn't work under WINE,
// and there is little documentation on manually defining SEH handlers from assembler.

const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

unsafe extern "system" fn veh_handler(ex: *mut EXCEPTION_POINTERS) -> i32 {
    let record = &*(*ex).ExceptionRecord;
    let context = &mut *(*ex).ContextRecord;

    let safe_memcpy_addr = try_aligned_memcpy as usize;
    #[cfg(target_arch = "x86_64")]
    const TARGET_OFFSET: usize = 25; // ret
    #[cfg(target_arch = "x86")]
    const TARGET_OFFSET: usize = 0x17; // xor eax, eax

    let range = safe_memcpy_addr..safe_memcpy_addr + TARGET_OFFSET;
    let addr = record.ExceptionAddress as usize;

    if range.contains(&addr) {
        #[cfg(target_arch = "x86_64")] {
            context.Rip = (safe_memcpy_addr + TARGET_OFFSET) as u64;
        }
        #[cfg(target_arch = "x86")] {
            context.Eip = (safe_memcpy_addr + TARGET_OFFSET) as u32;
        }
        EXCEPTION_CONTINUE_EXECUTION
    }
    else {
        EXCEPTION_CONTINUE_SEARCH
    }
}
#[cfg(target_arch = "x86_64")]
#[naked]
unsafe extern "fastcall" fn try_aligned_memcpy(dest: *mut u8, start: *const u8, end: *const u8) -> u32 {
    asm!(
        "xor rax, rax",
        "2:",
        "mov r9, [rdx]",
        "mov [rcx], r9",
        "add rcx, 8",
        "add rdx, 8",
        "cmp rdx, r8",
        "jne 2b",
        "inc rax",
        "ret",
        options(noreturn)
    )
}
#[cfg(target_arch = "x86")]
#[naked]
unsafe extern "fastcall" fn try_aligned_memcpy(dest: *mut u8, start: *const u8, end: *const u8) -> u32 {
    asm!(
        "push ebx",
        "mov ebx, [esp+8]",
        "2:",
        "mov eax, [edx]",
        "mov [ecx], eax",
        "add ecx, 4",
        "add edx, 4",
        "cmp edx, ebx",
        "jne 2b",
        "mov al, 1",
        "jmp 3f",
        "xor eax, eax",
        "3:",
        "pop ebx",
        "ret 4",
        options(noreturn)
    )
}

pub trait TryDeref<T: Sized + Copy> {
    /// Attempts to dereference the pointer, handling memory exceptions such as access violations.
    /// # Safety
    /// This is safe as per Rust's invariants (namely, nothing is done to prevent race 
    /// conditions).
    unsafe fn try_deref(self) -> Option<T>;
}

/// Type which guarantees at least usize alignment for 
struct UsizeAlignedUninit<T: Copy> { 
    val: MaybeUninit<T>,
    align_usize: [usize; 0]
}
impl<T: Copy> UsizeAlignedUninit<T> {
    fn uninit() -> Self {
        UsizeAlignedUninit { val: MaybeUninit::uninit(), align_usize: [] }
    }

    unsafe fn assume_init(self, offset: usize) -> T {
        *((&self as *const Self as usize + offset) as *const T)
    }

    fn as_mut_ptr(&self) -> *mut u8 {
        self as *const Self as *mut u8
    }
}

static VEH_HANDLER: OnceCell<usize> = OnceCell::new();
impl<T: Sized + Copy> TryDeref<T> for *const T {
    unsafe fn try_deref(self) -> Option<T> {
        VEH_HANDLER.get_or_init(|| {
            NonNull::new(unsafe { AddVectoredExceptionHandler(0, Some(veh_handler)) })
                .expect("Failed to register vectored exception handler")
                .as_ptr() as usize
        });

        let mem_buf : UsizeAlignedUninit<T> = UsizeAlignedUninit::uninit();
        let mem_buf_pos = self as usize & (size_of::<usize>() - 1);

        let start = self as usize & !(size_of::<usize>() - 1);
        let end = start + (size_of::<T>() + size_of::<usize>() - 1) & !(size_of::<usize>() - 1);
        unsafe {
            match try_aligned_memcpy(mem_buf.as_mut_ptr(), start as *const u8, end as *const u8) {
                0 => None,
                _ => Some(mem_buf.assume_init(mem_buf_pos)) 
            }
        }
    }
}

impl<T: Sized + Copy> TryDeref<T> for *mut T {
    unsafe fn try_deref(self) -> Option<T> {
        self.cast_const().try_deref()
    }
} 

#[cfg(target_pointer_width = "32")]
pub const STEAM_CLIENT : &'static str = "steamclient.dll";
#[cfg(target_pointer_width = "64")]
pub const STEAM_CLIENT : &'static str = "steamclient64.dll";

static STEAMCLIENT_PE: OnceCell<PeView> = OnceCell::new(); 
pub fn steam_client_pe<'a>() -> Result<&'a PeView<'a>, ()> {
    STEAMCLIENT_PE.get_or_try_init(|| -> Result<PeView, ()> {
        let handle = STEAM_CLIENT.get_handle().ok_or(())?;
        Ok(unsafe { PeView::module(handle as *const u8) })
    })
}

static STEAMCLIENT_CODE_BOUNDS: OnceCell<Range<u64>> = OnceCell::new();
pub fn client_code_bounds() -> Result<Range<u64>, ()> {
    STEAMCLIENT_CODE_BOUNDS.get_or_try_init(|| -> Result<Range<u64>, ()> {
        let pe = steam_client_pe()?;

        let text = pe
            .section_headers()
            .iter()
            .find(|sec| &sec.Name == b".text\0\0\0")
            .expect("steam client DLL .text section not found");      

        let start = pe.rva_to_va(text.virtual_range().start).unwrap() as u64;
        let end = pe.rva_to_va(text.virtual_range().end).unwrap() as u64;
        Ok(start..end)  
    }).cloned()
}

pub fn read_ascii_static_cstr<'a, T: Pe<'a>>(pe: &T, ptr: u64) -> Option<&'static str> {
    let a = pe.va_to_rva(ptr as Va).ok()?;
    let cstr = pe.derva_c_str(a).ok()?;
    let str = cstr.to_str().ok()?;

    if str.chars().all(|ch| (0x20..=0x7e).contains(&(ch as u8))) {
        Some(unsafe { std::mem::transmute(str) })
    }
    else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_deref() {
        let x = 4u128;
        let ptr = &x as *const u128;
        let bad_ptr = 0x420 as *const u32;

        unsafe {
            assert_eq!(ptr.try_deref(), Some(4u128));
            assert_eq!(bad_ptr.try_deref(), None);
        }
    }
}