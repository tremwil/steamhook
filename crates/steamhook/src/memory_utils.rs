use std::{ops::Range, arch::asm, sync::{RwLockReadGuard, RwLockWriteGuard, RwLock}, mem::MaybeUninit};
use once_cell::sync::OnceCell;
use pelite::pe::{PeView, Va, Pe};
use crate::vtable_scan::ModuleId;
use std::ffi::*;
use pod::Pod;

use core::intrinsics::r#try;

pub trait SafeDeref<T: Sized + Pod> {
    /// Dereferences a pointer, handling operating system exceptions caused by access violations. 
    fn deref_safe(self) -> Option<T>;
}

impl<T: Sized + Copy + Pod> SafeDeref<T> for *const T {
    fn deref_safe(self) -> Option<T> {
        struct S<Q: Sized + Copy + Pod> {
            val: MaybeUninit<Q>,
            addr: *const Q,
        }

        let mut data = S::<T> { val: MaybeUninit::uninit(), addr: self };

        unsafe { 
            let err = r#try(|ptr| {
                let data = &mut *(ptr as *mut S::<T>);
                data.val.write(*data.addr); // OS may raise an access violation exception here!
            }, &mut data as *mut S::<T> as *mut u8, |_, _| {});
            
            match err {
                0 => Some(data.val.assume_init()),
                _ => None
            }
        }
    }
}

impl<T: Sized + Copy + Pod> SafeDeref<T> for *mut T {
    fn deref_safe(self) -> Option<T> {
        self.cast_const().deref_safe()
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