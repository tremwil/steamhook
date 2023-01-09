use std::{collections::HashMap, ffi::CString};
use std::mem::size_of;
use std::sync::RwLock;
use pelite::pe::Va;
use windows::core::PCSTR;
use itertools::{Itertools};

use pelite::{
    pe::msvc::{
        RTTICompleteObjectLocator,
        RTTIClassHierarchyDescriptor,
        TypeDescriptor
    },
    pe::{Pe, PeView}
};

use crate::dbghelp::demangle;

#[cfg(target_arch = "x86")]
pub fn get_rtti_name(pe: &PeView, object_locator: &RTTICompleteObjectLocator) -> Option<String> {
    if object_locator.signature != 0 { return None; }

    pe.deref::<RTTIClassHierarchyDescriptor>(object_locator.class_descriptor).ok()?;    
    let type_desc : &TypeDescriptor = pe.deref(object_locator.type_descriptor).ok()?;

    let mangled_name = pe.derva_c_str(pe.va_to_rva((type_desc as *const TypeDescriptor) as u32).ok()? 
        + size_of::<TypeDescriptor>() as u32).ok()?.to_str().ok()?;

    if !mangled_name
        .chars()
        .all(|ch| (0x20..=0x7e).contains(&(ch as u8)))
    {
        return None;
    }

    demangle(mangled_name)
}

#[cfg(target_arch = "x86_64")]
pub fn get_rtti_name(pe: &PeView, object_locator: &RTTICompleteObjectLocator) -> Option<String> {
    if object_locator.signature != 1 { return None; }

    pe.derva::<RTTIClassHierarchyDescriptor>(object_locator.class_descriptor).ok()?;
    let _type_desc : &TypeDescriptor = pe.derva(object_locator.type_descriptor).ok()?;

    let mangled_name = pe.derva_c_str(object_locator.type_descriptor + size_of::<TypeDescriptor>() as u32).ok()?.to_str().ok()?;
    if !mangled_name
        .chars()
        .all(|ch| (0x20..=0x7e).contains(&(ch as u8)))
    {
        return None;
    }

    demangle(mangled_name)
}

use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use once_cell::sync::Lazy;

static RTTI_CACHE: Lazy<RwLock<HashMap<usize, HashMap<String, HashMap<u32, usize>>>>> = Lazy::new(|| {
    RwLock::new(HashMap::new())
});

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct VtableFinder {
    handle: Option<usize>,
    offset: u32,
    class: Option<String>
}

pub trait ModuleId {
    fn get_handle(self) -> Option<usize>;
}

pub const MAIN_MODULE: usize = 0;

impl ModuleId for &str {
    fn get_handle(self) -> Option<usize> {
        let cstr = CString::new(self).expect("invalid string");
        unsafe { GetModuleHandleA(PCSTR(cstr.as_ptr() as *const u8)) }.ok().and_then(|h| Some(h.0 as usize))
    }
}

impl ModuleId for usize {
    fn get_handle(self) -> Option<usize> {
        match self {
            0 => unsafe { GetModuleHandleA(PCSTR(0 as *const u8)) }.ok().and_then(|h| Some(h.0 as usize)),
            s => Some(s)
        }
    }
}

impl VtableFinder {
    pub fn new(module: impl ModuleId) -> Self {
        Self {
            handle: module.get_handle(),
            offset: 0,
            class: None
        }
    }

    pub fn new_main() -> Self {
        Self::new(MAIN_MODULE)   
    }

    pub fn cls<'a>(&'a mut self, cls_name: &str) -> &'a mut Self {
        self.class = Some(cls_name.into());
        self
    }

    pub fn offset<'a>(&'a mut self, offset: u32) -> &'a mut Self {
        self.offset = offset;
        self
    }

    /// Returns the address of the desired vtable, if it exists.
    pub fn find(&self) -> Option<usize> {
        let module_handle = self.handle?;
        let class_name = self.class.as_ref()?;

        let cache = RTTI_CACHE.read().expect("RTTI cache RWLock poisoned!");
        if cache.contains_key(&module_handle) {
            let mod_cache = cache.get(&module_handle).unwrap();
            return mod_cache.get(class_name)?.get(&self.offset).copied();
        }
    
        drop(cache); // Acquire write lock
        let mut cache = RTTI_CACHE.write().expect("RTTI cache RWLock poisoned!");
    
        cache.insert(module_handle, HashMap::new());
        let mod_cache = cache.get_mut(&module_handle).unwrap();
    
        for (vmt, offset, name) in scan_vtables(module_handle) {
            //debug!("{} (OFFSET {}) -> {:x}", name, offset, vmt);
            match mod_cache.get_mut(&name) {
                None => { mod_cache.insert(name, HashMap::from([(offset, vmt)])); }
                Some(m) => { m.insert(offset, vmt); }
            };
        }
    
        mod_cache.get(class_name)?.get(&self.offset).copied()
    }

    /// Return a list of (vtable offset in class, vtable) pairs, or nothing if no such class exists.
    pub fn find_all(&self) -> Vec<(u32, usize)> {
        if self.handle == None || self.class == None {
            return Vec::new();
        }
        let module_handle = self.handle.unwrap();
        let class_name = self.class.as_ref().unwrap();

        let cache = RTTI_CACHE.read().expect("RTTI cache RWLock poisoned!");
        if cache.contains_key(&module_handle) {
            let mod_cache = cache.get(&module_handle).unwrap();
            return mod_cache.get(class_name)
                .unwrap_or(&HashMap::new())
                .into_iter()
                .map(|(&u, &v)| (u, v))
                .collect()
        }

        drop(cache); // Acquire write lock
        let mut cache = RTTI_CACHE.write().expect("RTTI cache RWLock poisoned!");
    
        cache.insert(module_handle, HashMap::new());
        let mod_cache = cache.get_mut(&module_handle).unwrap();
    
        for (vmt, offset, name) in scan_vtables(module_handle) {
            //debug!("{} (OFFSET {}) -> {:x}", offset, name, vmt);
            match mod_cache.get_mut(&name) {
                None => { mod_cache.insert(name, HashMap::from([(offset, vmt)])); }
                Some(m) => { m.insert(offset, vmt); }
            };
        }
    
        return mod_cache.get(class_name)
            .unwrap_or(&HashMap::new())
            .into_iter()
            .map(|(&u, &v)| (u, v))
            .collect()
    }
}

pub fn scan_vtables(module_handle: usize) -> impl Iterator<Item=(usize, u32, String)>  {
    let pe = unsafe { PeView::module(module_handle as *const u8) };

    let text = pe
        .section_headers()
        .iter()
        .find(|sec| &sec.Name == b".text\0\0\0")
        .expect("no .text section found");

    let rdata = pe
        .section_headers()
        .iter()
        .find(|sec| &sec.Name == b".rdata\0\0")
        .expect("no .rdata section found");

    let text_bounds = text.virtual_range();
    let rdata_bounds = rdata.virtual_range();

    rdata
        .virtual_range()
        .step_by(size_of::<Va>())
        .tuple_windows()
        .filter_map(move |(vtable_meta_ptr_rva, vtable_rva)| {
            let vtable_meta_rva = pe
                .derva(vtable_meta_ptr_rva)
                .and_then(|va| pe.va_to_rva(*va))
                .ok()?;

            let vtable = pe.derva::<Va>(vtable_rva).ok()?;
            let vtable_entry_rva = pe.va_to_rva(*vtable).ok()?;

            if !rdata_bounds.contains(&vtable_meta_rva) || !text_bounds.contains(&vtable_entry_rva) {
                return None;
            }

            let col: &RTTICompleteObjectLocator = pe.derva(vtable_meta_rva).ok()?;
            let name = get_rtti_name(&pe, col)?;
            Some((vtable as *const Va as usize, col.offset, name))
        })
}