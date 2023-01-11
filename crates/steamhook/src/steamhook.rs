use std::collections::HashMap;
use std::ops::Index;
use std::ptr::NonNull;
use once_cell::sync::Lazy;
use thiserror::Error;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::core::PCSTR;
use std::sync::{RwLock};

use iced_x86::*;
use log;

use crate::server_analysis::ServerAnalysisError;
use crate::client_analysis::ClientAnalysisError;
use crate::singleton::RwSingleton;
use crate::vtable_hook::*;
use crate::vtable_scan::*;
use super::{memory_utils::*, server_analysis};

#[derive(Error, Debug)]
pub enum SteamHookInitError {
    #[error("{0}")]
    Other(String),
    #[error("{0}")]
    Common(#[from] CommonAnalysisError),
    #[error("{0}")]
    Client(#[from] ClientAnalysisError),
    #[error("{0}")]
    Server(#[from] ServerAnalysisError)
}

#[derive(Error, Debug)]
pub enum CommonAnalysisError {
    #[error("{} not found", STEAM_CLIENT)]
    SteamClientDll,
    #[error("CClientNetworkingAPI virtual method table not found")]
    NetworkingVmt,
    #[error("CSteamEngine static address not found")]
    SteamEnginePtr, 
    #[error("CSteamEngine::GetCurrentAppId method not found")]
    GetAppIdFunction,
    #[error("public export {}.Steam_LogOn not found", STEAM_CLIENT)]
    SteamLogOnExport,
    #[error("GetSteamClientInstance function not found")]
    SteamClientGetter
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum InterfaceBase {
    /// Interface is stored inline or as a pointer inside the CSteamEngine class.
    Engine,
    /// Interface is stored inline or as a pointer inside the CUser class.
    User,
    /// Interface is accessed using a nested pointer beginning at a static memory address.
    Static,
    /// Interface is stored as a pointer inside the CSteamClient class.
    ClientMap
}

pub trait SteamFunIdentifier {
    fn get_vmt_offset(self, interface: &impl ISteamInterface) -> Option<usize>;
}

impl SteamFunIdentifier for &str {
    fn get_vmt_offset(self, interface: &impl ISteamInterface) -> Option<usize> {
        interface.fun_offset(self)
    }
}

impl SteamFunIdentifier for usize {
    fn get_vmt_offset(self, interface: &impl ISteamInterface) -> Option<usize> {
        if self < interface.vtable().len() { Some(self) }
        else { None }
    }
}

pub trait ISteamInterface: Sized {
    fn name(&self) -> &str;
    fn vtable(&self) -> &'static [usize];
    fn instance(&self) -> Option<NonNull<()>>;
    fn base_kind(&self) -> InterfaceBase;

    fn fun_names(&self) -> &HashMap<usize, String>;
    fn fun_name(&self, vmt_offset: usize) -> Option<&str> {
        self.fun_names().get(&vmt_offset).map(|s| &**s)
    }

    fn fun_offsets(&self) -> &HashMap<String, usize>;
    fn fun_offset(&self, name: &str) -> Option<usize> {
        self.fun_offsets().get(name).copied()
    }

    fn fun_address(&self, fun: impl SteamFunIdentifier) -> Option<NonNull<()>> {
        NonNull::new(unsafe { VtableHookMan::instance().get_original(
            self.vtable().as_ptr() as *mut *const (), 
            fun.get_vmt_offset(self)? as isize
        ) } as *mut ())
    }

    fn fun_address_hooked(&self, fun: impl SteamFunIdentifier) -> Option<NonNull<()>> {
        NonNull::new(self.vtable()[fun.get_vmt_offset(self)?] as *mut ())
    }

    unsafe fn install_hook<A: VtableHookArgs>(&self, fun: impl SteamFunIdentifier, hook: impl VtableHookCb<A>) -> Option<HookHandle>
    {
        Some(VtableHookMan::instance_mut()
            .install_hook(self.vtable().as_ptr() as *mut *const (), fun.get_vmt_offset(self)? as isize, hook))
    }

    unsafe fn call<R: 'static>(&self, fun: impl SteamFunIdentifier, args: impl ThiscallArgs) -> Option<R> {
        let o = VtableHookMan::instance().get_original(
            self.vtable().as_ptr() as *mut *const (), 
            fun.get_vmt_offset(self)? as isize
        );
        Some(args.thiscall(self.instance()?.as_ptr(), o))
    }

    unsafe fn call_hooked<R: 'static>(&self, fun: impl SteamFunIdentifier, args: impl ThiscallArgs) -> Option<R> {
        Some(args.thiscall(self.instance()?.as_ptr(), self.vtable()[fun.get_vmt_offset(self)?] as *const ()))
    }
}

pub struct SteamInterface {
    name: String,
    instance: Option<NonNull<()>>,
    vtable: &'static [usize],
    fun_names: HashMap<usize, String>,
    fun_offsets: HashMap<String, usize>,
    base_kind: InterfaceBase
}

impl ISteamInterface for SteamInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn instance(&self) -> Option<NonNull<()>> {
        self.instance
    }

    fn vtable(&self) -> &'static [usize] {
        self.vtable
    }
    
    fn base_kind(&self) -> InterfaceBase {
        self.base_kind
    }

    fn fun_names(&self) -> &HashMap<usize, String> {
        &self.fun_names
    }

    fn fun_offsets(&self) -> &HashMap<String, usize> {
        &self.fun_offsets
    }
}

pub trait ISteamHook: RwSingleton {
    type InterfaceType: ISteamInterface;

    fn interfaces(&self) -> &HashMap<String, Self::InterfaceType>;

    fn get(&self, name: &str) -> Option<&Self::InterfaceType> {
        if !self.is_init() { None }
        else { self.interfaces().get(name) }
    }

    fn init(&mut self) -> Result<&mut Self, SteamHookInitError>;
    fn is_init(&self) -> bool;

    fn get_app_id(&self) -> u32;

    unsafe fn hook_app_id<A: VtableHookArgs + Clone>(&self, 
        appid_filter: impl Fn(u32) -> bool + 'static, 
        int: &str, fun: impl SteamFunIdentifier, 
        hook: impl VtableHookCb<A>) -> Option<HookHandle> 
    {
        if !self.is_init() { None}
        else {
            self.get(int)?.install_hook(fun, hook.with_filter(move |_| {
                appid_filter(SteamHook::instance().get_app_id())
            }))
        }
    }
}

#[cfg(target_pointer_width = "32")]
type GetAppIdFun = unsafe extern "thiscall" fn(usize) -> u32;
#[cfg(target_pointer_width = "64")]
type GetAppIdFun = unsafe extern "fastcall" fn(usize) -> u32;

#[derive(Default)]
pub struct SteamHook {
    interfaces: HashMap<String, SteamInterface>,

    steam_engine_ptr: Option<NonNull<usize>>,
    get_app_id_fun: Option<GetAppIdFun>,
    get_steam_client_fun: Option<extern "C" fn() -> usize>,

    is_client_hook: bool,
    is_common_initialized: bool,
    is_fully_initialized: bool
}

unsafe impl Send for SteamHook {}
unsafe impl Sync for SteamHook {}

impl RwSingleton for SteamHook {
    fn get_or_create() -> &'static RwLock<Self> {
        static INSTANCE : Lazy<RwLock<SteamHook>> = Lazy::new(|| RwLock::new(SteamHook::default()));
        &INSTANCE
    }
}

impl ISteamHook for SteamHook {
    type InterfaceType = SteamInterface;

    fn interfaces(&self) -> &HashMap<String, SteamInterface> {
        &self.interfaces
    }
    
    fn init(&mut self) -> Result<&mut Self, SteamHookInitError> {

        if self.is_fully_initialized {
            Ok(self)
        }
        else {
            self.init_common()?;
            if "steam.exe".get_handle().is_some() {
                // Currently, Steam does not have a 64-bit desktop app. This is just in case they ever release one
                #[cfg(target_arch = "x86_64")]
                return Err(SteamHookInitError::Other("64-bit server (main Steam app) not supported".to_owned()));

                self.is_client_hook = false;
                self.init_server()?;
            }
            else {
                self.is_client_hook = true;
                self.init_client()?;
            }
            self.is_common_initialized = true;
            Ok(self)
        }
    }

    fn is_init(&self) -> bool {
        self.is_fully_initialized
    }

    fn get_app_id(&self) -> u32 {
        if self.is_client_hook {
            todo!()
        }
        else {
            (|| 
                unsafe { Some(self.get_app_id_fun?(*self.steam_engine_ptr?.as_ptr())) }
            )().unwrap_or(0)
        }
    }
}

impl Index<&str> for SteamHook {
    type Output = SteamInterface;

    /// Returns a reference 
    /// ## Panics: 
    /// Panics if no interfaces with the given name exist
    fn index(&self, index: &str) -> &Self::Output {
        &self.interfaces[index]
    }
}

impl SteamHook {
    fn init_common(&mut self) -> Result<&mut Self, CommonAnalysisError> {
        if self.is_common_initialized {
            return Ok(self);
        }

        // First, find the pointer to the CSteamEngine instance and the function to obtain it
        // This should be a pretty reliable method of doing so
        let handle = STEAM_CLIENT.get_handle().ok_or(CommonAnalysisError::SteamClientDll)?;
        let client_net = VtableFinder::new(handle)
            .cls("CClientNetworkingAPI")
            .find()
            .ok_or(CommonAnalysisError::NetworkingVmt)?;

        let send_p2p_packet = unsafe { *(client_net as *const *const u8) };
        let mut code = unsafe { std::slice::from_raw_parts(send_p2p_packet as *const u8, 0x100) };
        let mut decoder = Decoder::with_ip(8 * std::mem::size_of::<usize>() as u32, code, code.as_ptr() as u64, DecoderOptions::NONE);
        let mut instr = Instruction::new();
        let mut info_factory = InstructionInfoFactory::new();

        while decoder.can_decode() && (self.steam_engine_ptr.is_none() || self.get_app_id_fun.is_none()) {
            decoder.decode_out(&mut instr);
            let info = info_factory.info(&instr);

            let mem_accessed = info.used_memory();
            if self.steam_engine_ptr.is_none() && mem_accessed.len() == 1 && mem_accessed[0].access() == OpAccess::Read {
                if let Some(addr) = mem_accessed[0].virtual_address(0, |_, _, _| Some(0)) {
                    log::debug!("SteamEngine pointer: {:x}", addr);
                    self.steam_engine_ptr = NonNull::new(addr as *mut usize);
                }
            }
            if self.get_app_id_fun.is_none() && instr.is_call_near() {
                let addr = instr.near_branch_target();
                log::debug!("GetAppId function: {:x}", addr);
                self.get_app_id_fun = Some(unsafe { std::mem::transmute_copy::<u64, GetAppIdFun>(&addr) });
            }
        }

        if self.steam_engine_ptr.is_none() {
            return Err(CommonAnalysisError::SteamEnginePtr);
        }
        if self.get_app_id_fun.is_none() {
            return Err(CommonAnalysisError::GetAppIdFunction);
        }

        // Now, try to find the Steam Client getter. A similar method is used. 
        // Get pointer to Steam_LogOn and find first function it calls - it creates/fetches the CSteamClient
        let steam_logon = unsafe { 
            GetProcAddress(HINSTANCE(handle as isize), PCSTR(b"Steam_LogOn\0".as_ptr()))
                .ok_or(CommonAnalysisError::SteamLogOnExport)?
        };

        code = unsafe { std::slice::from_raw_parts(steam_logon as *const u8, 0x100) };
        decoder = Decoder::with_ip(8 * std::mem::size_of::<usize>() as u32, code, code.as_ptr() as u64, DecoderOptions::NONE);
        while decoder.can_decode() && self.get_steam_client_fun == None {
            decoder.decode_out(&mut instr);

            if instr.is_call_near() {
                self.get_steam_client_fun = Some(unsafe { std::mem::transmute_copy(&instr.near_branch_target()) });
                log::debug!("GetSteamClient : {:x}", instr.near_branch_target());
                break;
            }
        }

        if self.get_steam_client_fun.is_none() {
            return Err(CommonAnalysisError::SteamClientGetter);
        }

        self.is_common_initialized = true;
        Ok(self)
    } 

    fn init_server(&mut self) -> Result<&mut Self, ServerAnalysisError> {
        // First try to get the CSteamEngine instance
        let steam_engine = unsafe { self.steam_engine_ptr
            .ok_or(ServerAnalysisError::CSteamEngineBadPtr)?
            .as_ptr() 
            .try_deref() 
        }.ok_or(ServerAnalysisError::CSteamEngineBadPtr)?;

        // Analyze interface dispatcher
        let interface_dispatcher_data = server_analysis::analyze_interface_dispatcher(steam_engine)?;
        let cfg = &interface_dispatcher_data.cfg;

        // Grab the CUser instance
        // TODO: Make sure the global user is always the used one. Despite multiple users apparently being 
        // supported, I never encountered a situation where there was more than 1 in the list.
        let cuser_offset = interface_dispatcher_data.user_offset;
        let cuser = unsafe { (steam_engine as *const *const usize)
            .offset(cuser_offset / 4 + 1).try_deref()
            .ok_or(ServerAnalysisError::UserListBadPtr(cuser_offset))?
            .offset(1).try_deref()
            .ok_or(ServerAnalysisError::UserBadPtr(cuser_offset))?
        };
        log::debug!("CUser instance: {:x}", cuser);

        // Analyze each detected call dispatcher, and find the instance
        for &(func, param_ip) in &interface_dispatcher_data.call_dispatchers {
            let dispatcher_info = server_analysis::analyze_call_dispatcher(func)?;
            let (base_kind, ptr) = server_analysis::analyze_interface_ptr(cfg, param_ip)?;

            let interface_instance = match unsafe { match base_kind {
                InterfaceBase::Engine => ptr.eval(steam_engine as isize),
                InterfaceBase::User => ptr.eval(cuser as isize),
                InterfaceBase::Static => ptr.eval(0),
                _ => None
            } } {
                Some(v) => v,
                None => {
                    log::warn!("failure to obtain instance for interface {} ({:?} {})", dispatcher_info.interface, base_kind, ptr);
                    continue;
                }
            };

            let interface_vtable = match unsafe { (interface_instance as *const *const usize).try_deref() } {
                None => {
                    log::warn!("failure to obtain vtable for interface {} ({:?} {})", dispatcher_info.interface, base_kind, ptr);
                    continue;
                }
                Some(v) => v
            };

            let vtable : &'static [usize] = unsafe {
                std::slice::from_raw_parts(interface_vtable, 
                    dispatcher_info.methods.iter().map(|c| c.vmt_offset).max().unwrap() as usize)
            };

            let fun_names : HashMap<usize, String> = dispatcher_info.methods
                .iter()
                .map(|c| (c.vmt_offset as usize, c.name.to_owned()))
                .collect();

            let fun_offsets : HashMap<String, usize> = dispatcher_info.methods
                .iter()
                .map(|c| (c.name.to_owned(), c.vmt_offset as usize))
                .collect();

            self.interfaces.insert(dispatcher_info.interface.to_owned(), SteamInterface { 
                name: dispatcher_info.interface.to_owned(), 
                instance: NonNull::new(interface_instance as *mut ()), 
                vtable, 
                fun_names, 
                fun_offsets, 
                base_kind 
            });
        }

        Ok(self)
    }

    fn init_client(&mut self) -> Result<&mut Self, ClientAnalysisError> {
        Err(ClientAnalysisError::Other("client analysis not yet implemented".to_owned()))
    }
}