
use std::error::Error;
use std::ffi::{CString, CStr};
use std::io::{Write, Read};
use std::path::PathBuf;
use itertools::Itertools;
use windows::core::PCSTR;
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleHandleExA, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT};
use windows::Win32::System::Console::{AllocConsole, GetConsoleWindow};
use named_pipe::*;
use std::time::Instant;
use std::fs as fs;
use std::ffi::c_char;

use ::steamhook::*;
use ::steamhook::singleton::RwSingleton;
use ::steamhook::memory_utils::STEAM_CLIENT;
use ::steamhook::vtable_scan::ModuleId;

unsafe fn setup_console() -> Result<(), Box<dyn Error>> {
    if GetConsoleWindow().0 == 0 && !AllocConsole().as_bool() {
        return Err("Failed to allocate console".into());
    }
    std::process::Command::new("CMD").args(["/C", "CLS"]).status()?;
    Ok(())
}

fn get_dll_path() -> Result<String, Box<dyn Error>> {
    let mut buf = [0u8; 256];
    let mut hinstance = HINSTANCE::default();
    if !unsafe { GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
        PCSTR(b"some static string" as *const u8), 
        &mut hinstance as *mut HINSTANCE) 
    }.as_bool() {
        return Err("GetModuleHandleExA failed".into());
    }
    let n_written = unsafe { GetModuleFileNameA(hinstance, &mut buf) } as usize;
    if n_written == 0 {
        Err("GetModuleFileNameA failed".into())
    }
    else {
        Ok(CString::new(&buf[0..n_written])?.to_str()?.to_owned())
    }
}

fn steamhook_test() -> Result<(), Box<dyn Error>> {
    unsafe { setup_console()?; }
    simple_logger::init_with_level(log::Level::Debug)?;

    let ti = Instant::now();
    SteamHook::instance_mut().init()?;
    println!("server code analysis completed in {} ms. Creating interface dump...", ti.elapsed().as_millis());
    let base_addr = STEAM_CLIENT.get_handle().ok_or("No steamclient instance".to_owned())?;

    let mut dump_folder: PathBuf = get_dll_path()?.into();
    dump_folder.pop();
    dump_folder.push("interface_dump");
    if dump_folder.exists() { fs::remove_dir_all(&dump_folder)?; }
    fs::create_dir(&dump_folder)?;

    dump_folder.push("dummy");
    for (name, int) in SteamHook::instance().interfaces() {
        use std::fmt::Write;
        let mut dump = String::new();
        writeln!(&mut dump, "index, name, callid, rva")?;
        for &i in int.fun_names().keys().sorted() {
            if let Some(name) = int.fun_name(i) {
                let rva = int.vtable().and_then(|v| Some(v[i] - base_addr)).unwrap_or(0);
                writeln!(&mut dump, "{}, {}, {:08x}, {:x}", i, name, int.call_id(i).unwrap_or(0), rva)?;
            }
        }
        let path = dump_folder.clone().with_file_name(name).with_extension(".csv");
        fs::write(path, dump)?;
    }

    // Connect to the test launcher
    let mut ipc_client = PipeClient::connect("\\\\.\\pipe\\steamhook_test")?;
    print!("connected to test launcher, setting hooks... ");

    // Install some hooks
    let _hooks = unsafe {
        let sh = SteamHook::instance();

        let persona_name_hook = sh.hook_app_id(
            |app| app == 480, 
            "IClientFriends", 
            "GetPersonaName", 
            |ctx: VtableHookCtx<*const i8>| -> Option<*const i8> {
                println!("GetPersonaName hook called! original result: {}", CStr::from_ptr(ctx.call_next(())).to_str().ok()?);
                Some(b"your_new_name\0" as *const u8 as *const i8)
            }.unwrap_or_next()
        )?;

        let socket_read_hook = sh.get("IClientNetworking")
            .ok_or("No IClientNetworking interface!".to_owned())?
            .install_hook("ReadP2PPacket", |_ctx, pub_dest: *mut u8, cub_dest: u32, msg_size: *mut u32, steam_id: *mut u64, _n_channel: i32| -> bool {
                println!("ReadP2PPacket hook called!");
                // Write a null terminated "test_string" in the buffer
                const PACKET: &[u8; 4] = &0xDEADBEEFu32.to_be_bytes();
                let mut slice = std::slice::from_raw_parts_mut(pub_dest, cub_dest as usize);
                match slice.write_all(PACKET) {
                    Ok(_) => { *msg_size = PACKET.len() as u32; *steam_id = 0xDEADBEEF; true },
                    Err(_) => { *msg_size = 0; false }
                }
            }
        )?;
        // Keep the hook handles in scope, as dropping them would mean uninstalling the hooks!
        (persona_name_hook, socket_read_hook)
    };

    println!("done\ntesting direct endpoint invocation...");
    
    // Example: calling internal steam IPC endpoint outside of hook
    // This does not always work! some functions require a current AppID to be called
    let persona_name : *const c_char = unsafe { SteamHook::instance()
        .get("IClientFriends")
        .ok_or("No IClientFriends interface!".to_owned())?
        .call("GetPersonaName", ())?
    };
    println!("GetPersonaName() -> {}", unsafe { CStr::from_ptr(persona_name) }.to_str()?);

    println!("done, testing IPC hooks...");

    // Send signal to server to notify that steamhook is ready
    ipc_client.write_all(&[0])?;
    // Wait for server to disconnect
    let buf = &mut [0u8; 1];
    ipc_client.read(buf).ok();

    println!("tests completed, unloading self.");
    // Hooks get dropped automatically

    Ok(())
}

#[allow(non_snake_case)]
#[allow(unused_variables)]
#[no_mangle]
pub unsafe extern "system" fn DllMain(hInstDll: HINSTANCE, fdwReason: u32, lpvReserved: *const()) -> i32 {
    if fdwReason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hInstDll);
        let _ = std::thread::spawn(move || {
            match std::panic::catch_unwind(steamhook_test) {
                Err(e) => {
                    println!("erp2p_proxy panicked in steamhook_test: {:#?}", e);
                }
                Ok(Err(e)) => {
                    println!("Encountered an error during steamhook_test: {:#?}", e);
                }
                Ok(_) => {},
            };
            memory_utils::clean_up_veh();
            FreeLibraryAndExitThread(hInstDll, 0);
        });
    }
    1
}